# Analysis: Mapping OIDC Claims to Admin Users

## Goal

Allow MediaManager to grant (and revoke) admin (`is_superuser`) status
based on claims returned by the configured OpenID Connect provider —
typically `groups`, `roles`, or a custom claim — instead of relying
solely on a static `admin_emails` allow-list in `config.toml`.

This unblocks deployments where the IdP (Authentik, Keycloak, Azure AD,
Google Workspace, etc.) already owns "who is an administrator," and
removes the operational pain of editing `config.toml` + restarting the
service every time admin membership changes.

## Current State

| Concern | Where it lives | Notes |
|---|---|---|
| OIDC config | `media_manager/auth/config.py:7` (`OpenIdConfig`) | `client_id`, `client_secret`, `configuration_endpoint`, `enabled`, `name` only. |
| OIDC client | `media_manager/auth/users.py:32` | `httpx-oauth` `OpenID` with scopes `["openid", "email", "profile"]`. |
| OIDC router | `media_manager/auth/router.py:33` (`get_openid_router`) | Built via fastapi-users `get_oauth_router`, `associate_by_email=True`. |
| Admin field | `User.is_superuser` (from fastapi-users base via `SQLAlchemyBaseUserTableUUID`) | Single boolean. No roles table. |
| Admin assignment | `media_manager/auth/users.py:67` (`on_after_register`) | Only fires on **first** registration; checks `user.email in config.admin_emails`. |
| Bootstrap admin | `media_manager/auth/users.py:132` (`create_default_admin_user`) | Creates `admin@example.com` / `admin` when DB is empty. |
| Admin gate (backend) | `media_manager/auth/users.py:229` (`current_superuser`) | Dependency on routes (e.g. `/users/all`). |
| Admin gate (frontend) | `web/src/routes/dashboard/settings/+page.svelte:55`, `web/src/lib/components/user-details.svelte:8`, `web/src/routes/dashboard/+layout.svelte:24` | All read `is_superuser` from `/users/me`. |

### Gaps that block claim-based admin mapping

1. **No claim access today.** `httpx-oauth`'s `OpenID.get_id_email`
   only returns `(account_id, email)`. The raw ID token / userinfo
   payload is parsed inside `httpx-oauth` and discarded before
   fastapi-users hands the user off to the `UserManager`. Without a
   change here, no Python code in MediaManager ever sees `groups` /
   `roles` / custom claims.
2. **`on_after_register` only runs once.** Even if we could read
   claims, the existing email-allow-list hook only promotes on
   registration. Subsequent logins where group membership changes
   would never re-evaluate admin status.
3. **No config surface.** `OpenIdConfig` has no fields for
   "which claim to read" or "which values mean admin," and no extra
   scopes are requested (a provider may not include `groups` in the
   token unless asked).
4. **Local accounts must keep working.** Whatever we add must
   coexist with the email/password flow and the
   `admin_emails`/`create_default_admin_user` bootstrap so an
   operator can still get in if the IdP is misconfigured.

## Design

### 1. Config surface (`media_manager/auth/config.py`)

Extend `OpenIdConfig` with a nested `admin_mapping` block:

```python
class OpenIdAdminMapping(BaseSettings):
    enabled: bool = False
    claim: str = "groups"          # ID-token / userinfo claim to inspect
    admin_values: list[str] = []   # values that grant is_superuser
    additional_scopes: list[str] = []  # appended to base_scopes
    revoke_when_missing: bool = True   # demote on login if claim no longer matches
```

Add `admin_mapping: OpenIdAdminMapping = OpenIdAdminMapping()` to
`OpenIdConfig`. Defaults keep current behaviour (feature off, no
extra scopes, no revoke). Document under
`docs/configuration/authentication.md` alongside the existing
`[auth.openid_connect]` block.

Example:

```toml
[auth.openid_connect.admin_mapping]
enabled = true
claim = "groups"
admin_values = ["mediamanager-admins", "platform-admins"]
additional_scopes = ["groups"]   # Authentik / Keycloak need this
revoke_when_missing = true
```

The `additional_scopes` list is appended to
`base_scopes=["openid", "email", "profile"]` at
`media_manager/auth/users.py:36` so providers actually emit the
claim. Some providers (Keycloak) ship groups in `openid`/`profile`;
others (Authentik, Azure AD) require an explicit scope, hence the
config knob.

### 2. Reading claims from the OIDC flow

`httpx-oauth.clients.openid.OpenID` overrides `get_id_email` and
already hits the userinfo endpoint with the access token. To capture
the full userinfo payload (where groups/roles live) we have two
viable options:

**Option A — subclass `OpenID` (recommended).** Create a thin
`ClaimAwareOpenID(OpenID)` that, after the upstream
`get_id_email` succeeds, stashes the userinfo dict on a
`contextvars.ContextVar` keyed by `account_id`. The
`UserManager.on_after_login` / `on_after_register` hooks then read
the var. This keeps the upstream library untouched and survives
library upgrades; the only coupling is to `OpenID.get_id_email`'s
behaviour.

**Option B — replace `get_oauth_router`.** fastapi-users exposes the
underlying callback; we could fork that route to inject claim
handling. Higher maintenance cost — fastapi-users owns state, PKCE,
and account-association logic we don't want to reimplement.

Recommendation: **Option A.** ~30 LoC, no fork, isolated to
`media_manager/auth/users.py`.

### 3. Promotion / demotion logic

Add a single helper `apply_oidc_admin_mapping(user, claims)`
invoked from both `on_after_register` and a new override of
`on_after_login`:

```
target = derive_is_superuser(claims, config.openid_connect.admin_mapping)
if target is None:        # mapping disabled or claim missing & revoke off
    return
if user.is_superuser != target:
    await self.update(user=user, user_update=UserUpdate(is_superuser=target))
```

Rules:

- Mapping disabled (`admin_mapping.enabled = False`) → no-op,
  preserves today's behaviour.
- Claim present, value matches → `is_superuser = True`.
- Claim present, value does **not** match →
  `is_superuser = False` (downgrade).
- Claim missing entirely:
  - `revoke_when_missing = True` → treat as no match, downgrade.
  - `revoke_when_missing = False` → leave existing value alone
    (safer when the IdP can't be trusted to always emit the claim).
- Only applies to users who logged in via OIDC this request.
  Local-password admins are never touched, so the
  `admin_emails` bootstrap and `create_default_admin_user`
  escape hatches stay intact.
- The `admin_emails` list keeps OR semantics: if the email is in
  the list **or** the claim matches, the user is admin. Prevents
  lockout if the OIDC mapping is misconfigured.

`on_after_login` must be added — fastapi-users supports it; today
the `UserManager` only overrides register/update/forgot/reset/verify
(`media_manager/auth/users.py:48–118`).

### 4. Audit + observability

Existing `on_after_update` already logs superuser grants
(`media_manager/auth/users.py:56`). The new flow goes through
`self.update`, so promotions/demotions show up in logs for free.
Add a single info log at the decision point —
`"OIDC claim mapping for user {id}: claim={...} matched={...} -> is_superuser={...}"` —
so misconfigurations surface without DB inspection.

### 5. Failure modes / safety

- **Claim is a string, not a list** (some IdPs send a single role
  as a scalar). The matcher should accept `str | list[str]` and
  normalise.
- **Nested claims** (`realm_access.roles` in Keycloak). Out of
  scope for v1; document as a known limitation and add
  dotted-path support later if asked. v1 expects a top-level
  claim key.
- **Last-admin demotion.** If the IdP downgrades the only
  remaining admin, the user loses access to the user-management
  UI. Mitigation: `admin_emails` is still honoured for OIDC users
  too (point 3 above), so an operator can put their own email
  there as a break-glass. Do **not** add a "must keep ≥1 admin"
  guard — it's surprising and hides a real IdP misconfiguration.
- **No claims at all** (provider returns empty userinfo). With
  `revoke_when_missing = False`, do nothing. With it true, log
  a warning and demote — operators opt into this explicitly.

### 6. Frontend impact

None required. `is_superuser` is already the contract
(`web/src/lib/api/api.d.ts:1676`), and `/users/me` re-reads it on
every dashboard load, so a demotion on the next OIDC login will
show up after the user's next browser refresh / session reissue.
Worth a note in the docs that demotion takes effect on next
login, not instantly — the JWT cookie still says `is_superuser`
until it expires, but the *authorisation* check on the backend
(`current_superuser` dependency) reads from the DB-backed user,
not the JWT, so privileged endpoints reject immediately. Verify
this in implementation — if any route reads `is_superuser` from
the JWT claims, the cookie needs reissuing on change.

## Implementation Checklist

1. `media_manager/auth/config.py` — add `OpenIdAdminMapping` and
   wire it into `OpenIdConfig`.
2. `media_manager/auth/users.py`
   - Append `admin_mapping.additional_scopes` to `base_scopes`.
   - Add `ClaimAwareOpenID` subclass with a `ContextVar` for the
     latest userinfo payload.
   - Add `apply_oidc_admin_mapping()` helper.
   - Add `on_after_login` override that calls it; update
     `on_after_register` to do the same.
3. `docs/configuration/authentication.md` — document the new
   block with an Authentik and a Keycloak example, plus the
   "demotion takes effect on next login" caveat.
4. Tests
   - Unit: `derive_is_superuser` matrix (claim absent / scalar /
     list / no match / revoke on/off).
   - Integration: stub `OpenID.get_id_email` + userinfo and walk
     a register-then-login cycle, asserting `is_superuser`
     transitions in both directions.
5. Verify on a real IdP (Authentik in the example config) before
   merging.

## Out of scope (deliberately)

- A full roles/permissions table. MediaManager only has
  admin-vs-not today; adding RBAC is a separate, much larger
  project.
- Nested-claim dotted paths and regex matching. Wait for a
  concrete request before adding complexity.
- SCIM / push-based provisioning. Pull-on-login is sufficient
  for the user counts MediaManager targets.
- Cookie/JWT revocation on demotion. Backend dependency-level
  checks already cover the security gap; immediate session kill
  is a nice-to-have, not a blocker.

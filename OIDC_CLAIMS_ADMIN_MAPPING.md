# Analysis: Mapping OIDC Claims to User Access

## Goal

Drive MediaManager access decisions from claims returned by the
configured OpenID Connect provider — typically `groups`, `roles`, or
a custom claim. Concretely, three outcomes per OIDC login:

1. Claim value matches an **admin** list → user is admitted as
   `is_superuser=True` (today's `admin_emails` allow-list, but
   sourced from the IdP instead of a static TOML list).
2. Claim value matches a **user** list → user is admitted as a
   regular user (`is_superuser=False`, `is_active=True`).
3. Claim matches neither → user is **denied access**
   (`is_active=False`). They can authenticate at the IdP, but
   MediaManager refuses to let them in.

This unblocks deployments where the IdP (Authentik, Keycloak, Azure AD,
Google Workspace, etc.) already owns "who can use MediaManager and at
what level," and removes the operational pain of editing
`config.toml` + restarting the service every time membership changes.

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

### Gaps that block claim-based access mapping

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
   "which claim to read" or "which values mean admin." It also
   hard-codes the requested scopes to `["openid", "email",
   "profile"]` at `media_manager/auth/users.py:36`, so operators
   can't ask the IdP for `groups`, `roles`, or any provider-specific
   scope — a precondition for the claim ever appearing in the
   userinfo payload.
4. **Local accounts must keep working.** Whatever we add must
   coexist with the email/password flow and the
   `admin_emails`/`create_default_admin_user` bootstrap so an
   operator can still get in if the IdP is misconfigured.
5. **No "deny" path on OIDC login today.** fastapi-users will
   happily create a user for any successful OIDC callback. There
   is no place where MediaManager rejects an authenticated IdP
   user — `is_active` is set to `True` by default and never
   re-evaluated against external state.

## Design

### 1. Config surface (`media_manager/auth/config.py`)

Two independent additions to `OpenIdConfig`. They're orthogonal:
claim-mapping needs extra scopes in practice, but operators may
want to request additional scopes for other reasons (future
features, audit, or because their proxy/IdP requires them), so
scope configuration is **not** nested inside `claim_mapping`.

```python
class OpenIdClaimMapping(BaseSettings):
    enabled: bool = False
    claim: str = "groups"          # ID-token / userinfo claim to inspect
    admin_values: list[str] = []   # claim values that grant is_superuser
    user_values: list[str] = []    # claim values that grant regular-user access
    deny_unmatched: bool = False   # if true, users in neither list are deactivated
    revoke_when_missing: bool = True  # re-evaluate on every login (demote/deny)


class OpenIdConfig(BaseSettings):
    client_id: str = ""
    client_secret: str = ""
    configuration_endpoint: str = ""
    enabled: bool = False
    name: str = "OAuth2"
    additional_scopes: list[str] = []                       # appended to ["openid", "email", "profile"]
    claim_mapping: OpenIdClaimMapping = OpenIdClaimMapping()
```

`OpenIdAdminMapping` from the previous revision is renamed to
`OpenIdClaimMapping` because the block now controls both
promotion **and** admission. Defaults keep current behaviour: feature
off, no extra scopes, no deny, no revoke. Document both fields under
`docs/configuration/authentication.md` alongside the existing
`[auth.openid_connect]` block.

#### Scopes — wiring

At `media_manager/auth/users.py:36` today:

```python
base_scopes=["openid", "email", "profile"],
```

becomes:

```python
base_scopes=["openid", "email", "profile", *config.openid_connect.additional_scopes],
```

Notes:
- **De-duplicate** the resulting list (preserve order) so an
  operator who naively re-adds `"openid"` doesn't send it twice.
- **Don't silently strip `openid`.** If someone tries to remove it,
  fastapi-users / httpx-oauth will fail loudly at the next login;
  that's clearer than the request succeeding with a non-OIDC token.
  No special-case code needed.
- The httpx-oauth `OpenID` client passes `base_scopes` straight to
  the authorise URL, so any string the provider understands works
  (`groups`, `roles`, `offline_access`, `openid:profile:read`, …).
  This is a thin pass-through, not a curated allow-list.

#### Why a top-level field, not under `claim_mapping`

- Claim-mapping is one consumer of extra scopes; future features
  (e.g. surfacing a user's groups in the UI, or audit logging the
  IdP's `acr` value) would re-need the same plumbing.
- Some IdPs require scopes that have nothing to do with claims at
  all — e.g. `offline_access` to get a refresh token. Coupling
  scope config to claim-mapping would force operators to enable a
  feature they don't want just to request the scope.
- It mirrors `httpx-oauth`'s own model: scopes are a property of
  the OAuth client, claim handling is a property of the
  application.

Example with full three-tier mapping:

```toml
[auth.openid_connect]
enabled = true
client_id = "mediamanager"
client_secret = "..."
configuration_endpoint = "https://auth.example.com/.well-known/openid-configuration"
name = "Authentik"
additional_scopes = ["groups"]   # Authentik / Azure AD need this; Keycloak often doesn't

[auth.openid_connect.claim_mapping]
enabled = true
claim = "groups"
admin_values = ["mediamanager-admins", "platform-admins"]
user_values  = ["mediamanager-users"]
deny_unmatched = true            # anyone not in either list is denied
revoke_when_missing = true
```

Example with extra scopes but no claim-mapping (perfectly valid —
all OIDC users admitted as regular users, like today):

```toml
[auth.openid_connect]
enabled = true
# ...
additional_scopes = ["offline_access", "groups"]
# claim_mapping omitted -> disabled by default
```

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

### 3. Access decision (admin / user / denied)

Add a single helper `apply_oidc_claim_mapping(user, claims)`
invoked from both `on_after_register` and a new override of
`on_after_login`:

```
decision = derive_access(claims, config.openid_connect.claim_mapping, user.email)
# decision ∈ {ADMIN, USER, DENY, NOOP}
match decision:
    case NOOP:  return                               # feature off, or claim missing & revoke off
    case ADMIN: target = (is_active=True,  is_superuser=True)
    case USER:  target = (is_active=True,  is_superuser=False)
    case DENY:  target = (is_active=False, is_superuser=False)

if (user.is_active, user.is_superuser) != target:
    await self.update(user=user, user_update=UserUpdate(**target))
```

#### Decision table

| `enabled` | claim present | in `admin_values` | in `user_values` | `email in admin_emails` | `deny_unmatched` | `revoke_when_missing` | decision |
|---|---|---|---|---|---|---|---|
| false | * | * | * | * | * | * | **NOOP** (today's behaviour) |
| true | * | * | * | yes | * | * | **ADMIN** (break-glass wins) |
| true | yes | yes | * | no | * | * | **ADMIN** |
| true | yes | no | yes | no | * | * | **USER** |
| true | yes | no | no | no | true | * | **DENY** |
| true | yes | no | no | no | false | * | **USER** (admit, no promotion) |
| true | no | – | – | no | * | true | **DENY** if `deny_unmatched`, else demote-only |
| true | no | – | – | no | * | false | **NOOP** (claim transient — trust prior state) |

Key consequences:

- `admin_emails` is the **highest-priority** rule. An operator email
  always lands as admin even if the IdP forgot to add them to the
  admin group, preventing lockout from misconfiguration.
- A user previously admin who shows up without the admin claim is
  **demoted to regular user**, not denied — they keep access at the
  lower tier. To remove them entirely, drop them from `user_values`
  too (or set `deny_unmatched = true` and remove them from both
  lists at the IdP).
- A user previously admitted who later matches neither list is
  **deactivated** (not deleted): the row stays for audit, and if
  they're re-added to a group, the next login re-activates them
  without losing user_id / history.
- Only applies to OIDC-sourced users. Local-password accounts are
  never touched, so `create_default_admin_user` and locally
  registered admins remain accessible. (Detected by the presence
  of an `oauth_account` row — fastapi-users tracks this.)

`on_after_login` must be added — fastapi-users supports it; today
the `UserManager` only overrides register/update/forgot/reset/verify
(`media_manager/auth/users.py:48–118`).

#### Denying the in-flight session

There's a wrinkle: `on_after_login` runs **after** the auth backend
has already issued the JWT cookie, so setting `is_active=False`
there doesn't invalidate the current response — it only blocks
*subsequent* requests, where `current_active_user` /
`current_superuser` dependencies refuse the inactive user. In
practice the browser follows the redirect to `/dashboard`,
`/users/me` returns 401, and the frontend kicks back to login. UX
is "logged in for one frame, then bounced," which is correct but
ugly.

Two ways to make denial immediate, in order of preference:

**Option A — override `UserManager.oauth_callback` (recommended).**
fastapi-users calls `oauth_callback` to resolve or create the user
*before* the auth backend issues a token. Override it to run the
claim check there and raise `UserInactive` (or
`fastapi_users.exceptions.UserNotExists`) when the decision is
DENY. The OAuth router catches both and returns a 4xx before any
cookie is set. Users see an error page, not a half-logged-in
dashboard.

**Option B — accept the one-frame session.** Simpler (no
`oauth_callback` override needed), and the security boundary still
holds because every protected endpoint independently verifies
`is_active` against the DB. Worth shipping as v1 if Option A turns
out to require more surgery than expected.

Recommendation: build the logic in `apply_oidc_claim_mapping` so
it's pure, then call it from both `oauth_callback` (to raise) and
`on_after_login` (to keep DB state in sync for users whose group
membership changed since their last visit).

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
  too (top of the decision table), so an operator can put their
  own email there as a break-glass. Do **not** add a "must keep ≥1
  admin" guard — it's surprising and hides a real IdP
  misconfiguration.
- **Lockout via `deny_unmatched`.** A misconfigured `claim` (typo,
  wrong scope, claim returned as nested object) means *every*
  user matches neither list and is denied. The `admin_emails`
  break-glass still works for emails in that list. For everyone
  else, the operator must either fix the config or temporarily
  set `deny_unmatched = false`. Log a warning at startup if
  `claim_mapping.enabled = true` and both `admin_values` and
  `user_values` are empty — that's almost certainly a mistake.
- **No claims at all** (provider returns empty userinfo). With
  `revoke_when_missing = False`, do nothing. With it true, behave
  as "no match" — demote admins to user tier, and (if
  `deny_unmatched`) deactivate. Operators opt into this
  explicitly.
- **Reactivation race.** A user deactivated by claim mapping who
  is later re-added to a group is reactivated on their next
  login. There's no admin-UI button to reactivate them earlier;
  if needed, an operator can flip `is_active` in the DB or via
  the existing `/users` admin endpoints. Acceptable for v1.

### 6. Frontend impact

Minimal. `is_superuser` is already the contract
(`web/src/lib/api/api.d.ts:1676`), and `/users/me` re-reads it on
every dashboard load, so a demotion on the next OIDC login shows
up after the user's next browser refresh / session reissue. The
JWT cookie still says `is_superuser` until it expires, but the
backend `current_superuser` dependency reads from the DB-backed
user, so privileged endpoints reject immediately. Verify during
implementation that no route reads `is_superuser` from JWT
claims; if any does, the cookie needs reissuing on change.

**One small frontend improvement worth adding:** when an OIDC
login is denied (Option A from §3) the OAuth router will return
4xx and redirect to the login page. The frontend already shows a
generic "login failed" state, but a denied-by-policy message is
more useful. The OAuth callback could attach
`?error=access_denied` to the redirect; the login page would map
that to "Your account is not authorised to access MediaManager.
Contact your administrator." No new API contract — just a query
param and a string in the existing error banner.

## Implementation Checklist

1. `media_manager/auth/config.py`
   - Add `additional_scopes: list[str] = []` on `OpenIdConfig`.
   - Add `OpenIdClaimMapping` (with `admin_values`, `user_values`,
     `deny_unmatched`, `revoke_when_missing`) and wire it into
     `OpenIdConfig` as `claim_mapping`.
   - Startup warning: if `claim_mapping.enabled` but both value
     lists are empty.
2. `media_manager/auth/users.py`
   - Append `config.openid_connect.additional_scopes` to
     `base_scopes` (de-duplicated, order preserved).
   - Add `ClaimAwareOpenID` subclass with a `ContextVar` for the
     latest userinfo payload.
   - Add pure `derive_access()` returning `ADMIN | USER | DENY |
     NOOP`, and `apply_oidc_claim_mapping()` that writes the
     resulting `(is_active, is_superuser)` to the user.
   - Override `UserManager.oauth_callback` to call
     `derive_access` and raise `UserInactive` on `DENY`
     (Option A in §3).
   - Add `on_after_login` override that calls
     `apply_oidc_claim_mapping` for existing users whose group
     membership has changed since their last visit; update
     `on_after_register` to do the same.
3. `media_manager/auth/router.py` (or wherever the OAuth router
   redirect lives) — attach `?error=access_denied` on
   `UserInactive` so the login page can show a friendly message.
4. `web/src/routes/login/+page.svelte` (and wherever the
   generic OAuth error is rendered) — map `error=access_denied`
   to "Your account is not authorised to access MediaManager."
5. `docs/configuration/authentication.md` — document the new
   block with an Authentik and a Keycloak example, the
   `deny_unmatched` semantics, the break-glass interaction with
   `admin_emails`, and the "changes take effect on next login"
   caveat.
6. Tests
   - Unit: `derive_access` truth-table — claim absent / scalar /
     list / matches admin / matches user / matches neither, with
     each combination of `deny_unmatched` and
     `revoke_when_missing`; plus the `admin_emails` override.
   - Integration: stub `OpenID.get_id_email` + userinfo and walk
     register → login → group-removed-login cycles, asserting
     `is_active` and `is_superuser` transitions in every
     direction (admit-as-user → promote → demote → deny →
     re-admit).
7. Verify on a real IdP (Authentik in the example config) before
   merging — including the denial path actually returning 4xx and
   the frontend showing the right message.

## Out of scope (deliberately)

- A full roles/permissions table. MediaManager only has
  admin-vs-not today; adding RBAC tiers beyond admin/user/denied
  is a separate, much larger project.
- Nested-claim dotted paths and regex matching. Wait for a
  concrete request before adding complexity.
- SCIM / push-based provisioning. Pull-on-login is sufficient
  for the user counts MediaManager targets — a denied user is
  blocked on their next visit, not instantly.
- Cookie/JWT revocation on demotion or denial of an already
  authenticated session. Backend dependency-level checks
  (`is_active`, `is_superuser`) already cover the security gap
  on the **next** request; immediate session kill across an
  active browser tab is a nice-to-have, not a blocker.
- Admin-UI controls for the claim-mapping config. Operators edit
  `config.toml` (or env vars) and restart, like every other
  setting today.

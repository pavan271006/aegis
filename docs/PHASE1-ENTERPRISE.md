# AEGIS Phase 1 — Enterprise Foundation (Critical)

Multi-tenancy, hardened authentication, API security. Built **additively** as a
new `app/enterprise/` package + Alembic migration `0001_phase1`, so the running
app keeps working while you roll over via **expand → migrate → contract**.

> Not auto-deployed. Phase 1 changes auth and the data model; it ships as a
> major version behind a staged rollout (below), not a hot push to the live demo.

## Files delivered

| File | Purpose |
|---|---|
| `backend/migrations/versions/0001_phase1_enterprise.py` | Schema, backfill, RLS, app role |
| `backend/migrations/env.py`, `backend/alembic.ini` | Alembic wiring |
| `app/enterprise/models.py` | Org, Membership, RefreshSession, SigningKey, MFA, PasswordHistory |
| `app/enterprise/tenancy.py` | RLS-scoped DB sessions (`SET LOCAL app.current_org`) |
| `app/enterprise/passwords.py` | argon2id + policy + history + HIBP |
| `app/enterprise/keys.py` | RS256 key rotation + JWKS |
| `app/enterprise/tokens.py` | Access JWT + refresh rotation/revocation/reuse-detection |
| `app/enterprise/mfa.py` | TOTP + backup codes |
| `app/enterprise/deps.py` | `require(role, mfa)` — secure-by-default dependency |
| `app/enterprise/ratelimit.py` | Redis sliding-window + login throttle |
| `app/enterprise/router_auth.py` | `/api/v2/auth/*` endpoints + JWKS |
| `app/enterprise/__init__.py` | `wire(app)`: CORS allowlist + security headers |
| `frontend/src/lib/auth.js` | In-memory access token, transparent refresh, MFA, org switch |
| `backend/requirements-enterprise.txt` | New deps |

---

## 1. Multi-Tenant Architecture

**Why** — Without tenant isolation, a single SaaS instance leaks every customer's
incidents/IPs across the boundary. This is the #1 enterprise + security blocker.

**Database schema changes** — `organizations` (uuid tenant), `memberships`
(user↔org↔role = tenant-scoped RBAC), and a non-null `org_id uuid` FK on all 11
tenant data tables (`sites, events, incidents, actions, audit_log,
monitoring_checks, allowlist, honeypots, quarantined_files, vulnerabilities,
posture_trends`). See migration `0001_phase1`.

**Backend architecture changes** — The app connects as a **least-privilege role
`aegis_app`** that is subject to `FORCE ROW LEVEL SECURITY`. Every request opens a
transaction and runs `SET LOCAL app.current_org = <org>` (`tenancy.tenant_session`).
RLS policies then scope *every* query to that org at the database — so a forgotten
`WHERE org_id=…` cannot leak data. `current_setting('app.current_org', true)`
returns NULL when unset ⇒ zero rows (**fail-closed**).

**Frontend changes** — Active org persisted (`aegis_org`); org switcher in the top
bar (the existing site selector pattern) calls `POST /api/v2/auth/switch` to mint a
new access token for another membership.

**API endpoints** — `GET /api/v2/auth/orgs`, `POST /api/v2/auth/switch?org=`.

**Security considerations** — RBAC is now per-org (`owner/admin/analyst/read_only`);
a user can hold different roles in different orgs. RLS is defense-in-depth *under*
app-layer checks, not instead of them. `memberships`/`users` are intentionally not
RLS-scoped (read during login before an org context exists) and are authorized in
code — a token's `org` claim is only minted for a verified active membership.

**Migration strategy** — Expand/contract: add nullable `org_id`, backfill a
"Default Organization" + memberships for existing users, set `NOT NULL` + FK +
index, then enable RLS. Reversible `downgrade()`.

**Rollout** — (1) run migration on a replica, verify backfill; (2) deploy app code
reading/writing `org_id` with RLS *enabled but app still single-org*; (3) flip
login to issue org-scoped tokens; (4) enable cross-tenant signups.

---

## 2. Enterprise Authentication

**Why** — The legacy auth was hand-rolled HMAC JWT, the signing secret == the API
key, tokens were unrevocable for 24h, no MFA, no refresh, weak hashing. Every one
of those is an audit failure.

**Database schema changes** — `signing_keys` (RS256 keypairs, private key
envelope-encrypted, rotation state), `refresh_sessions` (hashed, single-use,
rotation chain, revocation), `mfa_credentials` + `mfa_backup_codes`,
`password_history`; `users` gains `mfa_enabled, password_changed_at,
failed_logins, locked_until, is_superuser`.

**Backend architecture changes**
- **Access tokens:** short-lived (15 min) **RS256 JWT**, `kid`-headed, validated
  against a **JWKS** endpoint — consumers (SIEM, gateways) verify offline.
- **Key rotation:** `keys.rotate()` promotes a new active key, demotes the old to
  `retiring` (still in JWKS until issued tokens expire). 30-day default cadence.
- **Refresh tokens:** opaque 48-byte, stored only as SHA-256; **rotated on every
  use**; **reuse of a rotated token revokes the whole chain** (token-theft
  response). Logout + admin "revoke all sessions" supported.
- **Passwords:** **argon2id**, policy (length/classes/history/HIBP k-anonymity),
  lockout after N failures.
- **MFA:** TOTP (`pyotp`), encrypted secret, 10 single-use backup codes; required
  for `owner/admin` by policy; step-up challenge flow on login.

**Frontend changes** — `frontend/src/lib/auth.js`: access token kept **in memory**
(not localStorage) to shrink XSS blast radius; transparent refresh-and-retry on
401; MFA challenge UI; org switch.

**API endpoints**

| Method | Path | Notes |
|---|---|---|
| POST | `/api/v2/auth/login` | → tokens, or `{mfa_required, challenge}` |
| POST | `/api/v2/auth/mfa` | challenge + TOTP → tokens |
| POST | `/api/v2/auth/refresh` | rotates refresh, new access |
| POST | `/api/v2/auth/logout` | revoke refresh |
| GET | `/api/v2/auth/orgs` · POST `/switch` | multi-org |
| POST | `/api/v2/auth/mfa/enroll` · `/mfa/confirm` | self-service MFA |
| GET | `/api/v2/auth/.well-known/jwks.json` | public keys |

**Security considerations** — No symmetric secret shared with the API key; private
keys never leave the process unencrypted (KEK via KMS in prod); constant-time
verify; lockout + throttle on the login endpoint itself; tokens carry `org`+`role`
so authorization is explicit.

**Migration strategy** — Run alongside legacy `/api/auth/*`. On first login,
transparently re-hash legacy PBKDF2 → argon2 (`needs_rehash`). Seed one signing
key on boot. No password resets required.

**Rollout** — (1) deploy `/api/v2/auth/*` + JWKS; (2) point the new frontend at v2;
(3) enforce MFA for admins; (4) delete legacy `/api/auth/*` + the HMAC code.

---

## 3. API Security Hardening

**Why** — Legacy had `CORS *`, unauthenticated read endpoints, no rate limiting,
and the API key doubling as the JWT secret.

**Backend architecture changes**
- **Secure-by-default:** `deps.require(min_role, mfa_required)` is the *only* way to
  read a request principal; a route without it gets 401. Replaces the optional,
  inconsistent legacy guards across all 40+ endpoints.
- **Rate limiting:** Redis atomic sliding window (`ratelimit.limit(...)`), plus a
  strict per-account + per-IP `auth_throttle` on login.
- **CORS:** explicit origin allowlist + credentials (`enterprise.wire`).
- **Security headers:** HSTS, `X-Content-Type-Options`, `X-Frame-Options: DENY`,
  CSP, `Referrer-Policy` via middleware.
- **Secret management:** `settings.validate_prod()` refuses to boot without a real
  KEK + DB creds; envelope encryption (`crypto.py`) abstracts KMS.

**Frontend changes** — All API calls go through `auth.fetch()` (adds bearer,
handles refresh). No tokens in localStorage except the rotated refresh token.

**API endpoints** — applies to all; example wiring:

```python
# legacy:  @dashboard_router.get("")  def dashboard(db=Depends(get_db)): ...
# v2:
from app.enterprise.deps import require, Principal
@dashboard_router.get("")
def dashboard(user: Principal = Depends(require("read_only"))):
    # user.db is already RLS-scoped to user.org_id
    return scoring.compute(user.db)              # no manual org filter needed
```

**Security considerations** — Authorization is centralized and testable; RLS is the
backstop; rate limits protect against credential stuffing of the console itself
(ironic gap in the legacy build).

**Migration strategy** — Convert routers module-by-module to `require()`; keep the
machine `X-API-Key` path only for the agent ingest endpoint, scoped to its org.

**Rollout** — (1) add middleware + limits (non-breaking); (2) convert read routers;
(3) convert write routers; (4) remove legacy guards.

---

## Cutover checklist

1. Provision **Postgres** + **Redis**; create owner + run `alembic upgrade head`.
2. Set `AEGIS_KEK` (KMS), `AEGIS_DATABASE_URL` (aegis_app creds), `AEGIS_CORS_ALLOWED_ORIGINS`.
3. `enterprise.wire(app)` in `main.py`; seed a signing key; create the first org/owner.
4. Point frontend at `/api/v2/auth/*`; enforce MFA for admins.
5. Convert routers to `require()`; verify RLS with a 2-tenant test (tenant A cannot read tenant B).
6. Remove legacy `/api/auth/*` and the shared-secret JWT.

**Phase 1 acceptance tests:** cross-tenant read returns 0 rows; expired/rotated
refresh is rejected and revokes the chain; admin login without MFA is blocked;
login brute force is throttled; JWKS validates an issued token; key rotation keeps
old tokens valid until expiry.

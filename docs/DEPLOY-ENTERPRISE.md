# Deploying the AEGIS Enterprise stack (Phases 1–4)

This is a **new Postgres-backed deployment**, not an in-place upgrade of the live
SQLite demo. The enterprise stack is opt-in (`AEGIS_ENTERPRISE=1`) and additive,
so merging the code never disturbs the running demo.

## ✅ Validation status (run in a real Postgres before writing this)
- All 4 migrations apply cleanly: `0001 → 0002 → 0003 → 0004` (48 tables, 36 RLS).
- **Tenant isolation proven**: org A sees only A's rows, org B only B's, and an
  unscoped query returns **0 rows (fail-closed RLS)**.
- All 24 enterprise modules import under their real dependencies.
- Two first-deploy bugs found + fixed during shake-out: `pgcrypto` hard dependency,
  missing `email-validator`.

What is **not** yet validated (do before production): full app boot under load,
auth round-trip end-to-end, and live Okta/Entra/Splunk/Sentinel integration.

## 1. Provision infrastructure (all have free tiers, no SQLite)
- **PostgreSQL 14+** — Neon / Supabase / Render / RDS (persistent; the migration
  needs a superuser/owner role to create the `aegis_app` role + RLS).
- **Redis** — Upstash / Render (rate limiting, SIEM queue, SSO state).

## 2. Environment
```
AEGIS_ENTERPRISE=1
DATABASE_URL=postgresql+psycopg2://OWNER:***@host:5432/aegis      # migration/owner role
AEGIS_DATABASE_URL=postgresql+psycopg2://aegis_app:***@host:5432/aegis  # app RLS role
AEGIS_KEK=<openssl rand -base64 48>            # KMS-managed in prod
AEGIS_REDIS_URL=redis://:***@host:6379/0
AEGIS_CORS_ALLOWED_ORIGINS=https://app.yourdomain.com
AEGIS_ISSUER=https://api.yourdomain.com
# optional: AEGIS_LLM_PROVIDER / AEGIS_LLM_API_KEY (Copilot)
```
> Give `aegis_app` a password after the migration (`ALTER ROLE aegis_app WITH PASSWORD '...';`)
> — it's created `LOGIN` with none. The app connects as `aegis_app` (RLS-enforced);
> the migration/bootstrap runs as the owner.

## 3. Dependencies
Merge into `backend/requirements.txt`:
```
cat requirements-enterprise.txt requirements-phase2.txt requirements-phase4.txt >> requirements.txt
```
Image must also include `postgresql-client` (for backup validation) and, for SAML,
native `libxml2`/`xmlsec1`.

## 4. One-command bootstrap (validated)
From `backend/`:
```
DATABASE_URL=...owner... AEGIS_KEK=... \
BOOTSTRAP_ORG="Acme" BOOTSTRAP_EMAIL=owner@acme.com BOOTSTRAP_PASSWORD='***' \
python -m scripts.enterprise_bootstrap
```
This runs: ORM `create_all` → `alembic upgrade head` → first org + owner + signing key.

## 5. Start
Run the app with `AEGIS_ENTERPRISE=1`. The v2 surface comes up alongside the legacy
API: `/api/v2/auth/*`, `/api/v2/sso/*`, `/scim/v2/*`, `/api/v2/agents|cases|attack|tip|detections|copilot|compliance`, `/metrics`, plus CORS allowlist + security headers.

## 6. Cut over (expand → migrate → contract)
1. Run with both legacy + v2 (expand). Existing data is in the "Default Organization".
2. Point the frontend at `/api/v2/auth/*`; enforce MFA for admins; convert legacy
   routers to `Depends(require(...))`.
3. Wire the agent to mTLS; retire the shared API key.
4. Remove the legacy `/api/auth/*` + the shared-secret JWT (contract).

## Why this isn't a hot push to the live demo
The live demo runs on Render **SQLite** — Postgres RLS (the heart of tenant
isolation) doesn't exist there, the heavy deps aren't installed, and replacing auth
+ the data model on a running site mid-flight would break logins. Stand the
enterprise stack up as its own environment, validate (§ "not yet validated"), then
migrate users.

## Remaining before "Fortune-500 ready"
Integration tests vs. real IdP/SIEM tenants, a load/chaos harness, Entra-SCIM
discovery endpoints, agent-side guaranteed delivery + OTA rollback, and the HA
Postgres topology — see PHASE4 doc and the operational-readiness answers.

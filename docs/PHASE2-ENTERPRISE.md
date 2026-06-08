# AEGIS Phase 2 — SSO · SCIM · SIEM · Observability

Additive on top of Phase 1. Migration `0002_phase2`. Wired via `enterprise.wire(app)`.
Requires Postgres + Redis. Not auto-deployed (cutover, not hot-push).

| File | Purpose |
|---|---|
| `migrations/versions/0002_phase2_sso_scim_siem.py` | idp_connections, scim_tokens, siem_connections (+RLS) |
| `app/enterprise/models_p2.py` | ORM for the above |
| `app/enterprise/sso.py` | OIDC + SAML, JIT provisioning, token handoff |
| `app/enterprise/scim.py` | SCIM 2.0 Users/Groups |
| `app/enterprise/siem.py` | Forwarder: CEF/JSON → Splunk/Sentinel/Elastic/syslog/webhook |
| `app/enterprise/telemetry.py` | OTel + Prometheus + JSON logs |
| `frontend/src/lib/auth.js` | SSO callback handoff already supported |

---

## 1. SSO — OIDC + SAML

**Why** — Enterprises authenticate via their IdP; local passwords are a non-starter. Identity teams reject any product without it.

**Schema** — `idp_connections` (per-org, `kind=oidc|saml`, issuer/client or SAML metadata, `attr_mapping` claim→role, `email_domains`, `default_role`). Tenant-scoped + RLS.

**Backend** — OIDC: discovery → authorize redirect (state+nonce in Redis) → code exchange → **id_token validated against the IdP JWKS** (PyJWT `PyJWKClient`) → JIT provision. SAML: SP metadata + ACS via `python3-saml`, NameID+attributes → JIT. JIT find-or-creates the global `User`, upserts an active `Membership` with an IdP-mapped role, then mints Phase-1 access+refresh tokens and hands them to the SPA via a **one-time Redis code** (no tokens in the URL).

**Frontend** — "Sign in with SSO" → `/api/v2/sso/{conn}/oidc/login`; SPA `/sso/callback?code=` calls `POST /api/v2/sso/exchange` to retrieve tokens (already supported by `auth.js`).

**API** — `GET /{conn}/oidc/login` · `GET /oidc/callback` · `GET /{conn}/saml/metadata` · `POST /{conn}/saml/acs` · `POST /exchange`.

**Security** — state (CSRF) + nonce (replay) verified; client secret + SAML keys envelope-encrypted; email-domain allowlist; role re-synced from IdP each login; HTTPS-only redirects.

**Migration / rollout** — `alembic upgrade head`; admin adds a connection; pilot one org; enforce SSO-only (disable password login) per org via `organizations.settings`.

## 2. SCIM 2.0 Provisioning

**Why** — Lifecycle automation (auto-deprovision on offboarding) is a security control auditors check.

**Schema** — `scim_tokens` (hashed bearer, per org).

**Backend** — `/scim/v2/Users` (list/filter `userName eq`, create, PATCH `active`, DELETE→soft-deprovision). Bearer token resolves the org; all work in that org's RLS session. `active=false` deactivates the **membership** (per-tenant), preserving the global identity + audit trail.

**API** — `GET/POST /scim/v2/Users`, `PATCH/DELETE /scim/v2/Users/{id}`.

**Security** — opaque hashed tokens, revocable; org-scoped; standard SCIM schemas so Okta/Entra/Workspace connectors work unmodified.

**Rollout** — issue a SCIM token per org → paste into the IdP's provisioning app → verify create/deactivate round-trip.

## 3. SIEM Integrations

**Why** — SOCs operate in their SIEM; a tool that can't forward events is a silo (a Phase-1 critical gap).

**Schema** — `siem_connections` (per-org, `kind`, endpoint, encrypted secret, `format=json|cef`, options, last_ok/last_error).

**Backend** — `emit(org, type, payload)` durably enqueues to Redis; a worker (`run_worker`) fans out to every enabled connection. Sinks: **Splunk HEC**, **Microsoft Sentinel** (signed Log Analytics), **Elastic** bulk, **syslog** TCP/UDP, generic **signed webhook** (Chronicle). Formatters: JSON + ArcSight **CEF**. Failures go to a DLQ and surface in the admin UI.

**API** — admin CRUD for connections + "send test event"; `emit()` is called from incident/auth/audit code paths.

**Security** — secrets envelope-encrypted; outbound TLS; HMAC-signed webhooks; forwarding never blocks the request path (fire-and-forget enqueue).

**Rollout** — add connection → test event → enable → monitor last_ok/DLQ.

## 4. Observability — OTel + Prometheus

**Why** — When AEGIS silently fails you're blind *and* falsely assured. No self-telemetry = unoperable.

**Backend** — `telemetry.setup(app)`: OTel auto-instrumentation (FastAPI/SQLAlchemy/httpx, OTLP export), Prometheus `/metrics`, per-request middleware (latency/count/in-flight) + **domain metrics** (`ingest_lag`, `detections_total`, `blocks_total`, `siem_forwarded_total`), and one structured JSON log per request with trace correlation.

**Frontend** — none (ops-facing: Grafana dashboards from the Prometheus scrape + OTLP traces).

**Security** — `/metrics` bound to the internal network / scrape auth; no PII in labels (org id only).

**Rollout** — scrape `/metrics`; ship OTLP to Tempo/Jaeger; import Grafana dashboards; alert on ingest-lag SLO + error rate.

---

## Roadmap — items 5–10 (Phase 3/4), staged

Designed and ready to build next, one batch at a time (same output format + real code). Risk = enterprise impact.

| # | Feature | Core design | Cx | Risk |
|---|---|---|---|---|
| 5 | **Agent mTLS + Fleet** | Internal CA; secure enrollment (one-time token → CSR signed → per-agent cert); `agents`/`agent_heartbeats` tables; mTLS-verified ingest (cert CN = agent identity, org-bound); fleet health + signed OTA manifests | L | High |
| 6 | **Incident Case Mgmt** | `cases`, `case_notes`, `case_events`; ownership/assignment, SLA timers (first-response/resolution by severity), escalation rules, status workflow, `playbooks` (YAML steps) + runner; links incidents→case | L | High |
| 7 | **ATT&CK Mapping** | `attack_techniques` (T-IDs/tactics, seeded from MITRE STIX); detection→technique map; auto-tag incidents; coverage heatmap (tactics × techniques) on dashboard | M | Medium |
| 8 | **STIX/TAXII TI** | `taxii2-client` poll of feeds; `stix2` parse → `indicators` store (type/value/confidence/valid_until, aging); match ingest IPs/domains/hashes; sightings + enrichment on incidents | L | High |
| 9 | **Security Copilot** | Provider-agnostic LLM gateway; **RAG over the tenant's own incidents/cases** (pgvector); strict tool allowlist + output guardrails + per-tenant data isolation; "explain/triage/recommend" actions, never auto-acts | L | High |
| 10 | **Bug Hunter v2** | Real DAST: authenticated crawl, OpenAPI import, orchestrate ZAP/nuclei in sandboxed workers; CVE/SCA via dependency graph; EPSS/CVSS prioritization; ticketing sync; (replaces the naive v1 crawler) | XL | Medium |

**Acceptance criteria carried into each:** tenant-scoped (RLS), secure-by-default endpoints, metrics emitted, SIEM events on state changes, ATT&CK-tagged where relevant.

Say **"build 5–6"** (Phase 3) or **"build 7–10"** (Phase 4) and I'll implement them in this same format.

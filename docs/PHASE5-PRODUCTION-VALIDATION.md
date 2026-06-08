# AEGIS Phase 5 — Production Validation

Goal: move from **feature-complete** to **production-proven**. No new features.
The headline: the integration suite was not just written — it was **executed against
real PostgreSQL**, and doing so caught and fixed real bugs.

## Executed result
```
12 passed  (tenant isolation, RLS fail-closed, cross-tenant write rejection,
            password policy, refresh rotation + reuse-revocation, TOTP MFA + backup
            codes, audit-chain integrity + tamper detection, GDPR export/erase,
            suppression + confidence feedback, ATT&CK enrichment, TIP tenant
            scoping, agent PKI/cert signing)
```
**Bugs found by RUNNING it (now fixed):**
1. Migration hard-depended on `pgcrypto` (unavailable on minimal PG) — made tolerant.
2. `email-validator` was a missing runtime dependency — added.
3. `audit_log` is RLS-scoped but `append_audit` didn't set `org_id` — every audit
   write under the app role would have failed. Fixed.
4. Audit `details` were stored as a JSON *string scalar*, so `verify_chain` could not
   reconstruct the hash — tamper-evidence was broken even on clean data. Fixed.
5. `FeedbackIn.incident_id` was required but rule-level feedback has none. Fixed.
Plus a confirmed design lesson: **tenant scope is connection-bound** — the production
`tenant_session` (SET LOCAL per transaction) is correct; a reused session with plain
`SET` silently loses scope (the harness reproduced this).

---

## Section 1 — Integration testing
**Architecture** — `backend/tests/integration/`. A session-scoped fixture spins up a
**real Postgres via `pgserver`** (bundled binary → runs in CI with no system DB),
applies the legacy `create_all` (legacy tables only) then all Alembic migrations, and
exposes two session kinds:
- `owner_session` — superuser, bypasses RLS (setup).
- `scoped(org_id)` — connects as `aegis_app` with a **pinned connection** + the org
  GUC, so RLS is actually enforced (production parity).

**Fixtures** — `two_orgs` (two tenants + owner users/memberships); `scoped`/`owner_session`.

**Mock strategy** (for the external-integration items, to add alongside the DB suite):

| Area | Strategy |
|---|---|
| SSO OIDC | `respx`-mock the IdP discovery/token/JWKS; assert state+nonce, id_token validation, JIT membership |
| SAML | static signed assertion fixture → `python3-saml` ACS path |
| SCIM | FastAPI `TestClient` + a seeded SCIM token; assert create/PATCH-active/delete + RLS |
| SIEM | mock `httpx` transport; assert CEF/JSON payload + Sentinel HMAC signature bytes |
| Agent mTLS | real CA + CSR (already unit-tested); inject proxy headers into `agent_identity` |
| OTA | local fixture release + a signing key; assert signature verify + rollback path |
| TAXII | canned STIX 2.x bundle → assert indicator parse + match + sighting |
| Copilot | stub the LLM gateway; assert RAG retrieval is RLS-scoped and never autonomous |

**Example** — see `tests/integration/test_core.py` (the 12 passing tests).

## Section 2 — Load testing
**Framework** — `load/locustfile.py` (Locust) and `load/k6_ingest.js` (k6). Both ramp
the four daily-volume tiers and **fail the run on SLO regression** (p95 > 800 ms or
error rate > 1%).

| Tier | Sustained | Peak to test | Expectation (single node, post-fix) |
|---|---|---|---|
| 1k/day | negligible | — | trivial |
| 10k/day | ~0.12 rps | — | trivial |
| 100k/day | ~1.2 rps | 10× | comfortable |
| 1M/day | ~11.6 rps | ~116 rps burst | OK only after: bulk event INSERT, baseline→Redis, SQL/OLAP aggregation |

**Measure** (already emitted by `telemetry.py`): API p50/p95/p99
(`aegis_http_request_seconds`), DB latency (sqlalchemy OTel spans), **detection /
ingest lag** (`aegis_ingest_lag_seconds`), queue backlog (Redis `LLEN siem:queue`),
Redis op latency, CPU/mem (node exporter). **Grafana**: import an API-latency panel,
an ingest-lag SLO panel (alert > 60 s), a detections/min panel, and a SIEM-DLQ panel.

## Section 3 — Chaos testing
Inject with `toxiproxy` (DB/Redis/SIEM/TAXII/SSO) + `systemctl stop` (agent).

| Fault | Expected behavior | Recovery | Validation |
|---|---|---|---|
| **Postgres outage** | Writes fail; app returns 5xx (no HA today). `pool_pre_ping` reconnects on return. | Promote replica (HA topology) → connections re-establish | Kill primary; assert recovery < RTO; no data loss with PITR |
| **Redis outage** | Rate-limit **fails open**; SIEM `emit` swallows + keeps request path alive; SSO state lost (re-login). | Redis returns → queues resume | Stop Redis; assert ingest still 200, no 5xx storm |
| **Network partition (agent↔server)** | Agent **spools to disk** (no loss); server unaffected | Link heals → spool drains with backoff; server **dedups** re-sent batches | Partition 10 min under load; assert 0 lost + 0 duplicate events |
| **Agent disconnect** | Fleet marks **stale > 15 min**; alert fires | Agent reconnects via mTLS; heartbeat clears stale | Assert stale flag + alert + auto-clear |
| **SIEM outage** | Events buffer in Redis queue; failures → **DLQ** + `last_error` | Endpoint returns → worker drains; replay DLQ | Stop sink; assert queue grows then drains, nothing dropped |
| **TAXII feed outage** | Poll returns 502 to admin; indicators keep aging; matching unaffected | Feed returns → next poll resumes | Assert detection unaffected during outage |
| **SSO provider outage** | New SSO logins fail with a clear error; existing sessions valid until token exp | IdP returns → logins resume; break-glass local owner remains | Assert existing access tokens still work |

## Section 4 — Agent reliability (implemented)
- **Schema** (`0005_phase5`): `ingest_batches(org_id,batch_id PK,…)` for server-side
  **dedup** (exactly-once over at-least-once); agent canary columns.
- **Agent** (`agent/spool.py`): durable **WAL SQLite spool**, batched drain over mTLS,
  **retry + exponential backoff + full jitter**, **dead-letter table** (never drop),
  stable per-content `batch_id`.
- **Server**: the ingest endpoint records `batch_id` in `ingest_batches` and returns
  `409` (already accepted) on replay, so retries don't duplicate events/incidents.
  *(Wire this check into the legacy ingest handler at cutover.)*

## Section 5 — OTA safety (implemented)
`agent/updater.py` — state machine
`IDLE→CHECK→DOWNLOAD→VERIFY→STAGE→ACTIVATE→HEALTHCHECK→(COMMIT|ROLLBACK)`.
- **Signed artifacts**: sha256 + RS256 signature verified against AEGIS JWKS **before**
  activation — a compromised mirror can't push a trojan.
- **Canary**: `agents.canary` + `agent_releases.canary_percent` serve the new version
  to a slice first.
- **Health-gated activation**: previous binary retained; a **watchdog auto-reverts** if
  the new agent doesn't post a healthy heartbeat within the window (atomic symlink swap).
- **Failure scenarios**: bad signature/hash → ABORT (stay current); download fail →
  ABORT; unhealthy after activate → ROLLBACK; partial write → atomic swap prevents a
  half-installed binary.

## Section 6 — Production readiness checklist
P = priority (P0 blocks prod), Risk, Effort (S/M/L/XL).

| Area | Item | P | Risk | Effort | Status |
|---|---|---|---|---|---|
| Security | Tenant isolation / RLS proven | P0 | Crit | — | ✅ tested |
| Security | Auth: rotation/revocation/MFA proven | P0 | Crit | — | ✅ tested |
| Security | Convert legacy routers to `require()` + RLS | P0 | High | M | ☐ |
| Security | SAST/DAST/SCA in CI | P1 | High | S | ☐ |
| Reliability | Postgres HA (primary+replica+PITR, failover) | P0 | Crit | L | ☐ |
| Reliability | Redis HA / Sentinel | P1 | High | M | ☐ |
| Reliability | Agent guaranteed delivery + dedup | P0 | High | M | ✅ built, wire ingest |
| Reliability | OTA canary + auto-rollback | P1 | High | M | ✅ built |
| Performance | Bulk event INSERT + baseline→Redis + SQL aggregation | P0 | High | M | ☐ (1M/day gate) |
| Performance | Load test passes SLO at target tier | P0 | High | M | ☐ run it |
| Monitoring | Metrics/traces/logs + dashboards | P1 | Med | S | ✅ code, wire Grafana |
| Monitoring | Ingest-lag SLO alert + dead-man's-switch | P1 | High | S | ☐ |
| Backups | Encrypted, offsite, **restore-tested** | P0 | Crit | M | ✅ validator built |
| Recovery | Documented RTO/RPO + DR runbook + game day | P0 | Crit | M | ☐ |
| SSO | Live Okta + Entra + Google round-trip tests | P0 | High | M | ☐ |
| SCIM | Entra discovery endpoints + conformance | P0 | High | M | ☐ |
| SIEM | Live Splunk/Sentinel/Elastic delivery tests | P1 | Med | M | ☐ |
| Agents | mTLS at the proxy + revocation/CRL | P0 | High | M | ☐ |
| Compliance | Audit chain + GDPR proven | P1 | High | — | ✅ tested |
| Compliance | Retention job scheduled; SOC2/ISO program | P1 | High | XL | ☐ program |

### Production validation roadmap (priority order)
1. **P0 data-plane**: Postgres HA + PITR; bulk-insert + baseline→Redis; **run the load
   test to the target tier and pass SLOs**; wire agent dedup into ingest.
2. **P0 access-plane**: convert legacy routers to `require()`; live Okta/Entra SSO+SCIM
   round-trips; mTLS at the proxy + CRL.
3. **P0 recovery**: restore-tested backups + DR runbook + a **game day** (kill primary
   under load, prove RTO/RPO).
4. **P1 hardening**: Redis HA, SAST/DAST/SCA, Grafana + ingest-lag alerts, OTA canary
   rollout policy, live SIEM delivery tests.
5. **Program (not code)**: SOC 2 Type II / ISO 27001 controls + external audit.

**Brutal-honest bottom line:** the *security core* is now demonstrably correct
(12/12 against real Postgres, 5 real bugs killed). It is **not yet production-proven**
until the P0 items above pass — above all **Postgres HA**, a **load test that meets SLO
at your target tier**, and **live SSO/SCIM/SIEM round-trips**. Those are where a customer
would otherwise find the next failure first.

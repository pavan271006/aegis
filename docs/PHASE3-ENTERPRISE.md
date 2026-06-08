# AEGIS Phase 3 — Agent Platform + Incident Case Management

Additive. Migration `0003_phase3`. Wired via `enterprise.wire(app)`. Postgres + Redis.

| File | Purpose |
|---|---|
| `migrations/versions/0003_phase3_agents_cases.py` | 12 tables (+RLS) for fleet + cases |
| `app/enterprise/models_p3.py` | ORM |
| `app/enterprise/agents.py` | Per-org CA, enrollment, mTLS identity, fleet, OTA |
| `app/enterprise/cases.py` | Cases, SLA, escalation, notes, timeline, playbooks |

---

## 1. Agent Platform (VERY HIGH)

**Why** — The legacy agent was a cron shipping plaintext logs with one shared API
key, no identity, no integrity, no management. That's an unmanageable, spoofable
fleet — a non-starter at scale.

**Schema** — `agent_cas` (per-org CA, key envelope-encrypted), `agents`
(identity/status/cert/version/health), `agent_enrollment_tokens` (one-time, TTL,
use-capped), `agent_releases` (global signed OTA channel).

**Backend / trust model**
- **Per-org CA** auto-provisioned (4096-bit, 10-yr), private key encrypted at rest.
- **Secure enrollment:** agent posts a one-time token + a **CSR**; we sign a 90-day
  client cert whose subject binds it to **`O=<org_id>, CN=<agent_id>`**.
- **mTLS identity:** TLS terminates at the proxy (nginx/Envoy `verify client on`
  against the org CA); the proxy forwards the verified cert; `agent_identity`
  parses org+agent from the CA-signed subject (so it's trustworthy) and re-checks
  serial + status — no cross-tenant lookup, RLS intact.
- **Fleet/health:** heartbeat updates `version`/`health`/`last_seen`; list view
  flags stale agents (>15 min). Revoke flips status → proxy CRL denies next handshake.
- **OTA:** `GET /manifest` returns the latest release for the agent's channel with
  a **signature** (RS256 over the artifact sha256, AEGIS signing key) + JWKS — the
  agent verifies the signature before applying, so a compromised mirror can't push
  a trojaned binary.

**API** — `POST /api/v2/agents/tokens` (admin) · `POST /enroll` (token) ·
`POST /heartbeat` (mTLS) · `GET /api/v2/agents` (fleet) ·
`POST /{id}/revoke` (admin) · `GET /manifest` (mTLS).

**Agent-side (reference)** — generate keypair + CSR; `POST /enroll`; store cert;
every request uses the client cert (mTLS); poll `/manifest`, verify signature,
swap binary, restart. (To wire into `agent/aegis_agent.py`.)

**Security** — per-agent identity + revocation; signed updates; encrypted CA keys;
short-lived client certs; tokens single-use + TTL.

**Migration / rollout** — run `0003`; deploy the proxy mTLS config; enroll a pilot
host; cut the shipper over to mTLS; retire the shared API key.

## 2. Incident Case Management (HIGH)

**Why** — A SOC can't run on `open/contained/resolved` with no owner, SLA, or
audit trail. Required for IR process + compliance evidence.

**Schema** — `cases`, `case_incidents`, `case_notes`, `case_events` (append-only
timeline), `sla_policies`, `escalation_rules`, `playbooks`, `playbook_runs`.

**Backend** — create (from an incident or manual), **assign/ownership**, status
workflow that stamps `first_response_at`/`resolved_at` (stopping the SLA clocks),
**SLA** computed from per-severity policy, **escalation sweep** (`run_escalations`,
scheduler-driven) that flags breaches and fires rules (reassign / severity-bump /
notify), **investigation notes**, full **timeline**, and a declarative **playbook
engine** (`note/assign/status/notify/siem` steps with a run log). Every state
change writes a timeline event **and emits a `case.*` event to the SIEM forwarder**.

**API** — `POST /api/v2/cases`, `GET /cases`, `GET /cases/{id}`,
`/{id}/assign|status|notes|run-playbook|timeline`.

**Frontend** — a Cases page (queue with SLA-breach flags, owner, severity), case
detail (timeline + notes + linked incidents + playbook runner). (React, to add.)

**Security** — RLS-scoped; role-gated (`analyst` to mutate, `read_only` to view);
notes/timeline immutable; SIEM mirror for external audit.

**Rollout** — seed `sla_policies` + `playbooks`; auto-create a case on high-sev
incidents; enable the escalation job in the scheduler.

---

## Still outstanding — honest status + plan

### Software features (I'll build next, same format)

| # | Feature | Plan | Cx |
|---|---|---|---|
| ATT&CK | Mapping + coverage heatmap | Seed `attack_techniques` from MITRE STIX; map detection rules → T-IDs; auto-tag incidents/cases; tactics×techniques heatmap endpoint + UI | M |
| TIP | STIX/TAXII + IOC enrichment + actor intel + sightings | `taxii2-client` poll → `stix2` parse → `indicators`(+aging/confidence) + `threat_actors`; match ingest IOCs → `sightings`; enrich incidents | L |
| Copilot | NL queries + incident explanations + investigation assistant | Provider-agnostic LLM gateway; **RAG over the tenant's own cases/incidents** (pgvector); strict tool allowlist + output guardrails + per-tenant isolation; read-only, never auto-acts | L |
| Bug Hunter v2 | Auth'd scans, OpenAPI, ZAP, Nuclei, CVE correlation | Replace naive crawler: authenticated crawl + OpenAPI import; orchestrate ZAP/Nuclei in sandboxed workers; SCA/CVE via dependency graph; EPSS/CVSS prioritization + ticketing | XL |
| Detection Content Mgmt | Versioning, testing, rollback | `detection_rules`(versioned) + `rule_tests` (fixtures w/ expected verdicts) run in CI; signed content bundles; one-click rollback | M |
| FP Management | Suppression, confidence, feedback | `suppression_rules` + per-rule `confidence`; analyst FP/TP feedback loop retunes thresholds; "auto" mode gated on confidence ≥ threshold | M |
| Tenant Billing | Plans, subscriptions, usage | Stripe; `plans/subscriptions/usage_records`; metered events/agents/seats; quota enforcement middleware | L |
| Customer Portal | Self-service, API keys, usage, billing | Org-admin portal: scoped `api_keys`, usage dashboards, plan management, SCIM/SSO setup | L |

### Operations programs — **not software features** (you flagged this correctly)

These are **programs**, not code. AEGIS can ship the *software hooks*; the rest is
process, audit, and people:

- **SOC 2 Type II / ISO 27001** — software hooks: tamper-evident audit (hash-chain),
  access reviews export, change-management records, evidence-collection API. The
  certification itself = 6–12-month controls program + external auditor + pen test.
  Code is ~10% of this; do not conflate.
- **GDPR** — *implementable* slice: `DELETE /org/{id}/subject/{email}` (erasure),
  `GET /export` (portability, JSON), a **retention engine** (per-table TTL job) and
  PII-field encryption. The rest (DPA, RoPA, lawful basis, DPO) is legal/process.
- **Disaster Recovery** — software: automated **encrypted, offsite, integrity-checked
  backups** + scheduled **restore tests** (the legacy local-zip "backup" fails audit).
  Failover = infra + runbooks, not a feature.
- **High Availability** — architecture/IaC, not a feature: multi-AZ/region, LB,
  Postgres primary+replicas+PITR, Redis HA, stateless workers (Phase-1 already
  removed the in-process detection-state blocker). Deliver as Helm/Terraform + a DR
  runbook.

**Recommended next batch (Phase 4):** ATT&CK + TIP + Copilot (the three HIGH/MEDIUM
software items that compound), then GDPR endpoints + retention engine + tamper-evident
audit (the compliance slice that's actually code), then FP management + detection
content (detection quality), then billing/portal (commercialization). Bug Hunter v2
is its own track (XL) and arguably should integrate a real scanner rather than be
rebuilt in-house.

Say **"build ATT&CK + TIP + Copilot"** or pick any subset and I'll implement it.

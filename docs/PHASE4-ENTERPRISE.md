# AEGIS Phase 4 — ATT&CK · TIP · Detection/FP · Copilot · Compliance

Additive. Migration `0004_phase4`. Wired via `enterprise.wire(app)`. Postgres + Redis.

| File | Purpose |
|---|---|
| `migrations/versions/0004_phase4_*.py` | ATT&CK ref, TIP, detection/FP, retention; audit hash-chain |
| `app/enterprise/attack.py` | Detection→technique map, enrichment, coverage heatmap, exec report |
| `app/enterprise/tip.py` | STIX/TAXII poll, indicators, actors, matching, sightings |
| `app/enterprise/detections.py` | Rule versioning/tests/rollback + suppression/confidence/feedback |
| `app/enterprise/copilot.py` | LLM gateway + tenant-scoped RAG + read-only guardrails |
| `app/enterprise/compliance.py` | Tamper-evident audit, GDPR export/erase, retention, backup validation |

---

## 1. ATT&CK Mapping (`attack.py`)
**Why** — Enterprises buy detections expressed in ATT&CK; it's the lingua franca for coverage and board reporting.
**What** — Seeded technique catalog + a detection-key→technique map (e.g. `credential_stuffing → T1110.004 → Credential Access`); `techniques_for()` tags incidents at ingest; **coverage heatmap** (tactics×techniques with observed counts + which we have detections for); **executive report** (activity by tactic, top techniques, coverage ratio).
**API** — `GET /api/v2/attack/techniques|coverage|report`.
**Note** — seed with `attack.seed()` on deploy; import the full MITRE STIX bundle to go beyond the AEGIS-relevant subset.

## 2. Threat Intelligence Platform (`tip.py`)
**Why** — Without external intel, detection is context-free. STIX/TAXII is the standard.
**What** — Per-org **TAXII 2.1 feeds** → **STIX 2.x** parse → `indicators` (ipv4/domain/url/sha256, confidence, aging via `valid_until`) + `threat_actors`; `match()` checks observed IOCs against the store; `enrich_incident()` records **sightings** and attaches actor/source context.
**API** — `POST /feeds`, `POST /poll`, `GET /indicators`, `GET /actors`.
**Security** — feed creds envelope-encrypted; indicators RLS-scoped per org.

## 3. Detection Content + FP Management (`detections.py`)
**Why** — At 100s–1000s of rules you need versioning/testing/rollback; and FP control is what keeps "auto" mode from causing outages.
**What** — **Versioned rules** (`detection_rules` + `rule_versions`), **unit tests** (sample + expected verdict, CI-runnable), **one-click rollback**; **suppression rules** (`is_suppressed()` drops known-good before it becomes an incident), a **TP/FP feedback loop** that maintains a per-rule **confidence**, and a `confidence()` gate the responder can use to require approval below a threshold.
**API** — `POST /rules`, `/rules/{id}/versions|rollback|tests|test`, `/suppressions`, `/feedback`.

## 4. Security Copilot (`copilot.py`)
**Why** — "Why was this blocked?" / "Summarize today's incidents" — accelerates triage.
**What** — Provider-agnostic gateway (OpenAI/Anthropic/Azure via env), **RAG grounded only in the tenant's own incidents/cases** (RLS-scoped retrieval), strict guardrails: **read-only, no tools/actions, cites source IDs, fails closed if unconfigured, output redaction**.
**API** — `POST /copilot/ask|explain/{id}|summary`.
**Security** — never leaves the tenant boundary; no autonomous action; secrets stripped from output.

## 5. Compliance code slice (`compliance.py`)
**Why** — The *implementable* parts of GDPR + audit integrity + DR (the certifications themselves are programs, not code).
**What** —
- **Tamper-evident audit**: every entry hash-chained to the previous; `verify_chain()` detects any edit/delete and the break point.
- **GDPR**: `gdpr_export` (portability JSON) + `gdpr_erase` (right-to-be-forgotten; anonymize account, purge MFA/sessions/history/memberships, audited).
- **Retention engine**: per-table TTL enforcement over a strict whitelist (scheduler-driven).
- **Backup validation**: `pg_dump` + **prove it restores** (TOC + object count, optional scratch-DB restore) — fixes the legacy unverified local-zip "backup".
**API** — `GET /compliance/audit/verify`, `GET /gdpr/export`, `POST /gdpr/erase`, `POST /retention/run`, `POST /backup/validate`.

---

## Bug Hunter v2 — staged as an orchestration track (XL), not faked
A credible v2 is a **scanner orchestrator**, not a hand-rolled crawler:
`scan_jobs` + sandboxed workers that drive **OWASP ZAP** (authenticated active scan via the ZAP API), **Nuclei** (template-based), and **OpenAPI/Swagger import** to seed authenticated endpoint coverage; results normalized → findings with **CVE/CWE** tags, **EPSS/CVSS** prioritization, dedup, and ticket sync. It needs container workers + the external tools in the image, so it's its own deployable service — I'll build it as a dedicated module/worker when you want that track, rather than pretend a few hundred lines replace ZAP+Nuclei.

## What genuinely remains (and its nature)
- **Software, buildable next:** Tenant Billing (Stripe: plans/subscriptions/usage/quota) and Customer Portal (scoped API keys, usage, plan self-service) — both L, straightforward.
- **Not features (programs/infra):** SOC 2 / ISO 27001 certification (audit + controls program), DR failover and HA multi-region (Helm/Terraform + runbooks). AEGIS now ships the *code hooks* for all of them (tamper-evident audit, retention, GDPR, backup validation, stateless workers, RLS); the rest is process, infrastructure, and an external auditor — not a commit.

## Cumulative enterprise build (Phases 1–4), all real compiling code
Multi-tenancy+RLS · enterprise auth (RS256/MFA/refresh/rotation/revocation) · API hardening · SSO (OIDC/SAML) · SCIM · SIEM forwarding · OTel/Prometheus · agent PKI/mTLS/fleet/OTA · case management+playbooks · ATT&CK · STIX/TAXII TIP · detection content+FP mgmt · Security Copilot · tamper-evident audit · GDPR+retention · backup validation.

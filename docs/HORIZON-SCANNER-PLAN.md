# Horizon Scanner — Implementation Plan (Phase 1, in-monolith slice)

**Status: PROPOSAL — awaiting approval. No implementation until approved.**
Companion to [HORIZON-PLATFORM-DESIGN.md](HORIZON-PLATFORM-DESIGN.md),
[HORIZON-COVERAGE-AND-GAPS.md](HORIZON-COVERAGE-AND-GAPS.md),
[HORIZON-ENGINEERING-PROGRAM.md](HORIZON-ENGINEERING-PROGRAM.md).

> **Directive honored:** the legacy `bug_hunter.py` is treated as historical
> reference only. It is **not** integrated. Components are reused **only** where an
> isolated piece is well-designed *and* compatible with the Horizon architecture;
> otherwise the scanner is built from scratch to the architecture. Architecture
> quality takes priority over reuse.

> **What this is:** the first *buildable* slice of Horizon, implemented **inside the
> existing AEGIS enterprise app** as an **independent subsystem** that reuses the
> enterprise spine (auth, RBAC, audit, multi-tenancy, reporting, notifications, AI)
> and touches **none** of the AEGIS monitoring/ingest pipeline. It is designed with
> clean module boundaries so each component can later extract into the standalone
> Horizon microservices without redesign.

---

## 1. Legacy `bug_hunter.py` — component-by-component verdict

Each legacy piece judged against the Horizon principle it must satisfy.

| # | Legacy component | Horizon principle at stake | Verdict | Rationale |
|---|---|---|---|---|
| L1 | Global `scan_status` dict | Multi-tenancy · persistence · concurrency | ❌ **Discard** | A single process-global = one scan at a time, **cross-tenant leakage**, lost on restart. Antithetical to org-scoped, persisted, concurrent scans. |
| L2 | `threading.Thread` fire-and-forget | Orchestration/saga · cancellation · checkpointing · resumability | ❌ **Discard** (concept reimplemented) | No persistence, no cancel, no resume, cannot scale or be observed. Replaced by DB-persisted scan states + an async orchestrator. |
| L3 | Regex link/form/input extraction | Crawl coverage · robustness | ❌ **Discard impl** / ♻ *interface idea only* | Regex HTML parsing is fragile and blind to JS. The **pure-function shape** (`extract_forms(html) -> [...]`) is compatible and worth keeping as a design pattern, but reimplemented over a real HTML parser (`selectolax`/`lxml`). |
| L4 | `SQL_ERRORS` signature list | Proof (error-based signature is a valid **[A]** method) | ♻ **Reuse (isolated data asset)** | A small, genuinely useful corpus of DB error strings. Reusable verbatim as **seed data** for the SQLi error-based matcher. **The only real reusable artifact.** |
| L5 | SQLi single-payload detection flow | Proof-carrying · differential · FP-control | ❌ **Discard** | One static payload, no baseline/differential, emits no proof object. Reimplemented as error-based **+** boolean-differential with a typed proof. |
| L6 | Reflected-XSS "verbatim reflection" check | Proof (browser-*executed* canary) · FP-control | ❌ **Discard** | Reflection ≠ execution → FP-prone; **exactly** the anti-pattern Horizon's proof model rejects. Reimplemented as a unique-nonce canary (browser-execution proof added when the crawler gains a browser). |
| L7 | Hardcoded same-domain + 15-page bound | Authorization Grant scope + budget | ❌ **Discard** (concept → grants) | Scope/limits must come from **signed Authorization Grants + budgets**, not magic constants. |
| L8 | `Vulnerability` ORM model | Proof-carrying findings · org-scoping · scan linkage | ❌ **Discard** | No `org_id`, `scan_id`, proof, or confidence; tied to the monitoring pipeline. New `scan_findings` model instead. |
| L9 | `httpx` HTTP client | Tool choice | ♻ **Reuse (tool)** | Correct library, already a dependency. Reused **wrapped** by the safety layer (grant check + scope + rate bucket). |
| L10 | `responder.audit(...)` on discovery | Audit (tamper-evident) | ❌ **Discard impl** / ♻ *concept* | Right instinct, wrong sink. Reimplemented via the enterprise **hash-chained** `compliance.append_audit`. |

### 1.1 Net result of the comparison
- **Reused, isolated:** the **`SQL_ERRORS` corpus** (L4) as seed data; the **`httpx`
  tool choice** (L9); and the **pure-stateless-check design pattern** (L3/L5/L6 as an
  *idea*, not code).
- **Discarded:** everything stateful, unscoped, or FP-prone — global state, the
  threading model, regex crawling, naive detection flows, hardcoded bounds, the
  `Vulnerability` model, and the legacy audit call.
- **Honest conclusion:** ~95% of the legacy implementation is **incompatible** with
  Horizon's safety/proof/multi-tenant model and is discarded. Nothing is bent to fit.

---

## 2. Target architecture (Horizon, scaled to the monolith)

The full Horizon is a microservice fleet. Phase 1 implements the **same logical
components as cohesive modules** in one package, with boundaries drawn on the future
service seams so extraction is later a *move*, not a *rewrite*.

```
backend/app/enterprise/scanning/           # the new, independent subsystem
├── models.py         ORM: scan_targets, scan_grants, scans, scan_endpoints, scan_findings
├── grants.py         [TIER-0] Authorization Grant: issue (signed) + verify        → Horizon grant-svc
├── safety.py         [TIER-0] scope canonicalization · assert_in_scope · rate bucket → Horizon rate-bucket
├── orchestrator.py   scan saga state machine + async worker loop (DB-persisted)    → Horizon orchestrator
├── crawler.py        HTTP fetch + real-HTML parse + endpoint/param discovery       → Horizon crawler (HTTP-only MVP)
├── checks/           proof-carrying check plugins                                  → Horizon scan-worker + content
│   ├── base.py         Check protocol + typed Proof/Finding contracts
│   ├── passive.py      headers · TLS · cookies · CSP · mixed-content · secrets-in-JS
│   ├── sqli.py         error-based (reuses SQL_ERRORS) + boolean-differential
│   ├── xss.py          reflected canary (unique nonce)
│   └── misc.py         open redirect · permissive CORS
├── verify.py         independent re-test of candidates before "confirmed"          → Horizon verify
├── findings.py       proof schema · persistence · location-dedup                   → Horizon findings/correlation-lite
├── reporting.py      findings → JSON / SARIF / HTML + AI narrative                 → Horizon reporting (reuses copilot)
└── router.py         /api/v2/scanner/* endpoints                                   → Horizon gateway/API
```

**Non-negotiable Horizon invariants carried into Phase 1:**
1. **No outbound request without a live, matching Authorization Grant** (safety.py
   gate, checked in the httpx wrapper — every request, no exceptions).
2. **Aggregate per-target rate cap** enforced by a shared bucket (Tier-0).
3. **Proof-carrying findings** — a finding cannot be `confirmed` without a typed
   proof; confidence is ceiling-capped by proof type (design §4 of the coverage doc).
4. **Intrusive/destructive classes default-off**; Phase 1 ships only passive +
   active-safe.
5. **Every scan + grant action audited** via the enterprise hash-chained log.
6. **Tenant-scoped** end to end (`org_id` on every row; RLS on Postgres,
   app-scoping on SQLite via `tenant_session`).

---

## 3. Reusable components (the short, honest list)

| Reuse | Source | How |
|---|---|---|
| **Enterprise auth (RS256/JWKS)** | `enterprise.deps.require` | Every scanner route gated by `require(min_role)` |
| **RBAC (4-tier)** | `enterprise.deps` | grants/scan-launch = `analyst`+; intrusive = `admin`+ |
| **Multi-tenancy / RLS** | `enterprise.tenancy.tenant_session` | Worker opens a tenant session per scan's `org_id` |
| **Tamper-evident audit** | `enterprise.compliance.append_audit` | Grant create, scan start/stop, finding-confirm |
| **AI gateway** | `enterprise.copilot._complete` | Finding explanation + remediation + report narrative (optional; 503-safe) |
| **Notifications / SIEM** | `enterprise.siem.emit` | `scan.completed`, `finding.confirmed` events |
| **Crypto/KEK** | `enterprise.crypto` | Sign/verify grants; encrypt any target creds |
| **Model conventions** | `enterprise.models_p4` patterns | `UUID_TYPE(as_uuid=False)`, `JSON_TYPE`, `utcnow`, `org_id` FK |
| **`SQL_ERRORS` corpus** | legacy `bug_hunter.py` (L4) | Seed data for `checks/sqli.py` error matcher |
| **`httpx`** | existing dependency (L9) | Wrapped HTTP client in `crawler.py`/checks |

## 4. Components to discard
Global scan state (L1), the threading model (L2), regex crawling (L3), naive
single-payload SQLi (L5), verbatim-reflection XSS (L6), hardcoded scope/limits (L7),
the legacy `Vulnerability` model (L8), and the legacy audit call (L10). None are
imported; `bug_hunter.py` is left in place untouched as historical reference.

## 5. Required new services (modules in Phase 1, extractable later)
`grants.py` (Tier-0 authorization), `safety.py` (Tier-0 scope + rate), `orchestrator.py`
(saga + async worker), `crawler.py` (HTTP crawl/discovery), `checks/*` (proof-carrying
detections), `verify.py` (re-test), `findings.py` (proof model + dedup),
`reporting.py` (report + AI), `router.py` (API). Each maps 1:1 to a Horizon service
(§2) so Phase 2+ extraction is a relocation, not a redesign.

---

## 6. Database changes

**Additive only.** New `scan_*` tables in a single Alembic migration. **Zero changes**
to monitoring tables (`events`, `incidents`, `actions`, `vulnerabilities`, …). Follows
enterprise model conventions; every table carries `org_id` for tenant scoping/RLS.

```sql
-- Authorization keystone: nothing scans a host without a live, matching grant.
scan_grants(
  id uuid pk, org_id uuid fk, scope_type text,        -- 'domain'|'wildcard'|'url'
  scope_value text, allowed_classes text[],           -- ['passive','active_safe']
  max_rps int default 5, not_before ts, not_after ts,
  signed_by int fk users, signature text, revoked_at ts, created_at ts)

scan_targets(
  id uuid pk, org_id uuid fk, name text, base_url text,
  ownership_attested bool default false,              -- explicit "I'm authorized"
  tech jsonb default '{}', created_by int, created_at ts)

scans(
  id uuid pk, org_id uuid fk, target_id uuid fk, grant_id uuid fk,
  profile text,                                        -- 'passive'|'safe'|'full'
  state text default 'queued',                         -- saga state
  budget jsonb, consumed jsonb default '{}',           -- {max_requests,max_seconds}
  started_at ts, finished_at ts, created_by int, created_at ts)

scan_endpoints(
  id uuid pk, org_id uuid fk, scan_id uuid fk, method text, url text,
  params jsonb default '[]', source text,              -- 'crawl'|'form'|'bundle'
  content_hash text, created_at ts)

scan_findings(
  id uuid pk, org_id uuid fk, scan_id uuid fk, endpoint_id uuid fk,
  class text, severity text, confidence text,          -- potential|firm|confirmed
  proof jsonb,                                          -- {type, nonce?, evidence...}
  evidence_ref text, status text default 'new', created_at ts)
```
(Evidence blobs — request/response captures — stored as rows/JSON in Phase 1; move to
an object store when volume warrants, per the engineering program's deferral triggers.)

## 7. APIs (`/api/v2/scanner/*`, all behind `require()`)

```
# Targets
POST   /api/v2/scanner/targets                 register target + ownership attestation   (analyst)
GET    /api/v2/scanner/targets                  list                                      (read_only)

# Authorization Grants  [TIER-0]
POST   /api/v2/scanner/grants                   create a signed scope grant              (admin)
GET    /api/v2/scanner/grants                    list                                      (read_only)
POST   /api/v2/scanner/grants/{id}/revoke        revoke (halts in-scope scans)            (admin)

# Scans
POST   /api/v2/scanner/scans                    start {target_id|url, profile}           (analyst)
GET    /api/v2/scanner/scans                     list                                      (read_only)
GET    /api/v2/scanner/scans/{id}                state + progress + consumed budget        (read_only)
POST   /api/v2/scanner/scans/{id}/abort          cooperative cancel                        (analyst)
GET    /api/v2/scanner/scans/{id}/findings        proof-carrying findings                   (read_only)
GET    /api/v2/scanner/scans/{id}/report          JSON | SARIF | HTML (+AI narrative)       (read_only)
```
Conventions inherited from the enterprise API: RFC-7807 errors, `202`+resource for the
async scan, poll `GET /scans/{id}` for progress (SSE deferred). Every state-changing
call writes an audit entry.

## 8. UI (new **"Scanner"** console page, nav min-role `analyst`)
A new nav item + view in the React console:
- **Targets** — register a URL + a required "I am authorized to test this" checkbox
  (ownership attestation) → creates target + a default grant.
- **New scan** — pick target (or type a URL), choose profile (Passive / Safe), Start.
- **Live progress** — state, pages crawled, requests used vs budget, rate.
- **Findings table** — class, severity, **confidence badge**, endpoint, proof/evidence
  expander; plus a visible **"coverage / not-assessed"** note (Horizon honesty gap-fix).
- **Report** — export JSON/SARIF/HTML; optional AI "explain & remediate" (copilot).
Fits the existing `modules.jsx` + `api.js` patterns; no redesign of the shell.

## 9. Integration with shared enterprise services (clean seams)
- **Auth/RBAC/tenancy:** routes use `require()`; models carry `org_id`; the worker uses
  `tenant_session(org_id)` (same pattern the legacy scheduler uses out-of-request).
- **Audit:** `append_audit` on grant issue/revoke, scan start/abort/complete,
  finding→confirmed.
- **AI:** `copilot._complete` for finding explanation + report prose (fails closed to
  503; findings fully usable without it).
- **Notifications:** `siem.emit` on `scan.completed` / `finding.confirmed`; findings can
  later open **AEGIS cases** (reuse) — deferred to Phase 2.
- **No coupling** to ingest/detection/incident code — separate package, tables, router,
  worker.

## 10. Migration strategy
1. **Additive & flagged.** New tables via one Alembic migration (expand-only). New
   subsystem behind `AEGIS_SCANNER_ENABLED=1`; router mounted and worker started only
   when the flag **and** `AEGIS_ENTERPRISE=1` are set.
2. **Legacy untouched.** `bug_hunter.py` and its `/api/admin/scanner/*` endpoints are
   left as-is (already inert in enterprise mode); not referenced by the new subsystem.
3. **Reversible.** Disable the flag → router/worker off, tables dormant (no data loss).
   Down-migration drops only `scan_*` tables.
4. **Independent lifecycle.** The subsystem can be developed, tested, and shipped
   without touching monitoring code; its worker starts in the app lifespan guarded by
   the flag.
5. **Extraction-ready.** Module seams == Horizon service seams, so Phase 2 can lift
   `orchestrator`/`crawler`/`checks` into standalone workers behind a queue with no
   contract redesign.

## 11. Phase 1 scope vs. deferred (roadmap-aligned)
**In Phase 1 (Horizon v0→v1 slice):** grants + safety/rate, HTTP crawler + form/param
discovery, passive checks, active-safe SQLi (error + boolean-diff) and reflected-XSS
(nonce canary), open-redirect/CORS, verify pass, proof-carrying findings, coverage
note, report (JSON/SARIF/HTML) + optional AI, full enterprise integration.

**Explicitly deferred (with reason):**
- **Browser/JS crawling** — needs the Chromium fleet (engineering program trigger);
  Phase 1 is HTTP-only and will *say so* (SPAs under-covered — honest limitation).
- **OAST / blind vulns (SSRF/blind-SQLi/XXE)** — require a public collaborator server;
  **not feasible on a localhost MVP**. Blind classes are out of Phase 1 scope, stated.
- **Auth-matrix / IDOR, intrusive classes, correlation, plugin SDK, distributed
  workers** — later Horizon phases.

## 12. Risks & open decisions (need your call)
- **R1 — Orchestration runtime.** Phase 1 = in-process **asyncio worker** started in
  the app lifespan, DB-persisted state, cooperative cancel, "resume interrupted on
  boot." Fine for local/single-instance; **not** multi-instance safe (two app replicas
  would double-run a scan). Acceptable for MVP? (Prod → extract to a queue-backed
  worker, per Horizon.)
- **R2 — Rate bucket store.** Redis if available, else in-process token bucket (single
  instance). Same MVP caveat as R1.
- **R3 — API namespace.** Proposing `/api/v2/scanner/*` to sit with the existing v2
  console/auth. The design docs reserved `/api/v3` for the standalone Horizon; I
  recommend `/api/v2/scanner` now and `/api/v3` only at extraction. OK?
- **R4 — Grant UX.** Register-target auto-creates a default grant (scope = the target,
  classes = passive+safe) to keep the first run one-click, while still enforcing the
  Tier-0 gate. Acceptable, or require explicit grant creation?

## 13. Approval gate
**No code will be written until this plan is approved.** On approval I will implement in
this order (each independently testable): (1) models + migration, (2) grants + safety
[Tier-0, mutation-tested], (3) orchestrator + worker, (4) crawler, (5) checks + verify +
proof model, (6) router + API, (7) console page, (8) reporting + AI + audit/SIEM wiring.

Please confirm **§12 R1–R4** and give the go-ahead (or amendments).

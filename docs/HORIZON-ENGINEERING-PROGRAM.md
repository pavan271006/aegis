# AEGIS Horizon — Engineering Master Program (24-Month Execution Plan)

**Audience:** engineering leadership + implementing senior engineers.
**Status:** architecture v1.0 is frozen (see [HORIZON-PLATFORM-DESIGN.md](HORIZON-PLATFORM-DESIGN.md)
and [HORIZON-COVERAGE-AND-GAPS.md](HORIZON-COVERAGE-AND-GAPS.md)). This document does
**not** redesign architecture; it defines how to build it. No implementation code.

> **Leadership stance, stated once and applied everywhere.** The frozen architecture
> is capability-complete but, if built literally, imposes **seven stateful systems**
> (Postgres, Redis, OpenSearch, Neo4j, MinIO, VictoriaMetrics, NATS), **three
> languages**, and **two heavy control frameworks** (Temporal, KEDA) on a team that
> starts small. That is how platforms die of operational debt before they ship. So
> this program **sequences complexity in**, not out: we start with the minimum viable
> operational surface (Postgres + Redis + object store, Python-first, Postgres-backed
> sagas) and *earn* each additional system with a measured trigger. The §18 final
> review makes these cuts explicit. **Every deferral is reversible and pre-planned —
> we are delaying operational cost, not painting into a corner.**

---

## Contents
1. [Guiding Engineering Principles](#1-guiding-engineering-principles)
2. [Repository Strategy](#2-repository-strategy)
3. [Language & Runtime Strategy](#3-language--runtime-strategy)
4. [Microservice Build Order](#4-microservice-build-order)
5. [Database Strategy](#5-database-strategy)
6. [API Strategy](#6-api-strategy)
7. [Browser Infrastructure](#7-browser-infrastructure)
8. [Worker Infrastructure](#8-worker-infrastructure)
9. [Knowledge Graph](#9-knowledge-graph)
10. [AI Infrastructure](#10-ai-infrastructure)
11. [Observability](#11-observability)
12. [Testing Strategy](#12-testing-strategy)
13. [DevOps / Delivery](#13-devops--delivery)
14. [Security Program](#14-security-program)
15. [Performance Envelope](#15-performance-envelope)
16. [Cost Model](#16-cost-model)
17. [Documentation Roadmap](#17-documentation-roadmap)
18. [Engineering Organization](#18-engineering-organization)
19. [Implementation Plan (Milestones→Tasks)](#19-implementation-plan)
20. [Final Review & Simplification](#20-final-review--simplification)

---

## 1. Guiding Engineering Principles

1. **Operational surface is a budget.** Every new datastore, language, or framework
   must justify its 3am-pager cost. Default answer to "add a system" is *no, until a
   trigger fires.*
2. **Safety code is Tier-0.** The Authorization-Grant checks and per-target rate caps
   get the same rigor as a payments system: 100% branch coverage, mutation-tested,
   dual-reviewed, change-controlled. A scanner that hits the wrong target is an
   incident with legal consequences.
3. **Proof-carrying or it didn't happen.** No finding reaches "confirmed" without the
   typed evidence schema. This is enforced in code, not convention.
4. **Ship vertically, not horizontally.** Each release delivers one end-to-end user
   outcome (grant→scan→finding→report), never a half-built layer nobody can use.
5. **Boring where it doesn't differentiate; excellent where it does.** Postgres, not
   a fashionable DB. Chromium+CDP and the correlation engine are where we spend
   novelty budget.
6. **Reuse the AEGIS spine.** Auth, tenancy, RLS, audit, PKI, cases, compliance,
   crypto already exist and are production-shaped. We extend, never fork.
7. **Everything a team owns, a team is paged for.** Ownership = build + run + on-call.

---

## 2. Repository Strategy

### 2.1 Monorepo — decision and rationale

**Decision: single monorepo (`horizon/`).** Justification: the platform is one
coordinated system with heavy shared contracts (event schemas, the proof/finding
model, the plugin ABI). Polyrepo would force version-skew management across ~15
services for schemas that change together. Stripe/Google/Vercel-style monorepo gives
atomic cross-cutting changes, one CI graph, and one source of truth for contracts. We
accept the monorepo's cost (needs good tooling, careful CODEOWNERS) because
contract-coupling is the dominant force here.

**We do *not* adopt Bazel initially** — it's a tax a 15-engineer org can't afford.
Start with language-native builds orchestrated by a thin `make` + task runner; migrate
to Bazel only if incremental-build time crosses a pain threshold (trigger: CI > 20 min).

### 2.2 Structure

```
horizon/
├── README.md                    # 10-minute "clone→running locally" path
├── CODEOWNERS                   # every dir maps to exactly one owning team
├── Makefile                     # meta targets: bootstrap, test, lint, up, gen
├── docs/                        # this program + ADRs + runbooks (see §17)
│   ├── adr/                     # Architecture Decision Records (numbered, immutable)
│   └── runbooks/
│
├── platform/                    # shared, cross-service foundations
│   ├── contracts/               # SINGLE SOURCE OF TRUTH for cross-service types
│   │   ├── events/              #   event schemas (JSON Schema / protobuf) → codegen
│   │   ├── openapi/             #   the public REST spec (OpenAPI 3.1)
│   │   └── proto/               #   internal gRPC service contracts
│   ├── pyspine/                 # the reused AEGIS Enterprise package (auth, tenancy,
│   │                            #   RLS, audit, PKI, cases, crypto, compliance)
│   ├── libpy/                   # shared Python libs (config, logging, otel, errors)
│   ├── libgo/                   # shared Go libs (queue client, rate-bucket, otel)
│   └── plugin-sdk/              # the Tier-1/2/3 plugin SDK + ABI + validator
│
├── services/                    # one deployable per subdir; each = build+run+oncall
│   ├── gateway/                 # (py) edge API/BFF, authN, rate-limit, WS fan-out
│   ├── orchestrator/            # (py) scan saga state machine
│   ├── scheduler/               # (py) cron + event-triggered + continuous cadence
│   ├── grant-svc/               # (py) Authorization Grant issue/verify  [TIER-0]
│   ├── recon-worker/            # (go) subdomain/host/port/tech discovery
│   ├── crawler/                 # (go+node) Chromium/CDP state-graph crawler
│   ├── static-analyzer/         # (go) JS bundle/source-map mining, secrets
│   ├── api-discovery/           # (py) OpenAPI/GraphQL/param-mine
│   ├── scan-worker/             # (go) per-class active scanning (plugin host)
│   ├── authmatrix/              # (py) multi-identity replay + authz diff
│   ├── verify/                  # (py) independent re-test + OAST correlation
│   ├── oast-collaborator/       # (go) authoritative DNS/HTTP/SMTP callback listener
│   ├── correlation/             # (py) dedup, DAST⨯SAST⨯SCA, chain assembly
│   ├── risk-scorer/             # (py) exploitability + business-context scoring
│   ├── ai-svc/                  # (py) planner + analyst gateway (RAG, routing)
│   ├── reporting/               # (py) exec/dev/compliance report render
│   ├── evidence/                # (go) screenshot/HAR/response capture + store
│   └── notifier/                # (py) Jira/Slack/SIEM/webhook fan-out
│
├── apps/
│   ├── console/                 # (ts/react) operator web UI
│   └── cli/                     # (go) horizon-cli (CI-friendly, single binary)
│
├── plugins/                     # first-party check content
│   ├── templates/               # Tier-1 declarative (Nuclei-superset YAML)
│   └── native/                  # Tier-2 WASM plugin sources
│
├── deploy/                      # IaC: helm charts, terraform, k8s manifests
│   ├── helm/ · terraform/ · compose/   # compose = single-node dev/lite
│
├── test/                        # cross-service e2e, load, chaos, replay corpora
│   └── synthetic-targets/       # deliberately-vulnerable apps for CI (see §12.6)
│
└── tools/                       # dev tooling, codegen, migration runner, linters
```

### 2.3 Folder-by-folder intent (the non-obvious ones)

- **`platform/contracts/`** — the keystone. All cross-service types live here and are
  **code-generated** into each language. A service may never hand-define another
  service's message. PR that changes a contract triggers regeneration + downstream
  compile checks in one CI run. This is what makes the monorepo pay off.
- **`platform/pyspine/`** — the existing AEGIS Enterprise code, imported as a package,
  not copied. Horizon services depend on it for `require()`, tenancy, audit, PKI.
- **`platform/plugin-sdk/`** — versioned ABI; the validator enforces "findings carry
  proof" at build time so no plugin can emit an unprovable confirmed finding.
- **`services/*`** — strict rule: **one deployable, one owner, one on-call rotation.**
  A service imports only from `platform/*` and its own dir — never another service's
  internals (only its generated contract).
- **`test/synthetic-targets/`** — our own vulnerable apps (juice-shop-class, plus
  purpose-built) that CI scans to assert detections. Ground truth for precision/recall.

### 2.4 Naming conventions

| Thing | Convention | Example |
|---|---|---|
| Service dir & deployable | `kebab-case`, noun | `scan-worker` |
| Event subject | `dot.namespaced`, past-tense | `finding.confirmed` |
| DB table | `snake_case`, plural | `auth_grants` |
| Python module/pkg | `snake_case` | `horizon_verify` |
| Go package | short lower, no underscores | `ratebucket` |
| TS component | `PascalCase` | `FindingCard` |
| Env var | `HORIZON_` prefixed, SCREAMING | `HORIZON_OAST_ZONE` |
| Metric | `horizon_<svc>_<noun>_<unit>` | `horizon_crawler_pages_total` |
| Feature flag | `flag.<area>.<name>` | `flag.scan.intrusive_sqli` |
| ADR | `NNNN-title.md` (immutable once accepted) | `0007-defer-neo4j.md` |

### 2.5 Coding standards

- **Python:** 3.11+, `ruff` (lint+format), `mypy --strict` on all new code, `pytest`.
  FastAPI + SQLAlchemy 2.0 (matches AEGIS). Public functions typed and docstringed.
- **Go:** 1.22+, `golangci-lint`, `gofumpt`, table-driven tests, `context.Context`
  first arg everywhere, no global state in workers.
- **TS:** strict `tsconfig`, ESLint + Prettier, React + TanStack Query, no `any`.
- **Universal:** trunk-based, PRs < ~400 lines preferred, two approvals for Tier-0
  (grant/rate/auth) code, one otherwise; every PR green CI + CODEOWNERS approval.
- **Errors:** typed error taxonomy in `libpy`/`libgo`; RFC 7807 at the edge; never
  swallow exceptions in workers (emit to dead-letter with context).

### 2.6 Dependency management

- Python: `uv` (fast, lockfile-first) with a **single workspace lock**; renovate bot
  for updates; `pip-audit`/`osv-scanner` in CI (we're a security company — dogfood).
- Go: modules + workspace (`go.work`); `govulncheck` in CI.
- TS: `pnpm` workspaces, lockfile committed.
- **Third-party OSS tools we wrap** (nuclei, katana, subfinder…) are **pinned by
  digest**, vendored in signed container base images, SBOM-tracked (§14.8). No
  `latest`, ever.

---

## 3. Language & Runtime Strategy

Deliberate polyglot, minimized to three:

| Language | Where | Why |
|---|---|---|
| **Python** | control plane, AI, correlation, API, most workers | Reuses AEGIS spine; team velocity; the AI/correlation logic lives here |
| **Go** | high-throughput / IO-bound workers (recon, crawler driver, OAST, evidence, scan-worker), CLI | The best OSS security tools are Go; concurrency + single-binary deploy + low memory matter at the traffic tier |
| **TypeScript** | console UI only | Obvious |

**Rule:** a new service defaults to Python unless it is on the outbound-traffic hot
path (then Go). We will resist a fourth language indefinitely.

---

## 4. Microservice Build Order

Ordered by dependency topology and value-per-risk. **Bold = critical path.**

### Wave 0 — Foundations (nothing safe or testable without these)
1. **`platform/contracts`** + codegen — everything compiles against it.
2. **`platform/pyspine` integration** — wire AEGIS auth/tenancy/audit into a Horizon
   gateway skeleton.
3. **`grant-svc`** [TIER-0] — no worker may exist before the thing that authorizes it.
4. **`gateway`** — the front door; gives us a testable API immediately.
5. **queue + event bus client** (`libgo`/`libpy`) + **rate-bucket** [TIER-0].

*Rationale:* these are prerequisites for *every* downstream service; they carry the
safety invariants; none touch a target so they're low-risk to build first.

### Wave 1 — The thin vertical slice (prove the pipeline end-to-end)
6. **`orchestrator`** (Postgres-backed saga first — not Temporal; see §5/§20).
7. **`recon-worker`** — passive, can't harm a target; first real "work."
8. **`evidence`** + object store — everything needs to attach proof.
9. **`reporting`** (minimal) — closes the loop: grant→recon→finding→report.
10. **`console`** (minimal) — makes it demoable.

*Parallelizable:* recon-worker, evidence, and console can proceed in parallel once
contracts + orchestrator emit events.

### Wave 2 — The DAST core (the hard, high-value middle)
11. **`crawler`** — **the long pole**; start a de-risking spike in Wave 1 in parallel.
12. **`api-discovery`** — depends on crawler's intercepted traffic.
13. **`oast-collaborator`** [prereq for all blind checks].
14. **`scan-worker`** (plugin host) + **`verify`** — proof-carrying findings.

*Blocker:* `verify` depends on `oast-collaborator`; `scan-worker` blind checks depend
on both. Build OAST before intrusive plugins.

### Wave 3 — Intelligence & scale
15. **`correlation`** — needs finding volume from Wave 2.
16. **`risk-scorer`** + **`ai-svc`** — planner can retrofit into crawler later.
17. **`authmatrix`** — highest-value coverage; needs identities + verify mature.
18. **`static-analyzer`**, **`scheduler`** (continuous), **`notifier`** — parallel,
    independent, low-risk.

### Dependency summary
```
contracts → grant-svc → gateway → orchestrator ─┬→ recon → reporting/console  (W1)
                                                 ├→ crawler → api-discovery    (W2)
                                                 │      └→ oast → scan → verify
                                                 └→ correlation → risk → ai     (W3)
                                                        authmatrix (needs verify)
```
The crawler is the schedule risk. Mitigate with an early spike (§19 M2) that proves
Chromium state-graph crawling on 3 representative SPAs before committing the full
build.

---

## 5. Database Strategy

### 5.1 Store-by-store (with deferral triggers)

| Store | Role | When | Trigger to add |
|---|---|---|---|
| **Postgres (+RLS)** | system of record, findings, sagas | Day 1 | — |
| **Redis** | rate buckets, locks, cache, heartbeats | Day 1 | — |
| **Object store (S3/MinIO)** | evidence blobs | Day 1 | — |
| **OpenSearch** | finding full-text/faceted search | Deferred | findings > ~5M or console search p95 > 500ms on PG |
| **Graph (Neo4j / PG-AGE)** | knowledge graph / attack paths | Deferred | correlation queries need >3-hop traversal at scale |
| **Time-series (Victoria/Prom)** | metrics | Prom Day 1 | long-retention TSDB only if Prom retention insufficient |

Start on **three** stateful systems, not seven. The graph and search engines are
*queryable projections* of Postgres — we add them as read-optimizations when a
measured trigger fires, and the KG (§9) is defined so it can live in Postgres
recursive CTEs first.

### 5.2 Migrations & schema evolution

- **Tooling:** Alembic (matches AEGIS); one linear migration history in
  `platform/pyspine`/service-local dirs; migrations are code-reviewed like any change.
- **Expand→migrate→contract** for every breaking change (AEGIS already practices
  this): add new nullable column/table → dual-write/backfill → switch reads → drop old
  in a later release. **No destructive migration in the same release that introduces
  the replacement.**
- **Online-safe:** no long table locks; use `CREATE INDEX CONCURRENTLY`; backfills are
  batched background jobs, not migration-time.
- **Forward-only in prod;** rollback is *roll-forward with a compensating migration*,
  never `downgrade()` on live data. `downgrade()` maintained only for local/CI.
- **Every migration PR must include:** the migration, the backfill plan (or "n/a"),
  the rollback-forward note, and an estimate of lock/duration on prod-sized data.

### 5.3 Versioning, backups, rollback

- Schema version tracked in-DB (Alembic) and asserted at service boot (fail-closed on
  mismatch).
- **Backups:** managed-PG PITR (WAL) with tested restores — reuse AEGIS's
  backup-**validation** discipline (prove restore, don't just take a dump). Weekly
  automated restore-to-scratch drill; quarterly game-day full restore.
- **RPO ≤ 5 min (PITR), RTO ≤ 1 hr** for the control DB.

### 5.4 Partitioning, indexing, archival

- **Partition** high-volume, time-series-shaped tables by month:
  `findings`, `oast_interactions`, `events`, audit. Detach-and-archive old partitions
  to cold object storage per the AEGIS retention engine.
- **Indexing discipline:** every query pattern gets a named, reviewed index; no
  ad-hoc. Composite indexes lead with `org_id` (RLS + tenant locality). Partial
  indexes for hot filters (`status='new'`). Track index bloat; monthly `REINDEX`
  window as needed.
- **Archival:** evidence blobs lifecycle to infrequent-access → glacier per retention
  policy; findings older than policy move to partitioned cold storage but stay queryable
  for compliance export.

---

## 6. API Strategy

### 6.1 Surfaces
- **Public REST** (`/api/v3`, OpenAPI 3.1) — the contract for console, CLI, customers.
- **Internal gRPC** — service-to-service (typed, fast, from `platform/contracts/proto`).
- **Event bus** — async cross-service (not "API" but the primary integration path).
- **Webhooks out** — customer integrations.

### 6.2 Versioning
- URL-versioned public API (`/api/v3`); additive changes only within a version;
  breaking change = new version + 12-month deprecation with telemetry-driven sunset.
- gRPC/protobuf: field-number discipline, never reuse/remove fields (reserve them);
  internal services can move faster because the monorepo updates all callers atomically.
- Events: schema-versioned; consumers tolerate unknown fields (forward-compat);
  a subject only gets a `.v2` if a field's *meaning* changes.

### 6.3 SDK generation
- Generate typed SDKs from the OpenAPI spec: TS, Python, Go — published per release,
  versioned to match the API. CLI is a thin shell over the Go SDK.
- SARIF + OpenAPI are first-class outputs so we plug into GitHub/GitLab natively.

### 6.4 AuthN / AuthZ / rate limit / errors
- **AuthN:** AEGIS RS256 bearer via JWKS at the gateway (reused wholesale). Service
  accounts + scoped API keys for CI usage. mTLS for on-prem scanner agents (AEGIS PKI).
- **AuthZ:** AEGIS four-tier RBAC (`require(min_role)`); grant-creation and
  intrusive-scan launch are `admin`+ and MFA-gated. RLS enforces tenant isolation
  below the API entirely.
- **Rate limiting:** two layers — (1) API request rate per tenant/key at the gateway
  (reuse AEGIS ratelimit), (2) the *outbound* per-target scan rate bucket [TIER-0],
  which is a different, safety-critical control.
- **Errors:** RFC 7807 problem+json, stable machine-readable `type` URIs, no internal
  detail leakage, correlation-id in every response echoing the trace.
- **Conventions:** cursor pagination, `Idempotency-Key` on create-work POSTs, async
  202+resource for long ops, ETags where cacheable.

---

## 7. Browser Infrastructure

The most operationally demanding fleet; it executes hostile code (target JS).

### 7.1 Orchestration
- **`crawler` service** manages a pool of **browser pods**; each pod = one Chromium
  process exposing CDP. Playwright drives it. One **browser context per app-state**
  (cheap isolation), one **process per scan/tenant** (hard isolation).
- Assignment via the queue: a crawl task is leased by a crawler worker which acquires
  (or spawns) a browser pod pinned to that scan's tenant.

### 7.2 Scaling
- Browser pods are the RAM/CPU-heavy tier → their own node pool, scaled on
  **active-crawl count** (not queue depth alone). Scale-to-low when idle.
- **Density target (see §15):** ~8–16 concurrent heavy crawls per 16 vCPU / 64 GB
  node; many more light contexts. Bin-pack by expected crawl weight (SPA size).

### 7.3 Isolation & sandboxing (non-negotiable — untrusted execution)
- Browser pods run under **gVisor RuntimeClass** (or Kata/Firecracker for the
  highest-sensitivity tenants), ephemeral, **egress-locked by NetworkPolicy** to the
  in-grant scope + OAST + platform only.
- No shared filesystem; per-pod tmpfs wiped on teardown; no cross-tenant reuse — a
  context or process is destroyed, never recycled across tenants.
- Resource caps (RAM/CPU/pids/time) to contain zip-bombs and runaway JS.

### 7.4 Updates
- Chromium pinned by digest; a **weekly channel** rebuilds the browser base image,
  runs it against the synthetic-target corpus + a crawl-stability regression suite,
  and promotes via canary (1%→10%→100%). Never auto-pull upstream.
- Playwright version lockstepped with Chromium; upgrade is a reviewed PR with the
  regression gate.

### 7.5 Monitoring & debugging
- Per-crawl metrics: pages rendered, states discovered/deduped, network calls
  captured, **coverage % (frontier exhaustion)**, hangs, crashes, OOMs.
- **Debuggability:** on failure, retain a bounded artifact bundle — trace (Playwright
  trace viewer), screenshots, HAR, console log, CDP event tape — to object storage,
  linked from the scan. This is how we debug "why didn't it find X" without re-running
  against the customer.
- Crash-loop detection → quarantine the offending target/state to dead-letter, alert,
  continue the rest of the scan.

### 7.6 Storage
- HAR/trace/screenshot/video to object store, referenced by `evidence_ref`,
  lifecycle-expired. Large; a top-3 storage cost driver (§16) → capture *bounded*
  (cap response body sizes, sample video only on failure).

---

## 8. Worker Infrastructure

### 8.1 Scheduling & queues
- **Transport:** start with **Redis Streams** (already have Redis) for queues +
  a lightweight pub/sub; **adopt NATS JetStream** at the trigger (multi-consumer
  fan-out + replay needs exceed Redis Streams, ~Wave 3). Kafka only at extreme scale.
  *(This defers a whole stateful system — see §20.)*
- Per-capability priority queues; workers **pull** (never push); sharded by
  `target_id` for per-target rate/session locality.

### 8.2 Retries, idempotency, DLQ
- At-least-once delivery; **every handler idempotent** on `event.id` + natural key.
- Exponential backoff with jitter; capped attempts → **dead-letter queue** with full
  context + alert. Poison tasks never block a fleet.
- Idempotency keys persisted (Redis + PG) so a redelivered task is a no-op, not a
  double-scan (double-scanning a target is a *safety* issue, not just waste).

### 8.3 Concurrency, cancellation, checkpointing, resumability
- Concurrency governed by two independent limits: worker pool size **and** the
  outbound per-target rate bucket. The bucket wins — 1000 workers still can't exceed
  the grant's RPS.
- **Cancellation:** a `scan.aborted` / grant-revoked event is honored within seconds
  by every worker via a cancellation token checked between units of work; in-flight
  outbound request is allowed to finish, no new work starts.
- **Checkpointing:** long jobs (crawl, big scan) persist frontier/progress to PG at
  intervals; a crashed job resumes from the last checkpoint, not from zero. The saga
  in `orchestrator` is the durable coordinator.
- **Resumability:** scans are pausable/resumable by design; consumed-budget is durable
  so a resumed scan respects the original caps.

---

## 9. Knowledge Graph

### 9.1 Schema (logical)
Nodes: `Asset`, `Endpoint`, `Identity`, `Finding`, `Issue`, `Component(CVE)`.
Edges: `HOSTS`, `EXPOSES`, `REACHABLE_AS`, `HAS_FINDING`, `CORRELATES_WITH`,
`CHAINS_TO`, `USES_COMPONENT`. Every node carries `org_id` (tenant scoping).

### 9.2 Implementation path (deferral-driven)
- **Phase A (default):** the "graph" is a set of **Postgres tables + recursive CTEs**.
  Correlation's dedup and 1–2 hop joins run fine here. No new datastore.
- **Phase B (triggered):** when attack-path queries need cheap multi-hop traversal at
  scale, project into **Neo4j / PG-AGE** as a read model rebuilt from PG events. PG
  stays the source of truth; the graph is disposable and rebuildable.

### 9.3 Indexing, query optimization, consistency, lifecycle
- Indexed on `(org_id, node_type, key)`; hot traversal paths get materialized adjacency
  tables in Phase A.
- **Consistency:** the graph is *eventually* consistent with PG (it's a projection);
  correlation tolerates this. Never make the graph authoritative.
- **Lifecycle:** nodes/edges expire with their underlying findings per retention;
  rebuild job reconciles drift nightly (and on-demand after backfills).

---

## 10. AI Infrastructure

Reuses the AEGIS `copilot` provider-agnostic gateway. **Hard guardrail: AI never
promotes a finding to "confirmed" — it ranks and explains evidence the Verify fleet
produced.**

### 10.1 Prompt architecture
- Versioned prompt templates in-repo (`ai-svc/prompts/`, semver'd, reviewed like code).
- Structured I/O only: the model returns typed JSON against a schema (triage verdict,
  cluster id, remediation text) — validated, rejected+retried on schema violation.
- Tasks: **planner** (score crawl interactions, adapt WAF-blocked payloads),
  **analyst** (dedup/cluster, explain, remediate, report prose).

### 10.2 RAG
- Retrieval is **RLS-scoped to the tenant** (same guarantee as AEGIS copilot): context
  = the org's own findings, KG neighborhood, the tech fingerprint, and a curated
  remediation KB. Framework-specific remediation comes from retrieving the *detected*
  stack's guidance, not generic prose.
- Embeddings of remediation KB + historical findings in `pgvector` (no new store).

### 10.3 Evaluation & hallucination prevention
- **Golden eval set:** labeled findings → expected triage/cluster/severity; CI runs
  the AI against it and **gates releases on precision/recall/regression** of the eval
  scores (an AI prompt change is a code change with a test suite).
- Hallucination defenses: (1) output must cite evidence IDs that *exist*; a citation
  to a non-existent finding is auto-rejected; (2) severity/confidence are bounded by
  the proof tier (§ evidence model) — the model can lower but never raise the ceiling;
  (3) secret-redaction filter on all output (AEGIS pattern).

### 10.4 Model routing, caching, observability
- **Routing:** small/cheap model for high-volume triage & dedup; large model only for
  report prose and complex planning. Provider-agnostic (Anthropic/OpenAI/Azure/self-host)
  behind the gateway; per-tenant BYO-key supported.
- **Caching:** responses cached keyed on `(prompt_version, input_hash)`; crawl plans
  cached on surface hash; huge cost lever (§16).
- **Observability:** per-call token count, cost, latency, model, eval-score, cache-hit,
  schema-reject rate — all in the metrics pipeline; **hard per-scan AI cost budget**
  enforced by the orchestrator.

---

## 11. Observability

### 11.1 Pillars
- **Metrics:** Prometheus (RED per service + domain metrics: scans/sec, findings/sec,
  crawl coverage %, rate-bucket saturation, OAST callbacks). Naming per §2.4.
- **Tracing:** OpenTelemetry end-to-end; a `scan_id` and `trace_id` propagate through
  every event and service so one scan is one distributed trace.
- **Logging:** structured JSON (AEGIS logger), correlation-id on every line, no
  secrets (enforced by a log-scrubbing filter + CI check).

### 11.2 SLIs / SLOs (initial, per-service, tightened over time)
| Service | SLI | SLO (steady state) |
|---|---|---|
| gateway | availability; p95 latency | 99.9%; < 300 ms |
| grant-svc [TIER-0] | correctness (unauthorized-scan escapes) | **zero tolerance**; alert on any |
| orchestrator | scan completion success rate | ≥ 99% (excl. target-side failures) |
| crawler | crawl success rate; coverage % | ≥ 95%; coverage reported not SLO'd early |
| verify | false-positive rate on confirmed | < 2% (measured vs analyst verdicts) |
| oast-collaborator | callback capture reliability | 99.9% |

**Error budgets** drive release freezes: burn the gateway budget → feature work pauses
for reliability. Grant-svc has *no* budget — any unauthorized-scan event is a Sev-1.

### 11.3 Dashboards, alerts, incident response
- Per-service dashboard (RED + domain) + a **fleet dashboard** (scans in flight,
  outbound RPS per target vs cap, browser pod health, queue depths, DLQ counts).
- Alerts are **symptom-based + actionable** (page on "rate cap breached" or "unauthorized
  target contacted," not on CPU). Every alert links a runbook (§17).
- **Incident response:** reuse AEGIS cases + on-call rotations; Sev matrix; blameless
  postmortems with ADR/runbook follow-ups tracked to closure. A safety incident
  (wrong-target/rate-breach) has a mandatory customer-comms + legal-review path.

---

## 12. Testing Strategy

### 12.1 Unit
- Fast, hermetic, per-service. **Tier-0 code (grant/rate/authz) requires ~100% branch
  coverage + mutation testing** (`mutmut`/`go-mutesting`). Everything else pragmatic
  (~80% lines, coverage is a smell-detector not a target).

### 12.2 Integration
- Service + its real dependencies via testcontainers (PG, Redis, object store).
  Contract tests generated from `platform/contracts` assert producer/consumer
  compatibility — the monorepo's payoff.

### 12.3 End-to-end
- Full grant→scan→finding→report against **synthetic targets** in CI. Asserts the
  vertical slice works, not just units.

### 12.4 Replay
- Recorded target traffic (HAR/CDP tapes) replays deterministically so we can test the
  crawler/scanner **without hitting live targets** and re-test new plugin versions
  against old evidence (the design's replayability). Core to plugin regression.

### 12.5 Chaos, load, performance, regression
- **Chaos:** kill browser pods, drop the queue, revoke a grant mid-scan, network
  partition — assert safety invariants hold (esp. "revoked grant halts scan in
  seconds"). Run in staging on a schedule.
- **Load:** k6/Gatling on the API; a scan-generator that drives N concurrent scans to
  validate §15 density and the rate-cap under contention.
- **Performance regression:** benchmark crawl time & scan throughput per release;
  gate on regression thresholds.
- **Detection regression (precision/recall):** the synthetic-target corpus is the
  ground truth; every release reports precision/recall per vuln class and **fails on
  recall regression** for any [A] class. This is the product's core quality metric.

### 12.6 Synthetic-target corpus
- Curated deliberately-vulnerable apps (OWASP Juice Shop, DVWA-class, plus **purpose-
  built modern SPAs** covering React Server Actions, GraphQL, WebSockets, auth-matrix
  fixtures with known-owned objects for IDOR ground truth). Versioned in `test/`.
  This is a first-class engineering asset, staffed and maintained.

---

## 13. DevOps / Delivery

### 13.1 CI/CD
- **GitHub Actions**, monorepo-aware: path-filtered pipelines build/test only affected
  services (+ downstream contract consumers). Stages: lint → typecheck → unit →
  integration → build+sign image → e2e on synthetic targets → deploy.
- Images built reproducibly, **signed with cosign**, SBOM (Syft) attached,
  vuln-scanned (Grype/Trivy) — **admission controller rejects unsigned/HIGH-CVE images.**

### 13.2 Release trains & flags
- **Weekly release train** per service (services release independently; the train is a
  cadence, not a coupling). Hotfix path out-of-train for Sev-1/security.
- **Feature flags** (OpenFeature) gate every risky capability — especially each
  intrusive scan class ships **off**, enabled per-tenant after validation. Flags are
  the primary de-risking tool; a bad plugin is disabled without a deploy.

### 13.3 Canary / blue-green / rollback
- **Progressive delivery** (Argo Rollouts): canary for stateless services (1%→10%→
  100% gated on SLO burn + error rate). Because a bad *scanner* has real-world blast
  radius, canary also watches **outbound-safety metrics** (unexpected targets, rate
  breaches), not just internal health.
- Blue/green for the gateway and stateful-adjacent migrations.
- **Rollback:** roll-forward preferred; image rollback is one click; DB always
  expand→contract so a service rollback never faces an incompatible schema.
- **GitOps** (Argo CD): the cluster state is the repo; deploys are PRs.

---

## 14. Security Program

We are a security company; internal security is table stakes and a sales asset.

### 14.1 Trust boundaries (per service)
- **Internet-facing:** gateway, oast-collaborator (own hardened surface), console.
- **Tenant-data plane:** all services (RLS-scoped; no service sees cross-tenant data).
- **Untrusted-execution zone:** crawler + Tier-3 plugin containers (run hostile code →
  gVisor + egress-lock + ephemeral).
- **Tier-0 safety zone:** grant-svc + rate-bucket — change-controlled, dual-reviewed,
  isolated blast radius.

### 14.2 Secrets management
- Central secrets manager (Vault / cloud KMS); **no secret in env files or images.**
- Target session credentials & plugin creds encrypted at rest with **AEGIS KEK
  envelope crypto**; short-lived; never logged (CI log-scrub check).
- Signing keys (grants, plugin registry, agent OTA) in KMS/HSM; rotation automated.

### 14.3 Encryption
- TLS 1.2+/1.3 everywhere in transit; mTLS for service-to-service (SPIFFE/SPIRE
  identities) and for on-prem scanner agents (AEGIS PKI). At-rest encryption on all
  stores + object storage.

### 14.4 Audit logging
- Every grant, scan launch, verdict, config change, report access → AEGIS
  **hash-chained tamper-evident audit**. Exportable for SOC2/PCI evidence. This is
  both a control and a product feature.

### 14.5 Zero-trust
- No implicit trust between services; every internal call authenticated (mTLS
  identity) + authorized (service-account scope). The proxy-trusted mTLS header pattern
  from AEGIS agents applies to on-prem scanners.

### 14.6 RBAC
- AEGIS four-tier RBAC end-to-end; grant creation and intrusive scans gated to `admin`+
  and MFA. Break-glass access is logged, time-boxed, and alerts security.

### 14.7 The unique risk: we can attack the internet
- **Safety invariants (from §13 threat model) are enforced in code and tested in
  chaos:** no outbound request without a live matching grant; aggregate RPS ≤ grant
  cap across all workers; intrusive classes default-off; revoked grant halts scans in
  seconds; every action audited. Violation = Sev-1 with legal/customer-comms path.
- Egress NetworkPolicies pin every outbound-capable pod to in-grant scope. SSRF-into-
  our-own-infra is a modeled threat (workers can't reach the control plane's internals).

### 14.8 Supply-chain security
- All deps pinned by digest, SBOM-tracked, `osv-scanner`/`govulncheck`/`pip-audit` in
  CI. Wrapped OSS tools vendored in signed base images. Cosign-signed releases,
  provenance (SLSA-aligned) attestations. Dependency updates via bot + review, never
  auto-merged for anything in the outbound path.
- **Internal pentest + external audit** before GA and annually; a public bug-bounty at
  scale (dogfood our own category).

---

## 15. Performance Envelope

Order-of-magnitude estimates with stated assumptions — to be replaced by measured
numbers from load tests (§12.5). **These are planning figures, not guarantees.**

### 15.1 Assumptions
- "Standard scan" = mid-size SPA, ~500 endpoints, active-safe classes, authenticated,
  RPS cap 10/host. Chromium heavy-crawl ≈ 0.5–1 vCPU + 400–700 MB RAM sustained.

### 15.2 Estimates
| Dimension | Estimate | Basis |
|---|---|---|
| **Standard scan wall-time** | ~20–60 min | rate-cap-bound (10 RPS × ~500 endpoints × N probes), not CPU-bound |
| **Browser density** | ~8–16 heavy crawls / (16 vCPU,64 GB) node | RAM-bound; light contexts far denser |
| **Worker density (scan-worker)** | hundreds of probe-tasks/sec/node | IO-bound; capped by target RPS, not us |
| **Queue throughput** | 10k+ msg/sec (Redis Streams), 100k+ (JetStream) | transport benchmarks |
| **Findings volume** | ~10²–10³ raw / scan → ~10¹–10² issues post-dedup | dedup ratio from correlation |
| **Storage growth** | ~50–500 MB evidence / scan (HAR+screens) | bounded capture; video only on failure |
| **API latency** | p95 < 300 ms (reads), async for scans | reads are PG/cache-bound |
| **Expected concurrency** | 100s of concurrent scans / region at Wave 3 | worker fleet horizontal scale |

**The binding constraint is almost always the per-target rate cap, not our compute** —
by design (safety). This means throughput scales by *number of targets*, and our cost
scales with *browser-hours* and *AI tokens*, not raw request volume.

---

## 16. Cost Model

### 16.1 Biggest drivers (ranked)
1. **Browser fleet compute** — the dominant cost. Chromium is RAM-hungry and every
   modern-app scan needs it. ~single-biggest line.
2. **AI/LLM tokens** — triage + report generation across many findings; unbounded if
   uncontrolled.
3. **Egress bandwidth** — crawling + evidence upload.
4. **Storage** — HAR/screenshots/traces accumulate fast.
5. **Managed data services** (PG, Redis, later OpenSearch/graph) — steadier.
6. **Observability** (metrics/traces/logs cardinality) — a silent creeper.

### 16.2 Optimizations (mapped to drivers)
- **Browser:** context reuse (not process), bounded render waits, **structural dedup
  before render** (skip 10k sibling states), bin-pack + scale-to-low, spot/preemptible
  nodes for the crawl pool (crashes are already handled). *Biggest single lever.*
- **AI:** small-model routing for triage, cache on `(prompt_version,input_hash)` and
  surface hash, hard per-scan token budget, batch triage. Report-prose (large model)
  only once per scan.
- **Bandwidth/storage:** cap response-body capture size, sample video only on failure,
  aggressive lifecycle to cold storage, dedup identical evidence blobs by content hash.
- **Observability:** metric cardinality budget (no per-`target_id` labels on high-freq
  metrics), trace sampling (100% on failures, sampled on success), log retention tiers.
- **Data:** partition + archive; read replicas only when read-bound; defer
  OpenSearch/graph until triggers (each is real monthly spend).

### 16.3 Unit economics discipline
Track **cost-per-scan** as a first-class metric (browser-seconds + AI-tokens +
bytes). Price/package around it. A scan whose cost exceeds its plan allowance is
throttled by the orchestrator budget — no runaway bills, ours or the customer's.

---

## 17. Documentation Roadmap

Docs are versioned in-repo, reviewed with the code, and **CI-checked for staleness**
(a doc referencing a removed flag/endpoint fails CI).

| Doc | Audience | When | Owner |
|---|---|---|---|
| **Onboarding / "clone→running in 30 min"** | new engineers | Wave 0 | DevEx |
| **Developer guide** (local dev, contracts, codegen, plugin authoring) | engineers | Wave 0–1 | DevEx + owners |
| **Architecture docs + ADRs** | all eng | continuous (ADR per decision) | Architects |
| **Public API docs** (from OpenAPI) + SDK guides | customers/integrators | Wave 1 | API/Console |
| **Operations guide** (deploy, scale, config, DR) | SRE/customers (self-host) | Wave 2 | SRE |
| **Runbooks** (per alert, per Sev scenario) | on-call | with each service | owning team |
| **Troubleshooting** ("scan found nothing," "crawl hung," "FP reported") | support/customers | Wave 2 | Support+eng |
| **Security & compliance pack** (trust boundaries, SOC2/PCI mappings) | customers/auditors | Wave 3–4 | Security |
| **Plugin SDK docs + marketplace guide** | external authors | Wave 3 | Plugin team |

**Rule:** a service is not "done" (§19 DoD) without its runbook and dev-guide section.

---

## 18. Engineering Organization

### 18.1 Team topology (Team-Topologies-aligned)

Start ~15–20 engineers (5 teams); grow to ~50 (9 teams). Stream-aligned teams own
vertical slices; platform/enabling teams reduce their cognitive load.

| Team | Owns (services) | Type |
|---|---|---|
| **Control Plane** | gateway, orchestrator, scheduler, **grant-svc** [TIER-0], API/SDK | stream-aligned |
| **Scanning / Data Plane** | scan-worker, verify, oast-collaborator, plugin-sdk, static-analyzer, authmatrix | stream-aligned |
| **Browser / Crawler** | crawler, evidence, api-discovery | stream-aligned (specialist) |
| **Intelligence** | correlation, risk-scorer, ai-svc, knowledge graph | stream-aligned |
| **Console / DX** | console, cli, SDKs, dev tooling, docs infra | stream-aligned + enabling |
| **Platform** (grows out of Control Plane ~M4) | contracts, libpy/libgo, queue/event infra, k8s, IaC | platform |
| **SRE** (forms ~M3) | prod reliability, observability, on-call framework, incident cmd | platform |
| **Security** (forms ~M3) | internal sec, supply chain, threat model, audits, bug bounty | enabling |
| **Notifier/Integrations** (absorbed by Console/DX early, spun out ~M6) | notifier, ticketing, SIEM | stream-aligned |

### 18.2 Ownership evolution
- **Early (M0–M3):** fewer, broader teams; Control Plane holds grant-svc *and*
  platform concerns; SRE/Security are virtual (embedded champions).
- **Mid (M4–M6):** Platform and SRE spin out as load justifies; each service has a
  named owning team + on-call.
- **Late (M7+):** specialist teams (Plugin ecosystem, Enterprise/on-prem) form as the
  marketplace and hybrid deployment mature.

### 18.3 Architecture governance
- **ADR process:** every significant decision is a numbered, immutable ADR; reversal =
  a new ADR superseding the old. Lightweight, PR-based, 48-hour comment window.
- **Architecture Review Board** (rotating: architect + 2 senior ICs + security):
  reviews changes that cross service boundaries, touch Tier-0, add a datastore, or add
  a language. Its default posture is the §1 principle — *reject new operational surface
  absent a triggered need.*
- **Contract changes** require the ARB + affected owners; the monorepo makes the blast
  radius visible in one PR.
- **Tech-radar** reviewed quarterly (adopt/trial/hold/deprecate).

---

## 19. Implementation Plan

Hierarchy: **Milestone → Release → Epic → Task.** Milestones map to the roadmap
(v0–v4). Below: the full milestone/epic backlog, with **fully-worked task examples**
proving the template. The template is mandatory for *every* task; I show it in depth
for representative epics so the org replicates it, rather than enumerating ~600 tasks.

### 19.0 Global Definition of Done (applies to every task)
A task is Done only when: code merged behind green CI; unit + relevant integration
tests added and passing; **Tier-0 tasks also mutation-tested**; observability (metrics/
logs/trace spans) added; feature-flagged if risky; docs/runbook updated; CODEOWNERS +
required reviews approved; no new HIGH-CVE deps; deployed to staging and verified
against synthetic targets. "Done" ≠ "code written."

### 19.1 Milestone map (24 months)

| Milestone | Months | Roadmap | Theme | Exit criteria |
|---|---|---|---|---|
| **M0 Foundations** | 0–2 | — | Repo, contracts, spine, grant-svc, gateway, CI | Grant issued→verified; gateway auths via AEGIS; CI/CD green; one synthetic target in CI |
| **M1 Passive slice (v0)** | 2–5 | v0 | Recon + passive + evidence + reporting + console | End-to-end grant→recon→passive findings→report; ASM usable; **first customer value** |
| **M2 Crawler de-risk + spike** | 4–6 | v1 prep | Prove SPA state-graph crawl (parallel w/ M1) | Crawl 3 representative SPAs; coverage metric emitted; go/no-go on approach |
| **M3 DAST core (v1)** | 6–11 | v1 | Crawler + api-disc + OAST + scan-worker + verify | Confirmed reflected-XSS/SSRF/SQLi with proof on synthetic targets; FP < 2% on corpus |
| **M4 Intelligence (v2)** | 11–15 | v2 | Correlation + risk + ai-svc + continuous + integrations | Dedup + DAST⨯SCA correlation; AI triage passes eval gate; diff-aware rescans; Jira/SIEM |
| **M5 AuthZ & coverage (v3a)** | 15–18 | v3 | Auth-matrix + IDOR/BFLA + gap-fill classes (deser, traversal, WS) | IDOR confirmed via identity-diff on fixtures; 4 gap classes shipped behind flags |
| **M6 Intrusive & plugins (v3b)** | 18–21 | v3 | Intrusive classes (flagged), Plugin SDK T1→T2, marketplace beta | Intrusive classes safe under chaos tests; external author ships a T1 plugin |
| **M7 Enterprise scale (v4)** | 21–24 | v4 | Hybrid on-prem agents, HA/DR, compliance packs, multi-region | On-prem scanner enrolls via AEGIS PKI; DR drill passes RTO/RPO; SOC2 evidence export |

### 19.2 Worked epic + tasks (template proof)

#### Epic M0-E3: Authorization-Grant Service [TIER-0]
*Release: M0-R2. Owner: Control Plane. Why now: nothing may scan before authorization
exists; it carries the platform's core safety invariant.*

**Task M0-E3-T1 — Grant data model + signed-grant issuance**
- **Dependencies:** contracts (grant schema), pyspine (RBAC, audit, KEK/signing).
- **Complexity:** M (≈3–5 dev-days).
- **Acceptance criteria:** `POST /api/v3/grants` (admin+, MFA) persists a grant with
  scope/classes/rate/validity; grant is signed (detached sig over canonical form);
  creation writes a tamper-evident audit entry; RLS scopes grants to the org.
- **Testing:** unit (schema validation, signing, RBAC gate) at 100% branch + mutation;
  integration (PG + pyspine) for issue→read; negative tests (non-admin denied, expired
  window rejected).
- **Docs:** API doc for grant endpoints; ADR "grant signing scheme."
- **DoD:** global DoD + mutation score ≥ threshold + security review sign-off (Tier-0).

**Task M0-E3-T2 — Grant verification primitive (`assert_in_scope`)**
- **Dependencies:** T1.
- **Complexity:** M.
- **Acceptance criteria:** a library callable by every worker that, given
  `(grant, target_host, path, test_class)`, returns allow/deny; validates signature,
  time window, revocation, scope-match (incl. wildcard/CIDR canonicalization), and
  class-allowed; **denies RFC1918 unless explicitly granted**; deterministic + <1 ms.
- **Testing:** exhaustive table-driven tests incl. scope-canonicalization edge cases
  (IDN, trailing dot, IPv6, wildcard boundaries); mutation-tested; fuzz the scope
  matcher.
- **Docs:** developer guide "how workers check authorization"; runbook "grant denied
  unexpectedly."
- **DoD:** global DoD + fuzz corpus committed + security review.

**Task M0-E3-T3 — Grant revocation propagation (halt-in-seconds)**
- **Dependencies:** T2, event bus.
- **Complexity:** L (≈1–2 wks).
- **Acceptance criteria:** `POST /grants/{id}/revoke` emits `grant.revoked`; in-flight
  scans in scope stop starting new outbound work within ≤5 s (measured); audited.
- **Testing:** chaos test "revoke mid-scan" asserts halt-time SLO; integration across
  orchestrator + a worker.
- **Docs:** runbook "emergency stop / revoke a grant"; ops guide entry.
- **DoD:** global DoD + chaos test in the suite + Sev-1 runbook linked.

*(Every other epic decomposes with this exact template. The full epic backlog:)*

### 19.3 Epic backlog (by milestone — each expands into template'd tasks)

- **M0:** repo+monorepo tooling & CI; contracts+codegen; pyspine integration; gateway
  authN/authZ; **grant-svc [E3]**; rate-bucket [TIER-0]; queue/event client; single-node
  compose; first synthetic target in CI.
- **M1:** orchestrator (PG saga); recon-worker (subfinder/httpx/dnsx/naabu wrap);
  tech-fingerprint; passive checks (headers/TLS/cookies/CORS/secrets/SCA); evidence
  service + object store; minimal reporting (+SARIF); minimal console; findings/issues
  model + proof schema.
- **M2:** crawler spike; state-graph model; CDP interception; **coverage metric**;
  go/no-go ADR.
- **M3:** crawler productionization (gVisor, pools, updates); api-discovery
  (OpenAPI/GraphQL/param-mine); oast-collaborator; scan-worker + plugin host (Nuclei
  backend); active-safe classes (XSS/SQLi/SSRF/SSTI/cmd/XXE/open-redirect/CORS/JWT);
  verify + independent re-test; FP-control (baseline/soft-404, re-verify).
- **M4:** correlation (dedup, DAST⨯SAST⨯SCA, chains); risk-scorer (CVSS+exploit+KEV+
  business ctx); ai-svc (planner+analyst, RAG, eval gate, routing, caching); continuous/
  diff scanning; scheduler; notifier (Jira/Slack/SIEM/webhook); findings→AEGIS cases.
- **M5:** session/identity manager; authmatrix (IDOR/BFLA via identity-diff, fixtures);
  gap-fill classes (deserialization, path-traversal, WebSocket, clickjacking);
  server-action + gRPC-Web/tRPC discovery; "not-assessed" reporting section.
- **M6:** intrusive classes (time-based SQLi, smuggling, cache-poisoning — flagged,
  chaos-gated); plugin SDK T1→T2 (WASM ABI + validator + capability sandbox); signed
  registry + marketplace beta; T3 worker-plugin contract.
- **M7:** on-prem scanner agents (AEGIS PKI enrollment, pull-tunnel); multi-region +
  data residency; HA/DR (game-days); KEDA autoscale + NATS JetStream adoption (if
  triggered); OpenSearch/graph adoption (if triggered); compliance packs (ASVS/PCI/
  SOC2); GA hardening, external audit, bug bounty.

### 19.4 Parallelization & critical path
- **Critical path:** contracts → grant-svc → orchestrator → **crawler** → scan/verify →
  correlation. The crawler (M2/M3) is the schedule risk; the M2 spike de-risks it early
  and runs *parallel* to M1.
- **Always-parallel, low-coupling:** console/CLI, notifier, static-analyzer, docs,
  synthetic-target corpus, SDK generation — staffed to fill gaps without blocking the
  critical path.

---

## 20. Final Review & Simplification

Per the mandate: I reviewed the whole program for weakness, unnecessary complexity,
and simplification — and **changed the build accordingly.** The architecture (v1.0) is
untouched; the *execution* is leaner.

### 20.1 Cuts made in this document (complexity deferred, with triggers)
| v1.0 called for | Program starts with | Trigger to adopt the full thing |
|---|---|---|
| 7 stateful systems | **3** (PG, Redis, object store) | OpenSearch: findings>5M/search p95>500ms · Graph: >3-hop at scale · TSDB: Prom retention insufficient |
| Temporal for sagas | **Postgres-backed saga** in orchestrator | saga step-count/visibility outgrows PG (~M4+) |
| NATS JetStream Day 1 | **Redis Streams** | multi-consumer replay/fan-out needs exceed Redis (~M4) |
| Neo4j knowledge graph | **PG tables + recursive CTEs** | attack-path traversal cost (~M5+) |
| KEDA + gVisor + microVM Day 1 | gVisor for crawler only; **HPA** elsewhere; KEDA later | multi-tenant SaaS burst load (~M4/M7) |
| Bazel | make + language-native | CI > 20 min incremental |
| 4th language temptation | **3 languages, hard cap** | — (never, without ARB) |

Net effect: an M0–M3 team runs **3 datastores, 3 languages, HPA, GitHub Actions, and
Postgres sagas** — a surface a 15-person org can actually operate — while every
deferred system has a written trigger and a rebuildable-projection design so adoption
is additive, never a rewrite.

### 20.2 Weaknesses found and mitigations added
1. **Crawler is the single biggest schedule + technical risk.** → M2 spike *before*
   committing M3; go/no-go ADR; coverage metric so we can *measure* whether it works.
2. **"No findings" ambiguity** (a scanner's worst silent failure). → coverage % and a
   "not-assessed" report section are **acceptance criteria**, not nice-to-haves.
3. **Tier-0 safety could rot as the codebase grows.** → carved out as a named zone with
   100% branch + mutation coverage, dual review, chaos-tested revocation, zero error
   budget, and a Sev-1 legal/comms path. Treated like payments code.
4. **AI cost + hallucination are unbounded by default.** → hard per-scan token budget,
   eval-gated releases, proof-tier confidence ceilings, cache levers.
5. **Browser fleet cost dominates.** → structural-dedup-before-render + context reuse +
   spot nodes are called out as the top cost levers with owners.
6. **Org over-fragmentation early.** → start 5 broad teams; spin out Platform/SRE/
   Security only when load triggers, not on an org chart.

### 20.3 Unnecessary complexity explicitly rejected
- Per-service repos (version-skew hell for coupled contracts) — rejected for monorepo.
- A bespoke workflow engine — rejected; PG saga now, Temporal only if measured need.
- Microservice sprawl beyond the frozen set — the ARB rejects new services that could
  be a module; several "services" (notifier, static-analyzer) start as modules and
  spin out only when ownership/scale justifies.

### 20.4 Residual risks accepted (eyes open)
- Postgres-as-graph will hit a wall at large-tenant attack-path scale — accepted; the
  projection design makes the Neo4j move additive when the trigger fires.
- Redis Streams lacks JetStream's replay ergonomics — accepted for M0–M3; replay is
  achieved via evidence-tape re-runs until JetStream lands.
- Polyglot (Go+Py) raises the shared-tooling bar — accepted; justified by OSS-tool
  reality and hot-path performance; capped at 3 languages by governance.

### 20.5 Stopping condition
Further simplification would start removing *capability* (cutting scan classes, dropping
multi-tenancy, abandoning the coverage metric) rather than *operational cost* — which
would violate the frozen architecture and the honesty bar. The program is at the point
where it is as lean as it can be **without becoming a lesser product.** That is the
stopping condition.

---

*This is an execution program, not a redesign. The v1.0 architecture stands; this
document says who builds what, in what order, to what quality bar, at what cost, run by
which teams — with complexity sequenced in by measured need. No implementation code, by
design.*

# AEGIS Horizon — Autonomous Web Application Security Assessment Platform

**Design document — architecture & research only. No implementation code.**

> **Authorized use only.** Horizon is a Dynamic Application Security Testing (DAST),
> attack-surface-management (ASM), and recon-automation platform for **authorized**
> engagements: internal red teaming, contracted penetration tests, and scoped bug
> bounty programs. Every scan is gated behind a signed **Authorization Grant** (see
> §16 Security Model). It is not a mass-exploitation tool: there is no untargeted
> internet-wide scanning, no worm/self-propagation, and destructive test classes are
> opt-in and human-gated.

Codename **Horizon**. It is the *offensive/assessment tier* of the existing AEGIS
platform. Where AEGIS Enterprise is **passive** (it ingests logs and detects attacks
against your own assets), Horizon is **active** (it discovers, crawls, and probes
authorized targets to find vulnerabilities before an attacker does). Horizon reuses
AEGIS Enterprise's spine — organizations, RBAC, RS256/JWKS auth, agent PKI, case
management, tamper-evident audit, SIEM forwarding — and adds a distributed scanning
engine on top.

---

## Table of Contents

1. [Research Report](#1-research-report)
2. [Competitive Analysis](#2-competitive-analysis)
3. [Gap Analysis](#3-gap-analysis)
4. [Recommended Architecture](#4-recommended-architecture)
5. [Microservice Architecture](#5-microservice-architecture)
6. [Database Schema](#6-database-schema)
7. [Event Pipeline](#7-event-pipeline)
8. [Distributed Scanning Architecture](#8-distributed-scanning-architecture)
9. [Browser Automation Architecture](#9-browser-automation-architecture)
10. [Plugin SDK Architecture](#10-plugin-sdk-architecture)
11. [API Specification](#11-api-specification)
12. [Deployment Architecture](#12-deployment-architecture)
13. [Threat Model](#13-threat-model)
14. [Scaling Strategy](#14-scaling-strategy)
15. [Performance Optimization](#15-performance-optimization)
16. [Security Model](#16-security-model)
17. [Product Roadmap](#17-product-roadmap)
18. [Implementation Phases](#18-implementation-phases-value-vs-risk)

---

## 1. Research Report

### 1.1 The three eras of web-app scanning

**Era 1 — Signature crawlers (2000s):** Nikto, Wapiti, early Acunetix. Fetch HTML,
regex for known-bad paths and reflected parameters. Blind to anything JavaScript
renders. Effectively obsolete against modern apps.

**Era 2 — Proxy-driven DAST (2010s):** Burp Suite, OWASP ZAP. A human (or a spider)
drives traffic through an intercepting proxy; the tool replays and mutates requests.
Excellent signal, but coverage is bounded by what actually got proxied, and it
struggles to autonomously reach deep application state.

**Era 3 — Headless-browser + template engines (2020s→):** Nuclei + Katana,
Detectify, StackHawk, Burp's browser-powered scanning. A real Chromium renders the
app, the crawler follows the *rendered* DOM and intercepted network traffic, and a
declarative template engine expresses thousands of checks as data, not code. This is
the era Horizon targets — and pushes past it with an AI planning/correlation layer.

### 1.2 The core problem modern apps create

A 2015 scanner could `GET /` and see the whole site. A 2025 React/Next.js app ships a
near-empty `<div id="root">` and a bundle; the *real* application — routes, forms,
API calls, auth flows — only exists after hydration and user interaction. This breaks
every assumption of Era-1/2 tooling:

| Modern technique | Why it breaks naïve scanners | Horizon's required adaptation |
|---|---|---|
| **CSR / hydration** (React, Vue, Svelte) | No links in initial HTML | Render in real Chromium; crawl the post-hydration DOM |
| **SSR / streaming / RSC** (Next.js App Router, Remix) | Partial HTML, `flight` payloads, `<script>self.__next_f...>` chunks | Parse streamed RSC payloads; diff pre/post-hydration |
| **Client-side routing** (history API) | Navigation fires no HTTP request | Drive the router: click, watch `pushState`, snapshot each virtual route |
| **API-first / SPA + JSON** | Endpoints never appear as `<a href>` | Intercept `fetch`/XHR at CDP layer; mine JS bundles for URL/route strings |
| **GraphQL** | One endpoint, schema hidden | Introspection probe → per-field/mutation fuzzing; persisted-query awareness |
| **WebSocket / gRPC-Web / tRPC** | Not request/response | Frame-level interception; tRPC batch-link decoding |
| **Lazy loading / code splitting** | Routes load on demand | Trigger dynamic imports via interaction; watch for new chunks |
| **Service Workers / IndexedDB** | Offline caches, background sync | Inspect SW registration + Cache Storage + IDB via CDP |
| **WASM** | Logic compiled away from JS | Detect + fingerprint; flag as manual-review (out of automated scope) |
| **Passkeys / WebAuthn / MFA** | Can't script the authenticator | Virtual authenticator via CDP `WebAuthn` domain; else session-import |

### 1.3 Detection methodology taxonomy

Four families, each with a distinct false-positive/coverage profile:

1. **Passive** — analyze traffic already generated (headers, cookies, CSP, mixed
   content, secrets in JS, outdated libs via SRI/version fingerprint). Zero added
   requests, near-zero FP, but only finds "informational→medium" issues.
2. **Active safe** — send benign probes and reason about *differential* responses
   (reflected-XSS canaries, error-based SQLi markers, open-redirect follow, SSRF
   via out-of-band callback). The workhorse.
3. **Active intrusive** — time-based blind (SQLi `SLEEP`), boolean-blind inference,
   file-write probes, header smuggling. Higher confidence, higher blast radius →
   human-gated, rate-limited, scope-locked.
4. **Out-of-band (OAST)** — plant a payload that, if it fires, causes the *target*
   to call a Horizon-controlled collaborator server (DNS/HTTP/SMTP). The only
   reliable way to detect blind SSRF, blind XXE, blind SQLi exfil, and some RCE.
   This is Burp Collaborator's key insight and is non-negotiable for a serious DAST.

### 1.4 Crawling strategy — the state-explosion problem

Naïve BFS over a SPA explodes: every hover, every filter, every modal is a "state."
The research consensus (and Horizon's design):

- **Model the app as a state graph**, not a URL tree. A node = (normalized URL +
  DOM structural hash + auth context). An edge = an interaction (click/submit/route).
- **Deduplicate by structural similarity**, not exact match — a product page for
  SKU 1 and SKU 2 are the *same template*; crawl one, remember the shape, skip the
  10,000 siblings but record the parameter surface.
- **Prioritize by security value**: forms > state-changing buttons > new API calls >
  navigation > decorative interactions. A budget-bounded frontier (not exhaustive).
- **Combine three discovery channels** and union the results:
  1. Rendered-DOM crawl (Katana-style, headless Chromium).
  2. Passive network interception (every `fetch`/XHR the app itself makes).
  3. Static bundle mining (JS/source-map parsing for routes, endpoints, params) —
     LinkFinder/ParamSpider-style, but AST-based, not regex.

### 1.5 API discovery

The highest-value, most-under-tested surface. Sources Horizon fuses:

- Runtime interception (what the SPA calls).
- **OpenAPI/Swagger** auto-discovery (`/openapi.json`, `/swagger.json`, `/api-docs`,
  Redoc/Swagger-UI detection → import full spec).
- **GraphQL** introspection.
- JS bundle route tables (Next.js `__BUILD_MANIFEST`, React Router route configs).
- **Parameter mining** (Arjun-style): given an endpoint, discover accepted-but-
  undocumented params by differential response analysis.
- Historical URLs (gau/waybackurls) — passive, opt-in, for recon-heavy engagements.

### 1.6 AI usage in the current market (honest assessment)

Most "AI-powered scanner" claims in 2024–25 are marketing veneer over classic
engines. Where LLMs *genuinely* add value today, and where Horizon uses them:

- ✅ **Triage & dedup** — cluster 500 raw findings into 40 real issues.
- ✅ **Explanation & remediation** — turn a raw finding into dev-actionable prose.
- ✅ **Report generation** — executive + developer views from the same evidence.
- ✅ **Crawl planning** — decide *which* interactions are security-interesting
   (semantic understanding of a "Delete account" vs "Toggle dark mode" button).
- ✅ **Payload adaptation** — given a WAF-blocked probe, suggest encodings/mutations.
- ⚠️ **Vuln *confirmation*** — LLMs hallucinate; confirmation must stay
   evidence-based (OAST callback, differential proof), with the LLM only *ranking*
   confidence, never *asserting* a vuln it can't prove.
- ❌ **Autonomous exploitation** — deliberately out of scope; too risky, too legally
   fraught, and not what authorized assessment needs.

### 1.7 False-positive reduction — the make-or-break metric

Buyers abandon scanners over FP noise faster than over missed bugs. Horizon's
layered FP defense:

1. **Proof-carrying findings** — a finding is only "confirmed" if it carries
   reproducible evidence (OAST hit, reflected canary with unique nonce, differential
   timing with statistical significance). Everything else is "potential" and ranked
   lower.
2. **Re-verification pass** — every candidate is independently re-tested by a
   separate worker before it surfaces.
3. **Baseline/soft-404 learning** — learn the app's "not found" and "error" shapes
   so a check doesn't fire on every 200-that-is-really-an-error.
4. **Cross-finding correlation** — 200 "missing security header" hits collapse to 1
   issue with 200 locations.
5. **Historical suppression** — reuse AEGIS's existing suppression + TP/FP feedback
   loop (`rule_confidence`) so analyst verdicts train future ranking.

---

## 2. Competitive Analysis

Scored on the dimensions the brief calls out. Ratings are the design team's
assessment of publicly documented behavior, not benchmark numbers.

### 2.1 Commercial DAST / ASM

| Product | Architecture | Browser | API disc. | AI | FP control | Strength | Weakness Horizon exploits |
|---|---|---|---|---|---|---|---|
| **Burp Suite Pro** | Desktop, single-node, extensible (BApp/Montoya) | Embedded Chromium ("browser-powered scan") | Good (via proxied traffic) | Minimal (Burp AI early) | Excellent (human-in-loop) | Gold-standard signal, Collaborator OAST | Single-node, not continuous, not multi-tenant, manual-first |
| **Burp Enterprise** | Server + scan agents, CI/CD | Same engine | Same | Minimal | Excellent | Burp engine at scale | Costly; scheduling-centric, weak recon/ASM, limited AI triage |
| **Invicti (Netsparker)** | SaaS + on-prem, DAST+IAST | Chromium | Strong | "Proof-Based Scanning" (deterministic, not LLM) | **Excellent** (proof-based = near-zero FP) | Auto-verification is best-in-class | Closed templates, weak SPA state-modeling, no open plugin ecosystem |
| **Acunetix** | SaaS/on-prem, shares Invicti engine | Chromium (DeepScan) | Good | Deterministic | Very good | Fast, mature | Same closed-ecosystem limits |
| **Detectify** | SaaS, crowdsourced (Crowdsource) payloads | Chromium | Good | Some ML | Good | Payloads sourced from real hackers; great ASM (via Assetnote) | SaaS-only, no on-prem, black-box |
| **Rapid7 InsightAppSec** | Cloud, distributed engines | Chromium | Moderate | Some | Good | Enterprise integration, attack replay | Heavyweight, slower innovation |
| **StackHawk** | Dev-first, CI-native, ZAP-based | Chromium/ZAP | OpenAPI/GraphQL-native | Some | Good | Best CI/CD & API-spec workflow | Depth ceiling of ZAP engine |
| **Qualys / Tenable WAS** | Cloud VM-suite bolt-on | Limited | Weak | Minimal | Moderate | Fits existing VM programs | DAST is a checkbox, not a focus; weak on SPAs |

### 2.2 SAST / SCA / posture (adjacent — for correlation, not head-to-head)

| Product | Category | Relevance to Horizon |
|---|---|---|
| **Checkmarx, Veracode, Snyk, GitHub Adv. Security, GitLab, Semgrep, CodeQL** | SAST/SCA | Horizon *ingests* their findings to correlate "reachable in DAST" ⨯ "vulnerable in SAST" — a killer signal neither side has alone |
| **Contrast Security** | IAST | Runtime agent inside the app; Horizon can pair its DAST traffic with an optional IAST agent for confirmation |
| **Wiz, Orca, Defender for Cloud, AWS Inspector** | CNAPP/cloud posture | Provide the asset inventory Horizon scans; consume Horizon's findings for unified risk |
| **Censys, Shodan, Assetnote, Netlas** | Internet intel / ASM | External attack-surface seed data for the recon phase |
| **Horizon3.ai (NodeZero), Pentera** | Autonomous pentest / BAS | The closest *philosophical* competitors — autonomous, chained, safe-by-design. Network-centric; Horizon is web-app-centric and complements them |

### 2.3 Open-source ecosystem (Horizon embeds/wraps many of these)

| Tool | Role | Horizon's use |
|---|---|---|
| **Nuclei** + templates | Template-driven check engine | **Adopt** as one execution backend; Horizon's plugin SDK is a superset |
| **Katana** | Headless crawler | Reference model for the browser-crawl worker |
| **httpx / naabu / dnsx / uncover / alterx** | Probing/recon primitives | Wrapped as recon-worker tools |
| **subfinder / amass / gau / waybackurls** | Subdomain + historical URL disc. | Recon-worker asset discovery |
| **ffuf / feroxbuster / dirsearch / gobuster** | Content/dir brute | Content-discovery worker (rate-gated) |
| **sqlmap / Dalfox / XSStrike / Commix** | Class-specific exploiters | Specialist workers behind the OAST + proof layer |
| **Arjun / ParamSpider** | Parameter mining | API-discovery worker |
| **LinkFinder / SecretFinder** | JS endpoint/secret extraction | Static-analysis worker (AST-based reimplementation) |
| **TruffleHog / Gitleaks / Semgrep** | Secret + code scanning | SCA/secret worker for exposed source & JS |
| **OWASP ZAP** | Full DAST | Alternative execution backend; Horizon can orchestrate ZAP as a worker |
| **Aquatone / gowitness** | Screenshotting | Evidence-capture worker |

**Strategic stance:** Horizon does not reinvent Nuclei or sqlmap. It is the
**orchestration, state-modeling, correlation, and AI layer** that turns a toolbox of
best-in-class primitives into an autonomous, multi-tenant, continuous platform — with
a first-class plugin SDK so those tools plug in as data, not forks.

---

## 3. Gap Analysis — what nobody does well (Horizon's wedge)

1. **Deep SPA state-modeling.** Most scanners crawl rendered DOM but don't *model
   application state* as a dedup'd graph, so they either miss deep states or drown in
   duplicates. **Gap → Horizon's state-graph crawler (§9).**
2. **DAST⨯SAST⨯SCA correlation.** SAST says "line 42 is injectable"; DAST says
   "this endpoint is reachable." Neither says "reachable *and* injectable *and*
   unauthenticated." **Gap → Horizon's correlation engine + knowledge graph (§5.8).**
3. **Open, safe plugin SDK with a capability sandbox.** Nuclei templates are great
   but limited to request/response DSL; Burp extensions are powerful but unsandboxed
   and single-node. **Gap → Horizon's typed, capability-scoped plugin SDK (§10).**
4. **AI that plans the crawl and triages proof-carrying findings** — not AI that
   asserts vulns. **Gap → §5.7 AI Analyst + planner.**
5. **Continuous, diff-aware scanning.** Scan once = a point-in-time snapshot. Real
   value is "what changed since last scan, and did the change introduce risk?"
   **Gap → Horizon's continuous scheduler + finding-diff (§14.4).**
6. **Business-logic & auth-matrix testing.** The OWASP categories scanners *can't*
   automate (BOLA/IDOR, broken function-level auth, workflow bypass). **Gap →
   Horizon's multi-identity replay engine (§5.6) that runs the same request under N
   authenticated roles and diffs authorization.**
7. **True multi-tenancy + enterprise governance in an open-core tool.** **Gap →
   inherited free from AEGIS Enterprise (orgs, RLS, RBAC, audit, PKI).**

---

## 4. Recommended Architecture

### 4.1 Principles

- **Event-driven, not request/response.** A scan is a long-running saga; every stage
  emits events other stages subscribe to. Enables horizontal scale, replay, and
  observability.
- **Stateless workers, stateful orchestrator.** Workers pull work, do one thing,
  emit results, hold no cross-task state. Orchestrator owns the saga state machine.
- **Proof-carrying findings.** Nothing is "confirmed" without reproducible evidence.
- **Capability-scoped everything.** Every worker, plugin, and scan runs with the
  minimum authority (network scope, rate budget, test-class allowlist) it needs.
- **Safe-by-default.** Intrusive/destructive checks are opt-in, gated by an
  Authorization Grant, and rate-limited per target.
- **Reuse the AEGIS spine.** Auth, orgs, RBAC, audit, agent PKI, cases, SIEM already
  exist and are production-shaped — Horizon consumes them, not clones them.

### 4.2 Logical layers

```
┌──────────────────────────────────────────────────────────────────────┐
│  PRESENTATION      Web console · CLI (horizon-cli) · CI plugin · API   │
├──────────────────────────────────────────────────────────────────────┤
│  CONTROL PLANE     API Gateway · AuthZ (AEGIS) · Scan Orchestrator     │
│                    (saga SM) · Scheduler · Authorization-Grant service │
├──────────────────────────────────────────────────────────────────────┤
│  MESSAGING         Event bus (NATS JetStream / Kafka) · Work queues    │
│                    (per-capability, priority) · OAST collaborator      │
├──────────────────────────────────────────────────────────────────────┤
│  DATA PLANE        Recon · Crawl(Browser) · Static-Analysis · API-disc │
│  (worker fleets)   · Active-Scan(per class) · Auth-Matrix · Verify     │
│                    · Evidence-Capture · (each independently scaled)    │
├──────────────────────────────────────────────────────────────────────┤
│  INTELLIGENCE      AI Planner · AI Analyst (triage/dedup/report)       │
│                    · Correlation Engine · Risk Scorer                  │
├──────────────────────────────────────────────────────────────────────┤
│  KNOWLEDGE         Knowledge Graph (assets⨯endpoints⨯findings⨯identity)│
├──────────────────────────────────────────────────────────────────────┤
│  STORAGE           Postgres (RLS) · Object store (evidence/HAR/screens)│
│                    · Redis (cache/rate/locks) · OpenSearch (findings)  │
│                    · Graph store (Neo4j / PG-AGE) · Time-series (Vic.) │
├──────────────────────────────────────────────────────────────────────┤
│  OBSERVABILITY     OpenTelemetry traces · Prometheus · Loki · Grafana  │
└──────────────────────────────────────────────────────────────────────┘
```

### 4.3 Data flow (one scan, end to end)

```
Authorization Grant verified
        │
        ▼
 Scan created ──emit scan.created──▶ Orchestrator builds saga
        │
        ▼
 [Recon]  asset discovery ──emit asset.discovered──▶ Knowledge Graph
        │                                              │
        ▼                                              ▼
 [Crawl] browser state-graph ──emit endpoint.found──▶ dedup + KG
        │        ▲  (static bundle mining + net intercept feed in)
        ▼        │
 [API-disc] OpenAPI/GraphQL/param-mine ──emit surface.enumerated──▶ KG
        │
        ▼
 AI Planner scores the surface ──emit scan.plan.ready──▶ test scheduling
        │
        ▼
 [Active-Scan fleets] per vuln class, pull targets ──emit finding.candidate
        │                                                    │
        ▼                                                    ▼
 [Verify] independent re-test + OAST correlation ──emit finding.confirmed
        │
        ▼
 Correlation Engine (DAST⨯SAST⨯SCA, dedup, chain) ──emit issue.materialized
        │
        ▼
 Risk Scorer + AI Analyst (explain/remediate) ──emit issue.enriched
        │
        ▼
 Case opened (AEGIS cases) · SIEM emit · report artifacts · notify
```

---

## 5. Microservice Architecture

Service boundaries chosen so each scales on its own bottleneck and fails
independently. Sync APIs are gRPC internally, REST/JSON at the edge; everything
cross-service that isn't a query goes over the event bus.

### 5.1 API Gateway / BFF
Edge auth (validates AEGIS RS256 access tokens via JWKS), rate limiting, request
shaping, WebSocket fan-out for live scan progress. Stateless, N replicas behind LB.

### 5.2 Scan Orchestrator (the brain)
Owns the **scan saga** as an explicit state machine (durable, resumable). Consumes
stage-completion events, decides the next stage, enforces budgets (max requests, max
duration, max cost), handles pause/resume/abort, and compensating actions on failure.
Deliberately the *only* stateful control-plane service. Backed by a durable workflow
engine (Temporal is the reference choice; a Postgres-backed saga table is the
minimal-dependency alternative).

### 5.3 Scheduler
Cron + event-triggered scans (on deploy webhook, on new-asset-discovered, on
CVE-published-affecting-a-detected-tech). Owns "continuous monitoring" cadence per
asset and quiet-hours/rate windows. (Reuses AEGIS's scheduler patterns.)

### 5.4 Authorization-Grant Service
Issues and verifies **scope grants**: which hosts/IP ranges/paths an org is allowed
to test, signed and time-boxed, with per-grant test-class and rate caps. Every worker
checks the grant before touching a target. This is the legal/safety keystone (§16).

### 5.5 Worker fleets (data plane — all stateless, all pull-based)

| Fleet | Job | Scales on | Key tools |
|---|---|---|---|
| **Recon** | subdomain/asset/port/tech discovery | target breadth | subfinder, amass, dnsx, naabu, httpx, uncover |
| **Crawler (Browser)** | render + state-graph crawl | # of apps × depth | Chromium + CDP (Playwright driver) |
| **Static-Analysis** | JS bundle/source-map mining, secret scan | JS payload size | AST parser, TruffleHog, Semgrep |
| **API-Discovery** | OpenAPI/GraphQL/param-mine | # endpoints | introspection, Arjun-style differ |
| **Active-Scan (per class)** | XSS, SQLi, SSRF, SSTI, XXE, IDOR, … one fleet each | # of injection points | Nuclei, Dalfox, sqlmap, custom plugins |
| **Auth-Matrix** | replay requests under N identities, diff authz | # endpoints × # roles | session manager + differ |
| **Verify** | independent re-test of candidates | # candidates | proof engine + OAST correlation |
| **Evidence-Capture** | screenshots, HAR, request/response, video | # findings | Chromium, HAR writer |

Splitting Active-Scan per class matters: SQLi time-based checks are slow and serial
per host; XSS canary checks are fast and parallel; SSRF waits on OAST callbacks. Each
has a different concurrency/rate profile and must scale independently.

### 5.6 Session / Identity Manager
Holds authenticated sessions per target per role (cookie jars, bearer tokens,
recorded login flows, WebAuthn virtual-authenticator configs). Re-authenticates on
expiry, detects logout, and feeds the Auth-Matrix fleet. Secrets encrypted at rest
via AEGIS's KEK envelope crypto.

### 5.7 AI Planner + AI Analyst
- **Planner** (pre-scan & mid-scan): scores the discovered surface for
  security-interest, chooses which interactions to drive and which checks to
  prioritize under budget, and adapts payloads when probes are WAF-blocked.
- **Analyst** (post-finding): dedup/cluster, explain, remediate, risk-narrate, and
  generate exec + developer reports. Provider-agnostic gateway (reuses AEGIS
  `copilot.py` design: Anthropic/OpenAI/Azure via env, fail-closed if unconfigured).
  **Guardrail:** the Analyst never *promotes* a finding's confirmed-status; it only
  ranks and explains evidence the Verify fleet already produced.

### 5.8 Correlation Engine
Consumes `finding.confirmed` events and the Knowledge Graph. Responsibilities:
dedup across locations, **cross-source correlation** (DAST hit ⨯ SAST reachability ⨯
SCA CVE ⨯ exposed secret), **attack-chain assembly** (open-redirect → OAuth token
theft; SSRF → cloud metadata → cred), and issue materialization.

### 5.9 Risk Scorer
Combines CVSS base, an **exploitability signal** (proof strength, auth required,
preconditions), **business context** (asset criticality tag, data sensitivity,
internet-exposure), and **environmental** factors into a single prioritized score.
Emits `issue.enriched`.

### 5.10 Reporting Service
Renders exec summary, developer detail, compliance mappings (OWASP Top 10, ASVS,
PCI-DSS, SOC 2 evidence), and diff-since-last-scan. Outputs PDF/HTML/SARIF/JSON.
SARIF is first-class so findings flow into GitHub/GitLab code scanning.

### 5.11 OAST Collaborator Service
Horizon-controlled authoritative DNS + HTTP(S)/SMTP listener with per-scan unique
subdomains. Correlates inbound callbacks to the exact payload/injection point that
triggered them. The backbone of all blind-vuln detection. Multi-tenant isolation is
critical (§13).

### 5.12 Notification / Integration Service
Jira/Linear/ServiceNow ticketing, Slack/Teams/Telegram alerts, SIEM forwarding
(reuses AEGIS `siem.emit`), webhook out. Findings become AEGIS **cases** so the SOC
workflow (SLA, escalation, playbooks) applies unchanged.

---

## 6. Database Schema

Multi-store by design; Postgres is the system of record (with RLS via AEGIS tenancy).
Sketch DDL — illustrative, not migration-final. All tenant tables carry `org_id` and
inherit AEGIS's row-level-security policy.

### 6.1 Postgres — control plane & findings

```sql
-- Authorization: the legal keystone. No scan touches a host absent a live grant.
CREATE TABLE auth_grants (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id          uuid NOT NULL REFERENCES organizations(id),
  scope_type      text NOT NULL,          -- 'domain' | 'wildcard' | 'cidr' | 'url'
  scope_value     text NOT NULL,          -- e.g. '*.example.com', '10.0.0.0/24'
  allowed_classes text[] NOT NULL,        -- ['passive','active_safe','active_intrusive']
  max_rps         int  NOT NULL DEFAULT 10,
  not_before      timestamptz NOT NULL,
  not_after       timestamptz NOT NULL,
  signed_by       int  NOT NULL REFERENCES users(id),
  signature       text NOT NULL,          -- detached sig over the grant (non-repudiation)
  revoked_at      timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE targets (                    -- an app/asset in scope
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id        uuid NOT NULL REFERENCES organizations(id),
  name          text NOT NULL,
  base_url      text NOT NULL,
  tech_stack    jsonb NOT NULL DEFAULT '{}',  -- fingerprint: {framework, server, cdn,...}
  criticality   text NOT NULL DEFAULT 'medium',
  data_class    text NOT NULL DEFAULT 'internal', -- pii|phi|pci|internal|public
  created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE scans (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id        uuid NOT NULL REFERENCES organizations(id),
  target_id     uuid NOT NULL REFERENCES targets(id),
  grant_id      uuid NOT NULL REFERENCES auth_grants(id),
  profile       text NOT NULL,            -- 'recon' | 'passive' | 'full' | 'api' | 'continuous'
  state         text NOT NULL DEFAULT 'queued', -- saga state
  budget        jsonb NOT NULL,           -- {max_requests, max_duration_s, max_cost_usd}
  consumed      jsonb NOT NULL DEFAULT '{}',
  started_at    timestamptz,
  finished_at   timestamptz,
  created_by    int REFERENCES users(id),
  created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE assets (                     -- discovered during recon
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id        uuid NOT NULL,
  scan_id       uuid REFERENCES scans(id),
  target_id     uuid REFERENCES targets(id),
  kind          text NOT NULL,            -- subdomain|host|port|service|cert|cloud_bucket
  value         text NOT NULL,
  meta          jsonb NOT NULL DEFAULT '{}',
  first_seen    timestamptz NOT NULL DEFAULT now(),
  last_seen     timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, target_id, kind, value)
);

CREATE TABLE endpoints (                  -- the attack surface
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id        uuid NOT NULL,
  target_id     uuid NOT NULL,
  method        text NOT NULL,
  url_pattern   text NOT NULL,            -- normalized: /users/{id}
  source        text NOT NULL,            -- crawl|intercept|bundle|openapi|graphql|param_mine
  params        jsonb NOT NULL DEFAULT '[]', -- [{name,in,type,required}]
  auth_context  text,                     -- which identity reached it
  content_hash  text,                     -- structural dedup key
  first_seen    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, target_id, method, url_pattern, auth_context)
);

CREATE TABLE findings (                   -- raw, per-location, pre-dedup
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id        uuid NOT NULL,
  scan_id       uuid NOT NULL REFERENCES scans(id),
  endpoint_id   uuid REFERENCES endpoints(id),
  plugin_id     text NOT NULL,
  class         text NOT NULL,            -- 'xss'|'sqli'|'ssrf'|'idor'|...
  severity      text NOT NULL,            -- info|low|medium|high|critical
  confidence    text NOT NULL,            -- potential|firm|confirmed
  proof         jsonb NOT NULL,           -- {type, oast_hit_id?, canary?, timing_stats?}
  evidence_ref  text,                     -- object-store key: HAR/screenshot/req-resp
  status        text NOT NULL DEFAULT 'new', -- new|verified|false_positive|accepted_risk|fixed
  created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE issues (                     -- materialized, dedup'd, correlated
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id        uuid NOT NULL,
  target_id     uuid NOT NULL,
  class         text NOT NULL,
  title         text NOT NULL,
  severity      text NOT NULL,
  risk_score    numeric NOT NULL,         -- Risk Scorer output
  cvss_vector   text,
  cwe           text,
  owasp         text,                     -- 'A03:2021-Injection'
  locations     jsonb NOT NULL DEFAULT '[]', -- finding_ids collapsed here
  correlated    jsonb NOT NULL DEFAULT '{}', -- {sast_ref, sca_cve, secret_ref}
  chain         jsonb,                    -- attack-chain steps if part of one
  remediation   text,
  case_id       uuid,                     -- link to AEGIS case
  first_seen    timestamptz NOT NULL DEFAULT now(),
  last_seen     timestamptz NOT NULL DEFAULT now(),
  fixed_at      timestamptz
);

CREATE TABLE oast_interactions (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id        uuid NOT NULL,
  scan_id       uuid NOT NULL,
  correlation   text NOT NULL,            -- unique subdomain/token planted in payload
  protocol      text NOT NULL,            -- dns|http|smtp
  remote_addr   inet,
  raw           jsonb NOT NULL,
  received_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE identities (                 -- for the auth-matrix
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id        uuid NOT NULL,
  target_id     uuid NOT NULL,
  label         text NOT NULL,            -- 'admin'|'user_a'|'user_b'|'anon'
  role          text,
  session_enc   bytea,                    -- encrypted cookies/tokens (KEK envelope)
  login_recipe  jsonb,                    -- recorded login flow to re-auth
  created_at    timestamptz NOT NULL DEFAULT now()
);
```

### 6.2 Other stores

- **Object store (S3/MinIO):** evidence blobs — HAR files, screenshots, response
  bodies, crawl videos. Referenced by `evidence_ref`. Lifecycle-expired per retention
  policy (reuses AEGIS compliance retention engine).
- **Graph store (Neo4j or Postgres-AGE):** the Knowledge Graph — nodes
  `(Asset)-[HOSTS]->(Endpoint)-[REACHABLE_AS]->(Identity)`, `(Endpoint)-[HAS]->(Finding)`,
  `(Finding)-[CHAINS_TO]->(Finding)`. Powers correlation and attack-path queries.
- **OpenSearch:** full-text + faceted search over findings/issues for the console.
- **Redis:** rate-limit token buckets (per grant, per target), distributed locks
  (one crawler per app-state), worker heartbeats, hot cache.
- **Time-series (VictoriaMetrics/Prometheus):** scan metrics, worker utilization,
  finding-rate trends.

---

## 7. Event Pipeline

**Transport:** NATS JetStream (reference; Kafka for very high scale). Subjects are
hierarchical; consumers are durable, per-fleet, with at-least-once delivery and
idempotent handlers (dedupe on event `id`).

### 7.1 Core subjects

```
scan.created                target enumerated, grant verified, saga starts
scan.plan.ready             AI planner has scored the surface
scan.paused / .resumed / .aborted / .completed
asset.discovered            recon output
endpoint.found              a new (dedup'd) surface element
surface.enumerated          API-discovery finished for a target
injection_point.ready       an endpoint+param queued for a test class
finding.candidate           active-scan produced a potential
oast.callback               collaborator received an out-of-band hit
finding.confirmed           verify fleet produced proof
issue.materialized          correlation dedup'd + assembled
issue.enriched              risk-scored + AI explanation attached
evidence.captured           screenshot/HAR stored
```

### 7.2 Delivery guarantees & idempotency

- **At-least-once** everywhere; every handler is idempotent keyed on event `id` +
  a natural key (e.g. `finding` unique on `scan_id+endpoint+plugin+param`).
- **Ordered per target** where it matters (crawl before scan) via subject
  partitioning on `target_id`; unordered where safe (parallel class scans).
- **Backpressure:** work queues are bounded; when a fleet is saturated the
  orchestrator slows emission rather than dropping (protects the *target* from being
  hammered as much as the system from overload).
- **Replayability:** JetStream retention lets a scan be replayed for debugging or
  re-analysis with a new plugin version without re-hitting the target (evidence is
  stored).

### 7.3 The OAST correlation loop (why it's special)

```
active-scan plants payload containing  <unique>.oast.horizon.io
        │
        ▼ (target, later, out of band)
collaborator DNS/HTTP receives hit for <unique>
        │  emit oast.callback{correlation:<unique>, proto, addr, raw}
        ▼
verify fleet joins correlation→injection_point → emit finding.confirmed (blind vuln)
```
This decouples cause and effect across time and network path — the only sound way to
catch blind SSRF/SQLi/XXE/RCE.

---

## 8. Distributed Scanning Architecture

### 8.1 Work distribution

- **Pull, not push.** Workers pull from per-capability priority queues. A slow SQLi
  worker never blocks a fast XSS worker; adding capacity is "start more pods."
- **Sharding key = `target_id`.** All work for one target can be pinned so per-target
  rate limits and session reuse hold, while different targets fan out across the fleet.
- **Rate governance is per-target, globally enforced.** A Redis token bucket keyed on
  `(grant_id, target_host)` is checked by *every* worker before every outbound
  request. This is the single most important safety control — it guarantees Horizon
  never exceeds the authorized RPS *in aggregate*, no matter how many workers run.
- **Budget enforcement.** The orchestrator debits `scans.consumed` (requests, wall
  time, LLM cost) and halts stages when a budget cap is hit — prevents runaway scans
  and runaway bills.

### 8.2 Concurrency model per fleet

| Fleet | Concurrency shape | Rate discipline |
|---|---|---|
| Recon | High parallel, external tools | Provider-API-aware backoff |
| Crawler | 1 browser context per app-state; N contexts per app | Per-target RPS bucket |
| Active-Scan XSS/canary | High parallel per endpoint | Shared per-target bucket |
| Active-Scan SQLi time-based | Serial per host (timing needs isolation) | Strict, low RPS |
| SSRF/OAST | Fire-and-wait; callback-driven | Low RPS, long timeout |
| Auth-Matrix | Parallel per (endpoint × identity) | Per-target bucket |

### 8.3 Failure & resumption

- Worker crash → lease expires → task redelivered to another worker (idempotent).
- Orchestrator crash → durable saga state resumes from last committed step.
- Target goes down / WAF-blocks → circuit breaker per target pauses the scan, alerts,
  and offers resume; never hammers a struggling target.
- Poison task (repeatedly crashes a worker) → dead-letter queue + alert, scan
  continues.

---

## 9. Browser Automation Architecture

### 9.1 Engine choice

**Chromium via CDP, driven by Playwright.** Rationale: Playwright's auto-waiting and
multi-context model beat raw Puppeteer for reliability; CDP gives the low-level
domains (Network, Fetch, Page, DOM, WebAuthn, Storage) the crawler needs. Firefox/
WebKit contexts optional for cross-engine bugs. Selenium is rejected (slower, weaker
interception).

### 9.2 The state-graph crawler

```
Node   = (normalized_url, dom_structural_hash, auth_context)
Edge   = interaction (click | submit | route-change | api-call-trigger)
Frontier = priority queue (security-value-scored, budget-bounded)
```

Loop:
1. Load/return to a node (real navigation or replay of the interaction path).
2. **Instrument before interaction:** enable CDP `Network.enable`, `Fetch.enable`
   (request interception), `Page.setLifecycleEventsEnabled`, DOM mutation observer.
3. Snapshot: post-hydration DOM, structural hash, all forms, all event-bound
   clickables, current storage (cookies/LS/SS/IDB), registered service workers.
4. Enumerate candidate interactions; **AI Planner scores** them (a "Delete" button
   and a login form outrank a carousel arrow).
5. Execute the top-budgeted interactions; for each, capture: new network calls
   (→ endpoints), route changes (→ new nodes), DOM diffs, new storage.
6. Dedup new nodes by structural hash; enqueue novel ones; record parameter surface
   of duplicates without re-crawling them.

### 9.3 Network & protocol interception

- **Fetch/XHR:** CDP `Fetch.requestPaused` captures every call with headers/body →
  feeds API-discovery and endpoint table. Optionally rewrite (inject canaries).
- **WebSocket:** `Network.webSocketFrame*` events → frame log for WS security tests.
- **GraphQL:** detect by content-type/shape → trigger introspection → per-op fuzzing.
- **tRPC/gRPC-Web:** decode batch/framing to recover logical operations.
- **Source maps:** if exposed, fetch and reconstruct original source for better
  static analysis and secret detection (and flag the exposure itself).

### 9.4 Auth handling

- **Recorded login recipe** (Playwright codegen-style) stored per identity; replayed
  to (re)authenticate; detects success by post-condition assertion.
- **Session import** for MFA/passkey-protected apps a human logs into once.
- **WebAuthn virtual authenticator** via CDP `WebAuthn` domain for scriptable passkey
  flows in test environments.
- **Session isolation:** each identity = its own browser context (no cookie bleed),
  enabling the Auth-Matrix to run the same request as admin/user/anon and diff.

### 9.5 Isolation & hygiene

- Every browser runs **sandboxed, ephemeral, network-egress-restricted** to the
  authorized scope (§16). Contexts are torn down per scan; no state persists across
  tenants. Browsers run in gVisor/Kata or Firecracker microVMs for defense-in-depth
  (the crawler executes untrusted JS from the target — treat it as hostile).

---

## 10. Plugin SDK Architecture

Horizon's extensibility is its moat. Three tiers, so trivial checks stay trivial and
complex ones stay possible — all sandboxed and capability-scoped.

### 10.1 Tier 1 — Declarative templates (Nuclei-superset YAML)

For request/response checks. Horizon natively runs **Nuclei templates** (adopt the
huge existing corpus) and extends the schema with: multi-step flows, OAST assertions,
browser-context steps, and identity selection. 80% of checks need nothing more.

```yaml
id: reflected-xss-canary
info: { name: Reflected XSS (canary), severity: high, class: xss }
requires: { classes: [active_safe] }        # gated by Authorization Grant
flow:
  - inject: { param: "*", value: "hzn{{rand}}<svg/onload>" }
  - assert: { rendered_dom_contains: "hzn{{rand}}", executed: true }  # browser-verified
proof: { type: canary, nonce: "{{rand}}" }
```

### 10.2 Tier 2 — Typed programmatic plugins (WASM-sandboxed)

For logic templates can't express (stateful inference, custom decoders). Authored in
any language compiling to **WebAssembly (WASI)**; Horizon provides a typed host API.
WASM gives strong sandboxing + language freedom + safe distribution.

```
Host capabilities offered to a plugin (each must be declared & granted):
  http.request(scoped)      — only to in-grant hosts, rate-limited by host bucket
  oast.allocate()           — get a unique collaborator correlation id
  browser.eval(scoped)      — run in a crawled page's context
  kg.query(read-only)       — read the knowledge graph
  finding.emit(proof)       — emit a candidate (MUST carry proof to be confirmable)
  log/metric                — observability
Explicitly NOT offered: filesystem, arbitrary network, subprocess, env.
```

### 10.3 Tier 3 — Worker plugins (full containers)

For wrapping whole external tools (sqlmap, a custom fuzzer). Runs as a container
implementing the **Worker gRPC contract** (pull task → do work → emit findings). Most
powerful, least sandboxed → admin-approved + signed images only, network-policy-locked
to scope.

### 10.4 Governance

- Every plugin declares `requires.classes` (passive/active_safe/active_intrusive);
  the orchestrator refuses to schedule a plugin whose class exceeds the scan's grant.
- Plugins are **signed**; a registry enforces provenance (reuses AEGIS agent-release
  signing/JWKS pattern). Marketplace + private org registries.
- Findings without valid `proof` can never reach `confirmed` — the SDK makes proof a
  type requirement, not a convention.

---

## 11. API Specification

REST/JSON at the edge (OpenAPI 3.1 published), gRPC internally. All under `/api/v3`
(v2 is AEGIS Enterprise). Auth = AEGIS RS256 bearer; RBAC via `require(min_role)`.

### 11.1 Representative endpoints

```
# Authorization Grants (owner/admin)
POST   /api/v3/grants                 create a scope grant (signed)
GET    /api/v3/grants                 list
POST   /api/v3/grants/{id}/revoke     revoke immediately (kills running scans in scope)

# Targets
POST   /api/v3/targets                register an app (base_url, criticality, data_class)
GET    /api/v3/targets                list · GET /{id} detail (with tech fingerprint)

# Scans
POST   /api/v3/scans                  {target_id, profile, budget}  → 202 + scan_id
GET    /api/v3/scans/{id}             saga state, progress, consumed budget
POST   /api/v3/scans/{id}/pause|resume|abort
GET    /api/v3/scans/{id}/events      SSE/WebSocket live stream
GET    /api/v3/scans/{id}/surface     discovered endpoints/assets

# Identities (for auth-matrix)
POST   /api/v3/targets/{id}/identities        add role + login recipe / session import

# Findings & Issues
GET    /api/v3/issues                 filter: severity, class, status, target
GET    /api/v3/issues/{id}            detail + evidence + chain + remediation
POST   /api/v3/issues/{id}/verdict    {status: false_positive|accepted_risk|fixed} → trains ranking
POST   /api/v3/issues/{id}/retest     re-run just this check
GET    /api/v3/findings/{id}/evidence signed URL to HAR/screenshot

# Reports
POST   /api/v3/reports                {scan_id|target_id, format: pdf|html|sarif|json, audience}
GET    /api/v3/reports/{id}

# Plugins
GET    /api/v3/plugins                registry · POST install (signed) · per-org enable

# Continuous / schedule
POST   /api/v3/schedules              {target_id, cadence, profile, quiet_hours}

# Webhooks / integrations
POST   /api/v3/integrations/jira|slack|siem|github
```

### 11.2 Conventions

- **Async by default:** scans/reports return `202` + resource id; progress via SSE
  or webhook. No long-held connections.
- **Idempotency-Key** header on all POSTs that create work.
- **Cursor pagination**, RFC 7807 problem+json errors, strict request validation.
- **SARIF export** so issues drop straight into GitHub/GitLab code scanning.
- Every state-changing call writes an AEGIS tamper-evident audit entry.

---

## 12. Deployment Architecture

### 12.1 Topologies

| Mode | Who | Shape |
|---|---|---|
| **Single-node (dev/lite)** | solo pentester, evals | Docker Compose; SQLite/Postgres, one worker of each, embedded NATS. Mirrors AEGIS lite mode. |
| **Self-hosted cluster** | enterprises, sensitive scope | Kubernetes; HA control plane, autoscaled worker fleets, in-cluster OAST via delegated subdomain |
| **SaaS multi-tenant** | most customers | Regional K8s, per-tenant RLS + network isolation, shared OAST with strict correlation isolation |
| **Hybrid (SaaS control + on-prem scanners)** | can't send traffic to cloud | Control plane in SaaS; **scanner agents** run inside the customer network (reuses AEGIS agent PKI/mTLS enrollment) and pull work over an authenticated tunnel |

The **hybrid** model is the enterprise unlock and comes almost free: AEGIS already has
per-org CA, mTLS agent enrollment, signed OTA updates, and fleet health. A Horizon
scanner is "just another agent" — it enrolls, gets a cert, pulls scoped work, and
never requires inbound access to the customer network.

### 12.2 Kubernetes layout

```
control-plane ns:  gateway (HPA) · orchestrator (Temporal) · scheduler ·
                   grant-svc · ai-svc · correlation · risk · reporting
data-plane ns:     recon-pool · crawler-pool (gVisor RuntimeClass) ·
                   scan-pools (per class, KEDA-scaled on queue depth) ·
                   verify-pool · evidence-pool
platform ns:       nats-jetstream · redis · postgres(primary+replicas) ·
                   opensearch · neo4j · minio · victoria-metrics
edge:              oast-collaborator (own public IP + delegated NS records)
```

- **KEDA** scales scan pools on queue depth (0→N→0); crawler pool scales on active
  scans. Idle cost ≈ control plane only.
- **gVisor/Kata RuntimeClass** for browser + Tier-3 plugin pods (untrusted execution).
- **NetworkPolicies** pin worker egress to in-grant scope + collaborator + platform.

### 12.3 CI/CD

GitOps (Argo/Flux). Progressive delivery (canary) for workers since a bad scan plugin
has real-world blast radius. Plugin images signed (cosign) and admission-controlled.

---

## 13. Threat Model

Horizon is a high-value, high-authority system: it holds scope grants, session
secrets, and can generate traffic against real assets. It is itself a target.

### 13.1 Assets to protect
Authorization grants & signing keys; target session credentials/tokens; findings
(a map of how to breach customers); OAST callback data; the plugin supply chain.

### 13.2 Trust boundaries & top threats (STRIDE-flavored)

| # | Threat | Vector | Mitigation |
|---|---|---|---|
| T1 | **Scanning an unauthorized target** (accidental or malicious) | Bad scope, SSRF-into-internal, typo'd wildcard | Signed Authorization Grants checked by every worker; egress NetworkPolicy to in-grant hosts only; scope-canonicalization; deny RFC1918 unless grant explicitly allows |
| T2 | **Horizon used as an attack proxy / DoS amplifier** | Attacker drives scans at a victim | Grant + per-target aggregate rate cap (Redis, globally enforced); org-level quotas; anomaly alerts on scan volume |
| T3 | **Malicious plugin** exfiltrates data / escapes sandbox | Supply chain | WASM/WASI sandbox + declared capabilities; signed registry; Tier-3 containers admin-approved, gVisor-isolated, egress-locked |
| T4 | **Tenant isolation break** — org A sees org B's findings | RLS gap, shared OAST correlation collision | Postgres RLS (AEGIS); per-scan cryptographically-random OAST correlation ids; object-store keys namespaced + IAM-scoped |
| T5 | **Session-secret theft** | DB/disk compromise | KEK envelope encryption (AEGIS crypto); secrets never logged; short-lived; encrypted at rest & in transit |
| T6 | **Hostile target attacks the crawler** | Malicious JS, zip-bomb responses, XXE-back-at-scanner | Browser in microVM, ephemeral, resource-capped; response size limits; safe XML parsers; treat all target output as hostile input |
| T7 | **OAST server abused** as open resolver / relay | Public DNS/HTTP listener | Answer only for owned zone; no recursion/relay; rate-limited; logs correlation only |
| T8 | **Grant forgery / privilege escalation** | Signature bypass, RBAC gap | Detached signatures over grants; RBAC on grant creation (owner/admin); tamper-evident audit of every grant + scan |
| T9 | **Report leakage** (findings = a breach playbook) | Broken object refs, over-broad share | Signed, expiring evidence URLs; RLS on issues; report access audited; redaction of secrets in output (AEGIS copilot guardrail pattern) |

### 13.3 Safety invariants (must always hold)
1. No outbound test request without a live, matching grant.
2. Aggregate RPS to any host never exceeds the grant cap, across all workers.
3. Intrusive/destructive classes require explicit grant opt-in + are default-off.
4. Every scan and grant action is in the tamper-evident audit chain.
5. A revoked grant kills in-flight scans in its scope within seconds.

---

## 14. Scaling Strategy

### 14.1 Independent scaling axes
- **Breadth** (many targets) → recon + orchestrator replicas.
- **Depth** (big SPAs) → crawler pool (browser-bound, CPU/RAM heavy).
- **Test intensity** → per-class scan pools (KEDA on queue depth).
- **Findings volume** → correlation/AI/OpenSearch.
Each is a separate deployment with its own HPA/KEDA policy — no single bottleneck.

### 14.2 Stateless workers, durable state elsewhere
Workers hold nothing; all state is in Postgres/Redis/object-store/graph. Scale to
zero when idle; burst to thousands under load. The only stateful control service is
the orchestrator, made HA via the workflow engine.

### 14.3 Data-layer scaling
Postgres primary + read replicas (findings/issues reads are read-heavy); partition
`findings`/`oast_interactions` by time; OpenSearch for search fan-out; object store is
infinitely scalable by nature; graph store sharded per large tenant if needed.

### 14.4 Continuous / diff-aware scanning (the efficiency multiplier)
Re-scanning everything nightly is wasteful. Horizon fingerprints the surface
(`endpoints.content_hash`, bundle hashes) and only deep-tests what *changed* since the
last scan, plus periodic full sweeps. On a deploy webhook, scan the delta in minutes,
not the whole app in hours. Finding-diff drives "you introduced this bug in this PR."

### 14.5 Multi-region
Regional data residency (EU scans stay in EU); OAST collaborators per region;
control plane can be global with regional data planes.

---

## 15. Performance Optimization

- **Browser reuse & pooling:** warm Chromium pool; new *context* per state (cheap),
  new *process* only per scan/tenant (isolation). Context reuse is the single biggest
  crawler speedup.
- **Render budgets:** cap per-page hydration wait with lifecycle-event heuristics
  (network-idle + mutation-quiet) instead of fixed sleeps.
- **Structural dedup early:** hash-and-skip duplicate states *before* spending
  render/scan budget on them — the difference between crawling 50 states and 50,000.
- **Response caching:** passive checks and static analysis reuse the crawler's already
  captured responses (HAR) — never re-fetch for a second check.
- **Payload batching:** where safe, test multiple params/canaries per request.
- **Adaptive rate:** ramp RPS up while error rate stays flat; back off on 429/5xx or
  latency spikes — fast *and* polite.
- **LLM cost control:** cache AI plans/explanations keyed on surface hash; use small
  models for triage, large only for report prose; hard per-scan cost budget.
- **Tiered storage:** hot findings in Postgres/OpenSearch, cold evidence lifecycle'd
  to cheap object storage, expired per retention policy.
- **Precompiled plugin matchers:** compile template matchers once per scan, not per
  request.

---

## 16. Security Model

### 16.1 Authorization Grant (the keystone)
Nothing runs without a **signed, time-boxed, scope-limited grant**: hosts/CIDRs/paths,
allowed test-classes, max RPS, validity window, signer identity, detached signature
(non-repudiation). Every worker verifies the grant + scope-match + class-allowed
before every outbound request. Revocation is immediate and kills in-flight scans.

### 16.2 Identity, authN/authZ (inherited from AEGIS)
RS256/JWKS access tokens, refresh rotation, MFA/TOTP, SSO/SCIM, four-tier RBAC
(`read_only`→`analyst`→`admin`→`owner`). Grant creation and intrusive-scan launch are
`admin`+ and MFA-gated.

### 16.3 Multi-tenant isolation
Postgres RLS on every tenant table (AEGIS tenancy); per-tenant object-store namespacing;
cryptographically-random OAST correlation ids so callbacks can't cross tenants;
optional per-tenant scanner agents (on-prem) for full network isolation.

### 16.4 Secrets & crypto
KEK envelope encryption (AEGIS `crypto.py`) for session secrets, plugin creds, CA
keys; secrets never logged; TLS everywhere; agent mTLS for scanner enrollment.

### 16.5 Sandboxing
Browsers and Tier-3 plugins in gVisor/Kata/microVM, ephemeral, egress-locked. WASM/WASI
for Tier-2 plugins with declared capabilities only. Untrusted-input discipline on all
target responses.

### 16.6 Auditability & governance
Every grant, scan, verdict, report-access, and config change enters AEGIS's
hash-chained audit log — provable, tamper-evident, exportable for SOC2/PCI evidence.
Findings redact secrets before display/report.

---

## 17. Product Roadmap (MVP → Enterprise)

### v0 — Recon + Passive (MVP, ~weeks)
Grants, targets, recon fleet (subfinder/httpx/dnsx/naabu), tech fingerprint, passive
checks (headers, cookies, CSP, mixed content, exposed secrets/source maps, outdated
libs), findings/issues model, basic console + SARIF export. **Value:** immediate ASM +
low-risk signal, zero intrusive traffic. Proves the pipeline end-to-end.

### v1 — Browser Crawl + Active-Safe DAST
State-graph Chromium crawler, network interception, API discovery (OpenAPI/GraphQL/
param-mine), active-safe checks (reflected XSS canary, open redirect, SSRF via OAST,
error-based SQLi, CORS/JWT misconfig), OAST collaborator, Verify fleet + proof-carrying
findings. **Value:** real DAST that handles modern SPAs — the core product.

### v2 — Correlation + AI Analyst + Continuous
Knowledge graph, DAST⨯SAST⨯SCA correlation, AI triage/dedup/report, risk scoring,
continuous/diff-aware scanning, scheduler, Jira/Slack/SIEM integrations, findings →
AEGIS cases. **Value:** noise→signal, and point-in-time→continuous.

### v3 — Auth-Matrix + Business Logic + Plugin Marketplace
Multi-identity replay & authorization diffing (IDOR/BOLA, broken function-level auth),
intrusive class opt-in (blind/time-based, request smuggling, SSTI, XXE, prototype
pollution), Tier-1/2/3 plugin SDK + signed marketplace, WebAuthn virtual authenticator.
**Value:** the categories competitors can't automate.

### v4 — Enterprise scale + Hybrid + Compliance
Hybrid on-prem scanner agents (via AEGIS PKI), multi-region/data-residency, HA/DR,
KEDA autoscale, compliance report packs (ASVS/PCI/SOC2), advanced attack-chain
assembly, remediation-tracking over time. **Value:** lands regulated enterprises.

---

## 18. Implementation Phases (value vs. risk)

Ordered highest-value / lowest-risk first. Each phase is shippable and de-risks the
next.

| Phase | Deliverable | Value | Risk | Why this order |
|---|---|---|---|---|
| **P0** | Grants + Targets + audit + RBAC on AEGIS spine | Foundational safety | Low | Nothing is safe to build until authorization + isolation exist. Reuses AEGIS — mostly wiring. |
| **P1** | Event bus + orchestrator saga + one recon worker + findings model | Proves the distributed pipeline | Low | Passive recon can't harm a target; validates architecture cheaply. |
| **P2** | Passive check engine + console + SARIF | First real customer value (ASM) | Low | No intrusive traffic; immediate signal; establishes finding/report UX. |
| **P3** | Browser crawler + network interception + API discovery | The hard technical core | **High** | Highest engineering risk (SPA state-modeling). Do it once the pipeline around it is proven so failures are isolated. |
| **P4** | OAST collaborator + active-safe scan + Verify + proof model | Real DAST, low FP | Med | OAST is the correctness backbone; proof-carrying findings prevent the FP death-spiral. |
| **P5** | Correlation + Risk + AI Analyst | Noise → prioritized signal | Med | Needs volume from P4 to be worth building; AI stays advisory (bounded risk). |
| **P6** | Continuous/diff scanning + scheduler + integrations + cases | Point-in-time → program | Low | Straightforward once findings are stable; big retention/UX win. |
| **P7** | Auth-matrix + business-logic + intrusive opt-in | Uniquely differentiated coverage | **High** | Highest-value *and* highest-blast-radius — deferred until safety rails (grants, rate caps, verify, audit) are battle-tested. |
| **P8** | Plugin SDK (T1→T2→T3) + marketplace | Ecosystem / moat | Med | Opening extensibility before the core is stable would fragment it; sandboxing must be mature first. |
| **P9** | Hybrid agents + multi-region + compliance packs | Enterprise scale | Med | Pure scale/governance work; lands last because it needs a proven product to wrap. |

**Guiding rule:** capability that can touch a real target ships only *after* the
safety control that bounds it. Grants before scanning, rate caps before parallelism,
Verify before intrusive checks, audit before everything.

---

## Appendix A — How Horizon reuses the existing AEGIS spine

| AEGIS Enterprise capability | Horizon reuse |
|---|---|
| Orgs + Memberships + RLS multi-tenancy | Tenant isolation for all Horizon data |
| RS256/JWKS auth, refresh rotation, MFA, SSO/SCIM | Horizon's entire authN/authZ |
| 4-tier RBAC (`require(min_role)`) | Grant creation, intrusive-scan gating |
| Agent PKI (per-org CA, mTLS enrollment, signed OTA) | Hybrid on-prem **scanner agents** |
| Cases (SLA, escalation, playbooks, timeline) | Findings become cases; SOC workflow unchanged |
| Tamper-evident audit (hash-chained) | Grants, scans, verdicts, report access |
| SIEM forwarder (`siem.emit`) | Scan + finding events to customer SIEM |
| Copilot provider-agnostic LLM gateway + guardrails | AI Planner/Analyst gateway pattern |
| Compliance retention engine | Evidence/finding lifecycle expiry |
| KEK envelope crypto | Session secrets, CA keys, plugin creds |
| Prometheus/structured-logging/security-headers | Horizon observability baseline |

Horizon is not a rewrite — it is a new **data plane** (scanning) and **intelligence
layer** (planner/analyst/correlation) bolted onto AEGIS Enterprise's proven
**control plane** (auth, tenancy, governance).

---

*End of design document. No implementation code included, by design.*

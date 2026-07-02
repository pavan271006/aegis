# AEGIS Horizon — Coverage Catalog, Gap Analysis & Prioritization

**Companion to [HORIZON-PLATFORM-DESIGN.md](HORIZON-PLATFORM-DESIGN.md). Research & analysis only — no implementation code.**

> **Sourcing honesty.** This document synthesizes established, stable authoritative
> standards: OWASP Top 10 (2021), OWASP API Security Top 10 (2023), OWASP ASVS
> (4.0.3 / 5.0), OWASP WSTG, OWASP Testing Guide, CWE Top 25 (2023/2024), CISA KEV
> catalog *themes*, and MITRE ATT&CK. These taxonomies are stable and I state them
> from established knowledge (current to ~Jan 2026). **Fast-changing data — the exact
> current contents of the CISA KEV catalog and this quarter's NVD CVE trend counts —
> should be verified live before quoting specific numbers; I deliberately do not
> invent statistics or CVE IDs here.** Where a claim depends on live data, it is
> marked ⟨verify-live⟩. I can pull those on request.

---

## Automation-honesty rating (used throughout)

Every category carries one of three tiers. This is the core discipline the brief
demands — **do not overstate automation.**

| Tier | Meaning | What Horizon does |
|---|---|---|
| **[A] Reliably automatable** | Deterministic proof is obtainable (OOB callback, executed canary, cross-identity diff, version match) | Auto-**confirm** with evidence |
| **[B] Automation-assisted** | Machine narrows the search, but a human must judge exploitability/impact | Surface as **candidate**, rank, route to analyst |
| **[C] Primarily manual** | Depends on business/workflow semantics a scanner cannot know | **Assist only** (map surface, suggest tests); never claim confirmation |

---

# PART A — Landscape Review

## A.1 The authoritative frames and how Horizon uses each

| Source | What it is | Role in Horizon |
|---|---|---|
| **OWASP Top 10 (2021)** | Risk-ranked web app categories | Primary reporting taxonomy; every issue maps to an `Axx:2021` |
| **OWASP API Security Top 10 (2023)** | API-specific risk list | Reporting taxonomy for API findings (`APIxx:2023`) |
| **OWASP ASVS (4.0.3 stable; 5.0 released 2025)** | Verification requirement checklist (L1–L3) | Coverage completeness measure — "which ASVS controls can Horizon verify?" |
| **OWASP WSTG** | Web Security Testing Guide (test procedures) | Source of concrete test techniques per category |
| **CWE / CWE Top 25** | Root-cause weakness taxonomy | Precise `CWE-xxx` on every finding (better than OWASP for dev remediation) |
| **CVE / NVD** | Known vulnerability instances + CVSS | SCA/version-match findings; CVSS base for risk scoring |
| **CISA KEV** | Vulnerabilities *known to be exploited in the wild* | **Exploitability weight** in risk scoring — KEV membership is the strongest "fix now" signal |
| **MITRE ATT&CK** | Adversary TTPs | Defensive mapping (reuses AEGIS's existing `attack_techniques` tables); maps findings→technique for blue-team context |

## A.2 Cross-source trend synthesis (what the data agrees on)

Cross-referencing OWASP's 2021 reshuffle, CWE Top 25, and KEV themes, five durable
signals shape where a modern platform must invest:

1. **Broken Access Control moved to #1 (OWASP A01:2021).** Authorization — not
   injection — is now the dominant, most-prevalent web risk. IDOR/BOLA and
   broken-function-level-auth are the highest-value automatable-*with-identities*
   categories. This validates Horizon's **Auth-Matrix** as a first-class fleet.
2. **API risks diverged enough to need their own Top 10.** BOLA (API1:2023) and
   broken object-property-level auth (API3) are API-native. API-first apps expose the
   *most* surface and get the *least* DAST attention → Horizon's API-discovery fleet.
3. **SSRF earned its own OWASP slot (A10:2021) and dominates enterprise KEV
   entries** ⟨verify-live⟩ — appliance/edge SSRF→RCE chains are a recurring KEV
   pattern. Reinforces the **OAST collaborator** as non-negotiable.
4. **Supply-chain & integrity (A08:2021) rose sharply** — vulnerable components
   (A06), third-party JS, and CI/CD integrity. Pushes Horizon toward SCA correlation
   and third-party-script analysis, not just first-party DAST.
5. **Deserialization (CWE-502), path traversal (CWE-22), and auth bypass
   (CWE-287/306/862) are perennial KEV leaders** ⟨verify-live⟩ — the classes that
   turn into real-world mass exploitation. These deserve deep, high-confidence
   detection, and two of them (deserialization, some path-traversal variants) are
   **currently under-addressed** in the Horizon v1 design (see Part C).

---

# PART B — Coverage Catalog

Grouped by family. Each entry: Description · Root cause · Affected tech · Risk ·
Standards · Automatable(tier) · Auth-required · Manual-validation · Evidence ·
Remediation · Reference.

## B.1 Injection family

### Cross-Site Scripting (XSS) — reflected / stored / DOM
- **Description:** Attacker-controlled data reaches an HTML/JS sink and executes in a victim's browser.
- **Root cause:** Output not context-encoded; dangerous sinks (`innerHTML`, `eval`, `document.write`, framework `dangerouslySetInnerHTML`/`v-html`).
- **Affected tech:** All web; DOM-XSS especially in SPAs (React/Vue/Angular) via client-side routing/templating.
- **Risk:** High (account takeover, session theft).
- **Standards:** OWASP A03:2021; CWE-79; WSTG-INPV-01/02.
- **Automatable:** **[A]** reflected/DOM (browser-executed canary); **[A/B]** stored (needs re-crawl correlation).
- **Auth required:** Often (stored XSS in authenticated features).
- **Manual validation:** Rarely for reflected; sometimes for stored impact.
- **Evidence:** Unique nonce canary observed *executing* in the rendered DOM (not just reflected), screenshot + DOM snapshot.
- **Remediation:** Context-aware output encoding; CSP as defense-in-depth; framework auto-escaping; avoid dangerous sinks; Trusted Types.
- **Reference:** OWASP XSS Prevention Cheat Sheet.

### SQL Injection (and NoSQL / ORM / LDAP variants)
- **Description:** Untrusted input alters a backend query (SQL, MongoDB, LDAP, ORM DSL).
- **Root cause:** String-concatenated queries; unparameterized ORM raw queries; unsanitized filter objects (NoSQL operator injection `{$gt:""}`).
- **Affected tech:** Any DB-backed app; NoSQL in Node/Mongo stacks; ORM injection in raw-query escape hatches.
- **Risk:** Critical (data exfil, auth bypass, RCE via stacked queries).
- **Standards:** OWASP A03:2021; CWE-89 (SQL), CWE-943 (NoSQL), CWE-90 (LDAP); WSTG-INPV-05/06.
- **Automatable:** **[A]** error/boolean/time-based + OOB (SQLi); **[B]** NoSQL/LDAP/ORM (more FP-prone, needs review).
- **Auth required:** Sometimes.
- **Manual validation:** Low for classic SQLi; higher for NoSQL operator injection.
- **Evidence:** Differential response proof, statistically-significant time delta (isolated), or OOB exfil callback; the payload + response pair.
- **Remediation:** Parameterized queries / prepared statements; ORM safe APIs; input allow-listing; least-privilege DB role.
- **Reference:** OWASP SQLi Prevention Cheat Sheet; sqlmap techniques.

### Command Injection
- **Description:** Input reaches an OS shell/command constructor.
- **Root cause:** `system()/exec()` with concatenated input; shell=True; unsafe template of CLI args.
- **Affected tech:** Any app shelling out (image processing, PDF, network tools, legacy).
- **Risk:** Critical (RCE).
- **Standards:** OWASP A03:2021; CWE-78 (OS), CWE-77 (generic); WSTG-INPV-12.
- **Automatable:** **[A]** via differential + OOB callback.
- **Auth required:** Sometimes.
- **Manual validation:** Low when OOB fires.
- **Evidence:** OOB DNS/HTTP callback keyed to the injection point; or deterministic output marker.
- **Remediation:** Avoid shell; use exec-array APIs (no shell); strict allow-list; drop privileges.
- **Reference:** OWASP Command Injection Cheat Sheet.

### Server-Side Template Injection (SSTI)
- **Description:** Input evaluated by a server-side template engine → RCE.
- **Root cause:** User input concatenated into template source (Jinja2, Twig, Freemarker, Velocity, ERB).
- **Affected tech:** Server-rendered apps using template engines with user-controlled templates.
- **Risk:** Critical (RCE).
- **Standards:** OWASP A03:2021; CWE-1336/CWE-94; WSTG-INPV-18.
- **Automatable:** **[A]** polyglot math-eval markers (`{{7*7}}`→49) + OOB.
- **Auth required:** Sometimes.
- **Manual validation:** Low for detection; engine-specific exploitation may be manual.
- **Evidence:** Arithmetic evaluation marker in response; OOB for blind.
- **Remediation:** Never build templates from user input; sandboxed engines; logic-less templates.
- **Reference:** PortSwigger SSTI research (Kettle).

### XML External Entity (XXE)
- **Description:** XML parser resolves external entities → file read, SSRF, DoS.
- **Root cause:** XML parser with external-entity resolution enabled by default.
- **Affected tech:** SOAP, XML APIs, SAML, DOCX/SVG/XML file uploads, RSS.
- **Risk:** High–Critical.
- **Standards:** OWASP A05:2021 (misconfig); CWE-611; WSTG-INPV-07.
- **Automatable:** **[A]** OOB (entity fetch to collaborator) — the reliable path; **[B]** in-band file read.
- **Auth required:** Sometimes.
- **Manual validation:** Low with OOB proof.
- **Evidence:** OOB callback from XML entity; or file content reflected.
- **Remediation:** Disable DTD/external entities; use hardened parser config; prefer JSON.
- **Reference:** OWASP XXE Prevention Cheat Sheet.

### Insecure Deserialization  ⚠️ *(gap in current Horizon v1)*
- **Description:** Untrusted serialized data instantiated into objects → RCE/logic abuse.
- **Root cause:** Native deserializers on untrusted input (Java `readObject`, Python `pickle`, PHP `unserialize`, .NET `BinaryFormatter`, Ruby Marshal, insecure JSON polymorphic type handling).
- **Affected tech:** Java (ysoserial gadget chains), .NET, PHP, Python, Node (prototype pollution overlap).
- **Risk:** Critical; frequent KEV/CVE source ⟨verify-live⟩.
- **Standards:** OWASP A08:2021; CWE-502; WSTG-INPV-11.
- **Automatable:** **[B]** — detect serialized blobs in params/cookies; OOB gadget probes; but reliable confirmation often **[C]** (gadget availability is app-specific).
- **Auth required:** Often.
- **Manual validation:** High for exploitation; medium for detection.
- **Evidence:** Recognized serialized format in input + OOB callback from a benign gadget probe; magic-byte fingerprint.
- **Remediation:** Avoid native deserialization of untrusted data; signed/typed formats; allow-list classes; JSON with explicit schemas.
- **Reference:** OWASP Deserialization Cheat Sheet; ysoserial.

### CRLF / HTTP Response Splitting / Header Injection
- **Description:** Newlines injected into headers → response splitting, header injection, log injection.
- **Root cause:** Unsanitized input in response headers/redirect locations.
- **Risk:** Medium–High. **Standards:** CWE-93/113; WSTG-INPV-16.
- **Automatable:** **[A]** (injected header observed). **Auth:** rarely. **Manual:** low.
- **Evidence:** Injected header present in response. **Remediation:** Strip CR/LF; framework header APIs.

## B.2 Access control & authorization  *(OWASP #1 — highest prevalence)*

### Broken Object-Level Authorization (IDOR / BOLA)
- **Description:** User accesses another user's object by changing an identifier.
- **Root cause:** Missing per-object ownership check; trusting client-supplied IDs.
- **Affected tech:** All REST/GraphQL APIs; especially `/resource/{id}` patterns.
- **Risk:** High–Critical (mass data exposure).
- **Standards:** OWASP A01:2021; API1:2023; CWE-639/CWE-566; WSTG-ATHZ-04.
- **Automatable:** **[A]** *with the Auth-Matrix* — replay identical request as identity A vs B and diff (A sees B's data = confirmed). Without multiple identities, **[C]**.
- **Auth required:** **Yes** (needs ≥2 authenticated identities).
- **Manual validation:** Low when cross-identity diff is clean; higher when object semantics are ambiguous.
- **Evidence:** Same endpoint, identity A's session, returns identity B's object; the two responses side-by-side.
- **Remediation:** Server-side ownership checks on every object access; indirect/opaque references; centralized authЗ middleware.
- **Reference:** OWASP API Security Top 10 (API1).

### Broken Function-Level Authorization (BFLA) / privilege escalation
- **Description:** Lower-privileged user invokes higher-privileged function.
- **Root cause:** Auth enforced in UI only; missing role check server-side; hidden admin routes reachable.
- **Risk:** High–Critical. **Standards:** OWASP A01:2021; API5:2023; CWE-862/CWE-863/CWE-269; WSTG-ATHZ-02.
- **Automatable:** **[A]** with Auth-Matrix (low-priv identity reaches admin function). **Auth:** yes. **Manual:** low–medium.
- **Evidence:** Admin-only action succeeds under a non-admin session.
- **Remediation:** Deny-by-default; centralized RBAC/ABAC; server-side enforcement.

### Path Traversal / LFI / RFI  ⚠️ *(partial in Horizon v1)*
- **Description:** Input manipulates file paths → read/write/include arbitrary files.
- **Root cause:** User input in filesystem paths without canonicalization.
- **Affected tech:** File download/preview/upload, template includes, static handlers.
- **Risk:** High–Critical (KEV-frequent in appliances ⟨verify-live⟩).
- **Standards:** OWASP A01:2021; CWE-22/CWE-98; WSTG-ATHZ-01.
- **Automatable:** **[A]** canonical-file markers (`/etc/passwd`, `win.ini`) + differential.
- **Auth required:** Sometimes. **Manual validation:** Low.
- **Evidence:** Known file content in response; traversal payload + response.
- **Remediation:** Canonicalize + allow-list; reject `..`; serve from fixed base; avoid user input in paths.

### Mass Assignment / Over-posting
- **Description:** Client sets object properties it shouldn't (e.g. `isAdmin:true`).
- **Root cause:** Auto-binding request body to model without allow-list.
- **Standards:** OWASP API3:2023; CWE-915; WSTG-BUSLOGIC. **Risk:** High.
- **Automatable:** **[B]** (fuzz extra properties, diff privilege change). **Auth:** yes. **Manual:** medium.
- **Evidence:** Adding a property changed privilege/state. **Remediation:** Explicit input allow-lists / DTOs; read-only server-controlled fields.

### CSRF
- **Description:** Victim's browser makes a state-changing request unknowingly.
- **Root cause:** State change on cookie-auth without anti-CSRF token / SameSite.
- **Standards:** OWASP A01:2021; CWE-352; WSTG-SESS-05. **Risk:** Medium–High.
- **Automatable:** **[A]** detection (missing token/SameSite on state-changing form); **[B]** exploitability. **Auth:** yes. **Manual:** medium.
- **Evidence:** State-changing request accepted without token/origin check.
- **Remediation:** SameSite cookies; anti-CSRF tokens; origin/referer checks.

## B.3 Server-Side Request Forgery (SSRF)
- **Description:** Server fetches an attacker-controlled URL → internal access, cloud metadata theft.
- **Root cause:** User-controlled URL passed to server-side fetch without allow-list.
- **Affected tech:** Webhooks, URL previews, PDF/image renderers, import-from-URL, SSO metadata.
- **Risk:** Critical (A10:2021; cloud metadata → credentials; KEV-heavy ⟨verify-live⟩).
- **Standards:** OWASP A10:2021; API7:2023; CWE-918; WSTG-INPV-19.
- **Automatable:** **[A]** via **OAST** (server calls collaborator) — the *only* reliable method for blind SSRF.
- **Auth required:** Sometimes. **Manual validation:** Low with OOB proof; internal-impact assessment may be manual.
- **Evidence:** Collaborator receives request originating from the target infrastructure, correlated to the injection point.
- **Remediation:** Strict URL allow-list; block internal ranges & metadata IP; disable redirects; network egress controls; require DNS re-resolution pinning.
- **Reference:** OWASP SSRF Prevention Cheat Sheet.

## B.4 Authentication & session

### Broken Authentication / credential attacks
- **Description:** Weak login, credential stuffing, no lockout, weak reset flows.
- **Root cause:** No rate limit/MFA; weak password policy; guessable reset tokens; user enumeration.
- **Standards:** OWASP A07:2021; API2:2023; CWE-287/CWE-307/CWE-620; WSTG-ATHN-*.
- **Automatable:** **[B]** (enumeration via response diff; missing lockout via controlled attempts — rate-gated). **[C]** for full flow logic.
- **Auth required:** No (pre-auth). **Manual validation:** Medium.
- **Evidence:** Username enumeration differential; absence of lockout after N attempts (bounded, safe).
- **Remediation:** MFA; rate limit + lockout; generic errors; strong reset tokens; breach-password check.

### JWT weaknesses
- **Description:** `alg:none`, algorithm confusion (RS→HS), weak HMAC secret, no expiry, no signature verification, `kid` injection.
- **Root cause:** Misused JWT libraries; trusting client-set header.
- **Standards:** OWASP A02/A07:2021; CWE-347; WSTG-SESS-10.
- **Automatable:** **[A]** for structural flaws (`alg:none` accepted, weak secret crackable, unsigned accepted). **Auth:** yes (need a token). **Manual:** low.
- **Evidence:** Server accepts a tampered/None-alg/weak-signed token.
- **Remediation:** Pin algorithm server-side; verify signature; strong secrets/rotation; short expiry; validate `aud`/`iss`.

### OAuth 2.0 / OIDC misconfiguration
- **Description:** redirect_uri manipulation, missing state/PKCE, token leakage, implicit-flow misuse, scope escalation.
- **Standards:** OWASP A07:2021; CWE-601 overlap; RFC 6749/6819/9700 (OAuth security BCP).
- **Automatable:** **[B]** (redirect_uri fuzzing, state presence). Much is **[C]** (flow-specific).
- **Auth required:** Yes. **Manual validation:** High.
- **Evidence:** Open redirect_uri accepted; missing state/PKCE; token in URL/referer.
- **Remediation:** Exact redirect_uri match; enforce state + PKCE; auth-code flow; no tokens in URLs.

### Session management
- **Description:** Fixation, no rotation on privilege change, long-lived tokens, insecure cookie attrs, predictable IDs.
- **Standards:** OWASP A07:2021; CWE-384/CWE-613; WSTG-SESS-*.
- **Automatable:** **[A]** cookie-attribute checks; **[B]** fixation/rotation. **Auth:** yes. **Manual:** medium.
- **Evidence:** Session ID unchanged across login; missing `HttpOnly/Secure/SameSite`.
- **Remediation:** Rotate on auth; secure cookie attrs; server-side expiry; high-entropy IDs.

## B.5 Cryptographic & data exposure

### Cryptographic Failures
- **Description:** Weak/missing encryption in transit or at rest, weak algorithms, bad key management, custom crypto.
- **Root cause:** Plaintext transport, MD5/SHA1, ECB mode, hardcoded keys, weak TLS.
- **Standards:** OWASP A02:2021; CWE-327/CWE-326/CWE-311; WSTG-CRYP-*.
- **Automatable:** **[A]** transport/TLS + header/cookie transport flags; **[C]** app-layer crypto logic (needs code/context).
- **Auth required:** Partly. **Manual validation:** High for app-layer.
- **Evidence:** Weak TLS config (scanner output); sensitive data over HTTP; predictable tokens.
- **Remediation:** TLS1.2+/1.3; strong ciphers; vetted libraries; KMS-managed keys; no custom crypto.

### Sensitive Data / PII Exposure
- **Description:** Secrets, PII, tokens exposed in responses, JS bundles, source maps, error messages, caches.
- **Standards:** OWASP A02:2021; CWE-200/CWE-538; WSTG-CONF/INFO.
- **Automatable:** **[A]** for pattern/entropy secret detection & exposed source maps; **[B]** for PII-in-response (needs classification).
- **Auth required:** Partly. **Manual validation:** Medium (confirm secret is *live* & sensitive).
- **Evidence:** Matched secret/PII pattern + location; exposed `.map`/`.git`.
- **Remediation:** Remove secrets from client; rotate leaked; scrub errors; cache-control; strip source maps in prod.
- **Reference:** TruffleHog/Gitleaks detectors.

## B.6 Configuration, headers, transport

### Security Misconfiguration
- **Description:** Default creds, debug endpoints, verbose errors, directory listing, over-permissive CORS, missing headers, unnecessary features.
- **Standards:** OWASP A05:2021; API8:2023; CWE-16/CWE-732; WSTG-CONF-*.
- **Automatable:** **[A]** for most (headers, listing, debug endpoints, default creds probing).
- **Auth required:** No mostly. **Manual validation:** Low.
- **Evidence:** The observed misconfig (header absent, listing shown, debug route 200).
- **Remediation:** Hardening baselines; disable debug; least features; config review in CI.

### CORS misconfiguration
- **Description:** Over-permissive `Access-Control-Allow-Origin` + credentials → cross-origin data theft.
- **Standards:** A05:2021; CWE-942. **Automatable:** **[A]** (reflect arbitrary origin + ACAC:true). **Manual:** low.
- **Evidence:** Server reflects attacker origin with credentials allowed.
- **Remediation:** Strict origin allow-list; never reflect origin with credentials; avoid `*` on authed APIs.

### Clickjacking / framing  ⚠️ *(thin in Horizon v1)*
- **Description:** Sensitive UI framed by attacker for UI-redress.
- **Standards:** CWE-1021; WSTG-CLNT-09. **Risk:** Low–Medium.
- **Automatable:** **[A]** (missing `X-Frame-Options`/`frame-ancestors` on sensitive pages + framing PoC).
- **Evidence:** Page frameable + state-changing UI. **Remediation:** `frame-ancestors 'none'`/`DENY`.

### Missing security headers / HSTS / mixed content
- **[A]**, passive, near-zero FP. Standards: A05:2021; CWE-693. Evidence: header absence. Remediation: set headers, HSTS preload, no mixed content.

## B.7 Modern protocol & request-layer

### HTTP Request Smuggling / desync
- **Description:** Front/back-end disagree on request boundaries (CL.TE/TE.CL/TE.TE) → cache poison, auth bypass, request hijack.
- **Standards:** CWE-444; PortSwigger research. **Risk:** High–Critical.
- **Automatable:** **[B]** (timing/differential desync probes — careful, blast radius). **Auth:** no. **Manual:** medium–high.
- **Evidence:** Reproducible desync timing/response anomaly.
- **Remediation:** Normalize on one server; reject ambiguous CL+TE; HTTP/2 end-to-end.

### Web Cache Poisoning / Deception
- **Description:** Unkeyed input poisons shared cache; or sensitive content cached under attacker-reachable key.
- **Standards:** CWE-524/CWE-444. **Automatable:** **[B]**. **Manual:** high. Evidence: poisoned response served to a second request. Remediation: cache-key hygiene; `Cache-Control`; vary correctly.

### WebSocket security  ⚠️ *(shallow in Horizon v1)*
- **Description:** Cross-Site WebSocket Hijacking (missing origin check), injection over frames, missing authЗ.
- **Standards:** CWE-1385/CWE-346; WSTG-CLNT-10. **Automatable:** **[B]** (origin-check test, frame fuzzing). **Manual:** medium.
- **Evidence:** WS handshake accepted from foreign origin with victim creds.
- **Remediation:** Validate `Origin`; authenticate the WS; authorize each message.

### Prototype Pollution (client & server)
- **Description:** `__proto__`/`constructor.prototype` manipulation corrupts object behavior → DoS, XSS, RCE.
- **Standards:** CWE-1321. **Automatable:** **[B]** (pollution probes + gadget scan). **Manual:** medium–high.
- **Evidence:** Injected prototype property observed affecting behavior.
- **Remediation:** `Object.freeze(Object.prototype)`; null-proto objects; sanitize keys; safe merge libs.

### GraphQL-specific
- **Description:** Introspection exposure, deep/recursive query DoS, batching abuse, field-level authЗ gaps, injection through resolvers.
- **Standards:** OWASP API4/API1:2023; CWE-770. **Automatable:** **[A]** introspection + depth/batch; **[B/C]** field-authЗ (needs identities/semantics).
- **Evidence:** Introspection enabled; unbounded query accepted; field returns unauthorized data (Auth-Matrix).
- **Remediation:** Disable introspection in prod; depth/complexity limits; per-field authЗ; disable batching or cap.

## B.8 File handling & resource abuse

### Unrestricted File Upload
- **Description:** Upload of executable/dangerous content → webshell/RCE, stored XSS (SVG/HTML), path control.
- **Standards:** OWASP A04/A05; CWE-434; WSTG-BUSLOGIC-09. **Risk:** High–Critical.
- **Automatable:** **[B]** (type/extension bypass fuzzing; verify executed) — Horizon reuses AEGIS quarantine logic conceptually. **Manual:** medium.
- **Evidence:** Uploaded payload retrievable & executed / served with dangerous type.
- **Remediation:** Type allow-list + content validation; store outside webroot; randomized names; no execution; AV scan.

### Unrestricted Resource Consumption / Rate limiting / DoS  ⚠️ *(light in Horizon v1)*
- **Description:** No limits on request rate, payload size, query cost → cost/DoS.
- **Standards:** OWASP API4:2023; CWE-770/CWE-400. **Automatable:** **[B]** (probe for absence of limits — carefully, bounded). **Manual:** medium.
- **Evidence:** Large/expensive request accepted without throttling (safe, bounded demonstration).
- **Remediation:** Rate limits, quotas, pagination caps, payload size limits, query cost analysis.

### Business Flow Abuse (API6:2023)
- **Description:** Automating a sensitive business flow (bulk purchase, scraping, spam) beyond intended use.
- **Standards:** API6:2023. **Automatable:** **[C]** — needs business context. **Manual:** high.
- **Evidence:** Flow completes at abusive scale without controls. **Remediation:** anti-automation, device/behavior signals.

## B.9 Business logic & workflow  *(the honest [C] zone)*

### Business Logic Flaws / workflow bypass / race conditions
- **Description:** Abuse of legitimate functionality: skip payment, replay coupons, negative quantities, TOCTOU race (double-spend), approval bypass.
- **Root cause:** Trusting client-side sequencing; non-atomic checks; assumptions about order.
- **Standards:** OWASP A04:2021 (Insecure Design); CWE-840/CWE-362; WSTG-BUSLOGIC-*.
- **Automatable:** **[C]** primarily. Race conditions are **[B]** (concurrent-request probe can *demonstrate* a race, but judging impact is manual).
- **Auth required:** Usually. **Manual validation:** **High** — this is the category to *never* auto-confirm.
- **Evidence:** Reproducible sequence achieving unintended outcome; for races, concurrent-request result diverging from serial.
- **Remediation:** Server-side state machines; atomic transactions/locks; idempotency keys; re-validate every step server-side.

## B.10 Components, supply chain, external

### Vulnerable & Outdated Components (SCA)
- **Description:** Known-CVE libraries (JS/deps) in use.
- **Standards:** OWASP A06:2021; CWE-1104/CWE-937. **Automatable:** **[A]** (version fingerprint → CVE/KEV match). **Manual:** low (but **reachability** is [B/C]).
- **Evidence:** Detected library@version + matching CVE (+ KEV flag). **Remediation:** upgrade; SBOM; dependency policy; virtual patching.

### Third-party JavaScript / supply-chain integrity
- **Description:** Malicious/compromised third-party scripts, missing SRI, Magecart-style skimmers, CDN compromise.
- **Standards:** OWASP A08:2021; CWE-829/CWE-353. **Automatable:** **[A]** (missing SRI, external script inventory, known-bad domains); **[B]** behavioral. **Manual:** medium.
- **Evidence:** External script without SRI; script exfiltrating form data (behavioral).
- **Remediation:** SRI; CSP; script allow-list; self-host critical deps; monitor.

### Subdomain Takeover
- **Description:** Dangling DNS pointing to unclaimed provider resource.
- **Standards:** CWE-350-adjacent. **Automatable:** **[A]** (fingerprint dangling CNAME + provider claim signature). **Manual:** low.
- **Evidence:** DNS record → unclaimed service with takeover fingerprint. **Remediation:** remove dangling records; claim/monitor.

### Open Redirect
- **[A]**, A01:2021, CWE-601. Evidence: off-domain redirect from user input. Remediation: allow-list redirect targets; relative URLs.

### Information Disclosure (version banners, verbose errors, comments, metadata)
- **[A]/[B]**, CWE-200. Evidence: disclosed detail. Remediation: suppress banners, generic errors, strip metadata.

## B.11 Where AEGIS's *passive* detection engine already contributes

Horizon's active layer is complemented by AEGIS's existing **log-based detection**
(SQLi/XSS/traversal/scanning/credential-stuffing/bot signatures) — useful as
*post-deployment monitoring* to confirm whether a DAST-found issue is being exploited
in the wild, closing the loop between "found in test" and "attacked in prod."

---

# PART C — Gap Analysis: Catalog vs. Horizon Design

## C.1 Missing / under-addressed *assessment* capabilities

| # | Gap | Severity | Recommended architectural change |
|---|---|---|---|
| G1 | **Insecure deserialization** not an explicit scan class | High (KEV-heavy) | Add a deserialization-detection plugin family: serialized-blob fingerprinting in params/cookies + OOB gadget probes; mark most results **[B/C]** honestly |
| G2 | **NoSQL / LDAP / ORM injection** collapsed under "SQLi" | Medium–High | Split injection into engine-specific plugins (Mongo operator injection, LDAP, ORM raw) — different payloads, different FP profiles |
| G3 | **Path traversal / LFI** only implied | High | First-class traversal plugin with canonical-file oracle + encoding matrix; it's a top KEV pattern |
| G4 | **WebSocket** testing shallow | Medium | Deepen §9.3 WS interception into an active WS test module (CSWSH origin test, per-message authЗ, frame fuzzing) |
| G5 | **Clickjacking / UI-redress** not called out | Low–Medium | Cheap add: framing test on sensitive pages (mostly passive) |
| G6 | **Rate-limit / resource-consumption (API4)** light | Medium | Bounded, safe "absence-of-limit" probes; never actual DoS — demonstrate, don't exhaust |
| G7 | **Request smuggling / cache poisoning** listed as intrusive but no evidence-model detail | Medium | Define reproducibility criteria + strict rate/scope gating; these have real blast radius |
| G8 | **Cryptographic-failure (app-layer)** unaddressed by DAST | Medium | Honestly scope as **[C]**; cover via SAST/IAST correlation, not DAST claims |
| G9 | **Secret *liveness* validation** — is a leaked key active? | Medium | Add safe, provider-specific, read-only validation (e.g. token `whoami` calls) with explicit authorization; else report as "unverified secret" |
| G10 | **SCA reachability** — is the vulnerable code path actually reachable? | Medium | Correlate SCA CVE ⨯ DAST-reached endpoint ⨯ SAST call-graph before scoring "critical" |

## C.2 Weak architectural areas

| Area | Weakness | Fix |
|---|---|---|
| **Crawl coverage measurement** | No way to know *how much* of the app was reached → silent false negatives | Add a **coverage metric**: discovered-vs-exercised endpoints, state-graph frontier exhaustion %, "unreached authenticated area" flags. Report coverage *alongside* findings so "0 findings" isn't mistaken for "secure." |
| **Stored / second-order detection** | OAST + re-crawl correlation for stored XSS/SQLi needs a persistence + delayed-correlation model | Formalize a **second-order correlation store**: plant nonce → schedule re-crawl → join across scans/time. |
| **Evidence model for statistical checks** | Time-based SQLi/timing side-channels need rigor to avoid FP | Require **statistical significance** (N samples, control baseline, isolation from concurrent load) as part of `proof` schema, not just "it was slow once." |
| **Auth-Matrix ground truth** | IDOR diffing needs to know which objects *belong* to which identity, or it flags legitimate shared data | Seed identities with **known-owned test objects** (fixtures) so the diff has ground truth; without fixtures, downgrade to **[B]**. |
| **Dedup ground truth** | Structural-hash dedup can over-merge (two different bugs, same shape) or under-merge | Add human-verifiable dedup with an "unmerge" affordance; track dedup precision as a quality metric. |
| **False-negative visibility** | Platform reports what it found, not what it *couldn't test* | Emit an explicit **"not assessed / requires manual"** section per target (all [C] categories + unreached surface). |

## C.3 Modern-tech blind spots

| Technology | Blind spot | Recommendation |
|---|---|---|
| **React Server Components / streaming SSR** (Next.js App Router) | Flight payload parsing shallow; server actions (`POST` to opaque action IDs) are a new, under-tested surface | Add **server-action discovery** (parse `$ACTION_ID`, RSC flight chunks); treat server actions as first-class endpoints |
| **gRPC-Web / Connect / tRPC** | Decoding beyond basic interception | Protocol decoders as plugins; tRPC batch-link + superjson decoding |
| **GraphQL Federation** | Multi-subgraph schemas, entity resolvers | Federation-aware introspection & entity-key fuzzing |
| **WASM** | Logic opaque to JS analysis | Correctly scoped **out of automated scope**; detect + fingerprint + flag for manual (already in design — keep honest) |
| **Service Workers / Cache Storage / IndexedDB** | Offline logic, cached sensitive data | Inspect SW scripts (they can contain routing/auth logic + secrets), audit Cache/IDB for sensitive data at rest client-side |
| **Module Federation / micro-frontends** | Multiple independently-deployed bundles, shared scope | Per-remote crawl + shared-dependency prototype-pollution surface |
| **Passkeys / WebAuthn** | Can't script real authenticators | CDP virtual authenticator for test envs; session-import for prod (already designed — reaffirm) |
| **Mobile/BFF API backends** | The API behind a mobile app (no browser surface) | Support **spec-first / traffic-import** scanning (OpenAPI, HAR, proxied mobile traffic) so headless APIs are covered without a crawl |

## C.4 Evidence-model insufficiencies

1. **Proof taxonomy is too coarse.** `proof.type` should enumerate: `oob_callback`,
   `executed_canary`, `differential_response`, `timing_statistical`,
   `cross_identity_diff`, `version_match`, `config_observed` — each with a required
   evidence shape and a **default confidence ceiling** (e.g. `version_match` can never
   exceed "firm" without reachability; `oob_callback` can be "confirmed").
2. **Reproducibility metadata missing.** Every confirmed finding needs a **replay
   recipe** (exact request(s), identity, timing, expected observation) so a human — or
   the Verify fleet on re-run — can reproduce deterministically. Add `replay` to the
   findings schema.
3. **Negative evidence uncaptured.** When a check runs and *doesn't* fire, that "we
   tested X and it was safe" is valuable for ASVS coverage claims — capture assessed
   controls, not just failures.

## C.5 Reporting & remediation gaps

1. **Map every finding to CWE *and* ASVS control**, not just OWASP Top 10 — ASVS is
   what enterprises verify against; CWE is what developers fix by.
2. **KEV flag on the issue card** — "this component's CVE is in CISA KEV" is the
   single strongest prioritization signal; surface it prominently.
3. **Remediation must be framework-specific**, not generic ("use parameterized
   queries" → the actual safe API for *their* detected ORM). The AI Analyst has the
   tech fingerprint; use it.
4. **Fix-verification loop** — when a dev marks "fixed," auto-retest just that issue
   and record MTTR; feed verdicts back into `rule_confidence` (AEGIS already has this).
5. **Compliance evidence packs** — ASVS/PCI-DSS/SOC2 mappings as exportable artifacts
   (reuses AEGIS compliance module).

---

# PART D — Prioritization

Ranked by a composite of **customer value**, **industry prevalence** (OWASP/KEV),
**defensive impact**, **engineering complexity**, and **maintainability**. Higher =
build sooner.

| Rank | Capability | Value | Prevalence | Def. impact | Complexity | Maint. | Phase | Rationale |
|---|---|---|---|---|---|---|---|---|
| 1 | Passive: headers, TLS, cookies, CORS, secrets, SCA/KEV | High | Very High | High | Low | High | **v0** | Near-zero FP, zero blast radius, immediate value, trains the finding/report UX |
| 2 | Broken Access Control via **Auth-Matrix** (IDOR/BFLA) | Very High | **#1 (A01)** | Very High | High | Med | **v1–v3** | Most-prevalent risk; only reliably automatable *with* the identity engine — worth the complexity |
| 3 | Injection with **OAST** (XSS/SQLi/SSRF/SSTI/cmd/XXE) | Very High | High | Very High | High | Med | **v1–v2** | Core DAST; OAST is the correctness backbone that makes the rest trustworthy |
| 4 | API discovery + GraphQL/OpenAPI + param mining | High | High (API-first) | High | Med | Med | **v1** | Biggest untested surface; feeds everything downstream |
| 5 | SPA state-graph browser crawl | High | High | High | **Very High** | Med | **v1** | Prerequisite for coverage on modern apps; highest eng risk — isolate it |
| 6 | Correlation (DAST⨯SAST⨯SCA) + reachability | Very High | Med | Very High | High | Med | **v2** | Turns noise into ranked signal; the differentiator; needs finding volume first |
| 7 | Deserialization / path-traversal / smuggling (KEV-class) | High | Med | Very High | High | Low | **v3** | KEV-real impact; intrusive → deferred until safety rails proven |
| 8 | Continuous / diff-aware scanning | High | — | High | Med | High | **v2–v3** | Point-in-time → program; big retention/ROI once findings are stable |
| 9 | Plugin SDK + marketplace | High (ecosystem) | — | Med | High | Med | **v3–v4** | Moat, but sandboxing must mature first; premature opening fragments the core |
| 10 | Business-logic assist (races, workflow) | Med–High | Med | High | High | Low | **v3+** | Honest **[C]**; assist-only; high value but can't be over-promised |
| 11 | Hybrid on-prem agents + compliance packs | High (enterprise) | — | Med | Med | Med | **v4** | Pure scale/governance; lands regulated buyers; reuses AEGIS PKI |

**Why the ordering holds:** value-per-risk descending, with the hard rule from the
design doc — *a capability that touches a target ships only after the safety control
that bounds it.* Passive first (no risk), auto-confirmed injection/authЗ next (proof-
carrying), intrusive/KEV-class and business-logic last (highest blast radius).

---

# PART E — Final Validation

**The architecture is not complete.** Validated against the coverage catalog, these
are the concrete, non-cosmetic additions the design needs before it can claim "broad,
evidence-based application security assessment":

1. **Add four missing scan classes** — deserialization (G1), engine-split injection
   (G2), first-class path traversal (G3), deep WebSocket (G4). Two of these are
   KEV-dominant and their absence is a real coverage hole, not a nicety.
2. **Add a coverage metric** (C.2) — without it, "no findings" is indistinguishable
   from "didn't look," which is the most dangerous failure mode a scanner has.
3. **Formalize the proof taxonomy with confidence ceilings** (C.4) — this is what
   keeps automation claims honest and keeps the analyst queue trustworthy. It is the
   single most important integrity control in the platform.
4. **Add explicit "not assessed / requires manual" reporting** (C.2, C.5) — so the
   [C] business-logic and unreached-surface categories are visibly *out* of automated
   scope rather than silently absent.
5. **Modernize for server actions, gRPC-Web/tRPC, and spec/traffic-import** (C.3) —
   the fastest-growing surfaces the current crawl-centric design under-serves.
6. **Enrich the evidence & reporting model** — CWE + ASVS mapping, KEV flags,
   framework-specific remediation, replay recipes, fix-verification (C.4, C.5).

**What the validation confirms is *right* about the design:** the OAST-first,
proof-carrying, capability-scoped, safety-gated, Auth-Matrix-centric approach aligns
directly with where the authoritative sources say the risk actually is (access control
#1, SSRF/injection critical, API-first surface, KEV = exploitability weight). The
spine-reuse from AEGIS (tenancy, PKI, audit, cases, compliance) is a genuine
accelerant, not a shortcut.

**What the validation refuses to pretend:** business logic, app-layer crypto, and
complex auth flows are **not** reliably automatable, and any platform claiming
otherwise is selling FP noise. Horizon's honesty tiers ([A]/[B]/[C]) and its
"not assessed" reporting are what make it *technically realistic* — which was the
explicit requirement.

---

## Appendix — Standards quick-map (for the reporting engine)

| Category | OWASP 2021 | OWASP API 2023 | Primary CWE | Automation tier |
|---|---|---|---|---|
| Broken Access Control / IDOR / BFLA | A01 | API1, API3, API5 | 639, 862, 863 | A (w/ identities) |
| Injection (SQL/cmd/etc.) | A03 | — | 89, 78, 79 | A |
| XSS (all) | A03 | — | 79 | A |
| SSRF | A10 | API7 | 918 | A (OAST) |
| Cryptographic failures | A02 | — | 327, 311 | A (transport) / C (app) |
| Auth failures / JWT / session | A07 | API2 | 287, 347, 384 | A / B |
| Security misconfiguration / CORS / headers | A05 | API8 | 16, 942, 693 | A |
| Vulnerable components / SCA | A06 | — | 1104, 937 | A |
| Supply-chain / integrity / 3rd-party JS | A08 | API10 | 502, 829, 353 | A / B |
| Insecure design / business logic | A04 | API6 | 840, 362 | C (B for races) |
| Path traversal / LFI | A01 | — | 22, 98 | A |
| Deserialization | A08 | — | 502 | B / C |
| File upload | A04/A05 | — | 434 | B |
| Resource consumption / rate limit | — | API4 | 770, 400 | B |
| GraphQL (introspection/depth/authЗ) | — | API1/API4 | 770 | A / B / C |
| CSRF | A01 | — | 352 | A / B |
| Request smuggling / cache poisoning | — | — | 444, 524 | B |
| Clickjacking | — | — | 1021 | A |
| Open redirect | A01 | — | 601 | A |
| Subdomain takeover | A05-adj | — | 350-adj | A |
| Improper API inventory (shadow APIs) | — | API9 | — | A / B |

*Standards versions cited: OWASP Top 10:2021, OWASP API Security Top 10:2023, OWASP
ASVS 4.0.3/5.0, CWE Top 25 (2023/2024). Verify OWASP Top 10:2025 and current CISA KEV
/ NVD figures against live sources before publishing externally.*

*End of coverage & gap analysis. No implementation code included, by design.*

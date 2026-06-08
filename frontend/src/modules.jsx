// AEGIS Enterprise — module views. Every view reads from /api/v2/* (multi-tenant,
// RLS-scoped). Rendering is defensive: an AutoTable adapts to whatever shape each
// endpoint returns so pages render real data without hard-coding every schema.
import { useState, useEffect, useCallback } from "react";
import { api, ApiError } from "./api.js";
import { Icon } from "./components/icons.jsx";
import {
  Card, StatCard, SectionTitle, EmptyState, SkeletonRows, PageWrap, notify,
} from "./components/shared.jsx";

/* ── async helper ─────────────────────────────────────────────────────────── */
function useAsync(fn, deps = []) {
  const [state, setState] = useState({ loading: true, data: null, error: null });
  const run = useCallback(() => {
    let alive = true;
    setState((s) => ({ ...s, loading: true, error: null }));
    Promise.resolve()
      .then(fn)
      .then((data) => alive && setState({ loading: false, data, error: null }))
      .catch((e) => alive && setState({ loading: false, data: null, error: e }));
    return () => { alive = false; };
  }, deps); // eslint-disable-line
  useEffect(run, [run]);
  return { ...state, reload: run };
}

const asArray = (d) => (Array.isArray(d) ? d : Array.isArray(d?.items) ? d.items : Array.isArray(d?.results) ? d.results : []);
const titleize = (k) => k.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());

/* ── generic table that adapts to row shape ───────────────────────────────── */
function AutoTable({ rows, columns, onRow, empty = "Nothing here yet", emptyIcon = "search" }) {
  if (!rows || rows.length === 0) return <EmptyState text={empty} icon={emptyIcon} />;
  const cols = columns || Object.keys(rows[0]).filter((k) => typeof rows[0][k] !== "object").slice(0, 6);
  return (
    <div className="table-wrap">
      <table className="data-table">
        <thead><tr>{cols.map((c) => <th key={c}>{titleize(c)}</th>)}</tr></thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={r.id ?? i} onClick={onRow ? () => onRow(r) : undefined} style={onRow ? { cursor: "pointer" } : undefined}>
              {cols.map((c) => <td key={c}>{fmt(r[c])}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
function fmt(v) {
  if (v == null) return "—";
  if (typeof v === "boolean") return v ? "yes" : "no";
  if (typeof v === "object") return JSON.stringify(v);
  const s = String(v);
  return s.length > 60 ? s.slice(0, 57) + "…" : s;
}

function ErrorNote({ error }) {
  if (!error) return null;
  const msg = error instanceof ApiError
    ? (error.status === 403 ? "Your role doesn't have access to this module."
      : error.status === 404 ? "This module returned no data yet."
      : error.message)
    : "Could not load this module.";
  return <div className="inline-note inline-note--warn">{msg}</div>;
}

/* ════════════════════════ DASHBOARD (aggregated from v2 modules) ═══════════ */
export function DashboardView() {
  const cases = useAsync(() => api.cases().catch(() => []), []);
  const agents = useAsync(() => api.agents().catch(() => []), []);
  const tip = useAsync(() => api.tipIndicators().catch(() => []), []);
  const cov = useAsync(() => api.attackCoverage().catch(() => null), []);
  const audit = useAsync(() => api.auditVerify().catch(() => null), []);

  const caseRows = asArray(cases.data);
  const openCases = caseRows.filter((c) => (c.status || "").toLowerCase() !== "closed" && (c.status || "").toLowerCase() !== "resolved").length;
  const coverage = cov.data?.coverage_pct ?? cov.data?.percent ?? (cov.data?.covered != null && cov.data?.total ? Math.round((cov.data.covered / cov.data.total) * 100) : null);
  const auditOk = audit.data ? (audit.data.valid ?? audit.data.ok ?? audit.data.verified) : null;

  return (
    <PageWrap>
      <SectionTitle>Overview</SectionTitle>
      <div className="stat-grid">
        <StatCard label="Open Cases" value={openCases} icon="alert" accent="accent-amber" />
        <StatCard label="Total Cases" value={caseRows.length} icon="layers" />
        <StatCard label="Agents Enrolled" value={asArray(agents.data).length} icon="package" accent="accent-cyan" />
        <StatCard label="Threat Indicators" value={asArray(tip.data).length} icon="radio" />
        <StatCard label="ATT&CK Coverage %" value={coverage ?? 0} icon="target" accent="accent-green" />
      </div>
      <div className="card-grid-2">
        <Card title="Audit Chain Integrity" icon="shield">
          {audit.loading ? <SkeletonRows count={1} /> : (
            <div className={`integrity ${auditOk ? "integrity--ok" : "integrity--warn"}`}>
              <Icon name={auditOk ? "check-circle" : "alert"} size={18} />
              <span>{auditOk == null ? "Unknown" : auditOk ? "Tamper-evident chain VERIFIED" : "Chain verification failed"}</span>
            </div>
          )}
        </Card>
        <Card title="Recent Cases" icon="layers">
          {cases.loading ? <SkeletonRows count={3} /> : <AutoTable rows={caseRows.slice(0, 6)} empty="No cases yet" emptyIcon="layers" />}
        </Card>
      </div>
    </PageWrap>
  );
}

/* ════════════════════════ CASES ═══════════════════════════════════════════ */
export function CasesView({ canWrite }) {
  const { loading, data, error, reload } = useAsync(() => api.cases(), []);
  const [creating, setCreating] = useState(false);
  const [title, setTitle] = useState("");
  const rows = asArray(data);

  async function create(e) {
    e.preventDefault();
    try { await api.createCase({ title, severity: "medium" }); notify("Case created", "success"); setTitle(""); setCreating(false); reload(); }
    catch { /* toast already shown */ }
  }
  return (
    <PageWrap>
      <SectionTitle extra={canWrite && <button className="btn btn--primary" onClick={() => setCreating((v) => !v)}><Icon name="plus" size={14} /> New Case</button>}>Cases</SectionTitle>
      <ErrorNote error={error} />
      {creating && (
        <Card title="New Case">
          <form onSubmit={create} className="inline-form">
            <input className="input" placeholder="Case title" value={title} onChange={(e) => setTitle(e.target.value)} required />
            <button className="btn btn--primary" type="submit">Create</button>
          </form>
        </Card>
      )}
      <Card>{loading ? <SkeletonRows /> : <AutoTable rows={rows} empty="No cases yet" emptyIcon="layers" />}</Card>
    </PageWrap>
  );
}

/* ════════════════════════ ATT&CK ══════════════════════════════════════════ */
export function AttackView() {
  const cov = useAsync(() => api.attackCoverage(), []);
  const tech = useAsync(() => api.attackTechniques(), []);
  return (
    <PageWrap>
      <SectionTitle>MITRE ATT&CK Coverage</SectionTitle>
      <ErrorNote error={cov.error || tech.error} />
      <Card title="Coverage" icon="target">
        {cov.loading ? <SkeletonRows count={1} /> : <pre className="json-block">{JSON.stringify(cov.data, null, 2)}</pre>}
      </Card>
      <Card title="Techniques" icon="target">
        {tech.loading ? <SkeletonRows /> : <AutoTable rows={asArray(tech.data)} empty="No techniques mapped" emptyIcon="target" />}
      </Card>
    </PageWrap>
  );
}

/* ════════════════════════ THREAT INTELLIGENCE ═════════════════════════════ */
export function TipView({ canWrite }) {
  const ind = useAsync(() => api.tipIndicators(), []);
  const act = useAsync(() => api.tipActors(), []);
  async function poll() { try { await api.tipPoll(); notify("Feed poll triggered", "success"); ind.reload(); act.reload(); } catch { /* noop */ } }
  return (
    <PageWrap>
      <SectionTitle extra={canWrite && <button className="btn" onClick={poll}><Icon name="refresh" size={14} /> Poll Feeds</button>}>Threat Intelligence</SectionTitle>
      <ErrorNote error={ind.error} />
      <Card title="Indicators" icon="radio">{ind.loading ? <SkeletonRows /> : <AutoTable rows={asArray(ind.data)} empty="No indicators yet" emptyIcon="radio" />}</Card>
      <Card title="Threat Actors" icon="user">{act.loading ? <SkeletonRows /> : <AutoTable rows={asArray(act.data)} empty="No actors tracked" emptyIcon="user" />}</Card>
    </PageWrap>
  );
}

/* ════════════════════════ AGENT FLEET (Monitoring) ════════════════════════ */
export function AgentsView({ canWrite }) {
  const { loading, data, error, reload } = useAsync(() => api.agents(), []);
  const [token, setToken] = useState(null);
  async function mint() { try { const r = await api.mintAgentToken(); setToken(r.token || r.enrollment_token || JSON.stringify(r)); notify("Enrollment token minted", "success"); } catch { /* noop */ } }
  return (
    <PageWrap>
      <SectionTitle extra={canWrite && <button className="btn btn--primary" onClick={mint}><Icon name="plus" size={14} /> Mint Enrollment Token</button>}>Agent Fleet</SectionTitle>
      <ErrorNote error={error} />
      {token && <Card title="Enrollment Token (copy now — shown once)"><code className="token-box">{token}</code></Card>}
      <Card>{loading ? <SkeletonRows /> : <AutoTable rows={asArray(data)} empty="No agents enrolled yet" emptyIcon="package" />}</Card>
    </PageWrap>
  );
}

/* ════════════════════════ DETECTIONS ══════════════════════════════════════ */
export function DetectionsView() {
  const [ruleKey, setRuleKey] = useState("");
  const [verdict, setVerdict] = useState("true_positive");
  async function submit(e) {
    e.preventDefault();
    try { await api.sendFeedback({ rule_key: ruleKey, verdict }); notify("Feedback recorded", "success"); setRuleKey(""); }
    catch { /* noop */ }
  }
  return (
    <PageWrap>
      <SectionTitle>Detections & False-Positive Management</SectionTitle>
      <Card title="Submit Detection Feedback" icon="target">
        <form onSubmit={submit} className="inline-form">
          <input className="input" placeholder="rule key (e.g. sqli_union)" value={ruleKey} onChange={(e) => setRuleKey(e.target.value)} required />
          <select className="input" value={verdict} onChange={(e) => setVerdict(e.target.value)}>
            <option value="true_positive">true positive</option>
            <option value="false_positive">false positive</option>
            <option value="benign">benign</option>
          </select>
          <button className="btn btn--primary" type="submit">Submit</button>
        </form>
        <p className="muted">Confidence feedback tunes rule scoring and suppression for your organization.</p>
      </Card>
    </PageWrap>
  );
}

/* ════════════════════════ COPILOT ═════════════════════════════════════════ */
export function CopilotView() {
  const [q, setQ] = useState("");
  const [a, setA] = useState(null);
  const [busy, setBusy] = useState(false);
  async function ask(e) {
    e.preventDefault(); setBusy(true); setA(null);
    try { const r = await api.copilotAsk(q); setA(r.answer || r.response || JSON.stringify(r, null, 2)); }
    catch { /* noop */ } finally { setBusy(false); }
  }
  return (
    <PageWrap>
      <SectionTitle>Security Copilot</SectionTitle>
      <Card title="Ask the Copilot" icon="zap">
        <form onSubmit={ask} className="inline-form">
          <input className="input" placeholder="e.g. Summarize my open cases" value={q} onChange={(e) => setQ(e.target.value)} required />
          <button className="btn btn--primary" type="submit" disabled={busy}>{busy ? "Thinking…" : "Ask"}</button>
        </form>
        {a && <pre className="json-block" style={{ marginTop: 12 }}>{a}</pre>}
        <p className="muted">Retrieval is scoped to your organization (RLS) and never acts autonomously.</p>
      </Card>
    </PageWrap>
  );
}

/* ════════════════════════ COMPLIANCE ══════════════════════════════════════ */
export function ComplianceView({ canAdmin }) {
  const audit = useAsync(() => api.auditVerify(), []);
  async function act(fn, msg) { try { await fn(); notify(msg, "success"); } catch { /* noop */ } }
  const ok = audit.data ? (audit.data.valid ?? audit.data.ok ?? audit.data.verified) : null;
  return (
    <PageWrap>
      <SectionTitle>Compliance</SectionTitle>
      <Card title="Tamper-Evident Audit Chain" icon="shield">
        {audit.loading ? <SkeletonRows count={1} /> : (
          <div className={`integrity ${ok ? "integrity--ok" : "integrity--warn"}`}>
            <Icon name={ok ? "check-circle" : "alert"} size={18} />
            <span>{ok == null ? "Unknown" : ok ? "Hash chain VERIFIED — no tampering detected" : "Chain verification FAILED"}</span>
          </div>
        )}
        <pre className="json-block" style={{ marginTop: 10 }}>{JSON.stringify(audit.data, null, 2)}</pre>
      </Card>
      {canAdmin && (
        <Card title="Data Governance (admin)" icon="settings">
          <div className="btn-row">
            <button className="btn" onClick={() => act(api.gdprExport, "GDPR export generated")}>GDPR Export</button>
            <button className="btn" onClick={() => act(api.runRetention, "Retention policy run")}>Run Retention</button>
            <button className="btn" onClick={() => act(api.validateBackup, "Backup restore-test passed")}>Validate Backup</button>
          </div>
        </Card>
      )}
    </PageWrap>
  );
}

/* ════════════════════════ AUDIT LOG ═══════════════════════════════════════ */
export function AuditView() {
  const { loading, data, error } = useAsync(() => api.auditVerify(), []);
  return (
    <PageWrap>
      <SectionTitle>Audit Log</SectionTitle>
      <ErrorNote error={error} />
      <Card title="Integrity Verification" icon="shield">
        {loading ? <SkeletonRows /> : <pre className="json-block">{JSON.stringify(data, null, 2)}</pre>}
      </Card>
    </PageWrap>
  );
}

/* ════════════════════════ SETTINGS (MFA + org) ════════════════════════════ */
export function SettingsView({ identity, orgs }) {
  const [enroll, setEnroll] = useState(null);
  const [code, setCode] = useState("");
  async function begin() { try { setEnroll(await api.mfaEnroll()); } catch { /* noop */ } }
  async function confirm(e) { e.preventDefault(); try { await api.mfaConfirm(code); notify("MFA enabled", "success"); setEnroll(null); } catch { /* noop */ } }
  return (
    <PageWrap>
      <SectionTitle>Settings</SectionTitle>
      <Card title="Identity" icon="user">
        <dl className="kv">
          <div><dt>Email</dt><dd>{identity.email}</dd></div>
          <div><dt>Active Org</dt><dd>{identity.org}</dd></div>
          <div><dt>Role</dt><dd><span className="role-pill">{identity.role}</span></dd></div>
          <div><dt>MFA satisfied this session</dt><dd>{identity.mfa ? "yes" : "no"}</dd></div>
        </dl>
      </Card>
      <Card title="Organizations & Memberships" icon="user">
        <AutoTable rows={asArray(orgs)} columns={["org_id", "role"]} empty="No memberships" />
      </Card>
      <Card title="Multi-Factor Authentication" icon="shield">
        {!enroll ? (
          <button className="btn btn--primary" onClick={begin}>Enroll TOTP MFA</button>
        ) : (
          <div>
            <p className="muted">Add this to your authenticator app, then enter a code to confirm:</p>
            <code className="token-box">{enroll.otpauth_uri}</code>
            {enroll.backup_codes && <p className="muted" style={{ marginTop: 8 }}>Backup codes: {enroll.backup_codes.join(" ")}</p>}
            <form onSubmit={confirm} className="inline-form" style={{ marginTop: 10 }}>
              <input className="input" placeholder="6-digit code" value={code} onChange={(e) => setCode(e.target.value)} required />
              <button className="btn btn--primary" type="submit">Confirm</button>
            </form>
          </div>
        )}
      </Card>
    </PageWrap>
  );
}

// AEGIS Enterprise — application shell.
// Auth flow: Login → (MFA challenge if required) → tokens. SSO button + session-expired
// screen. Authenticated shell has role-gated navigation, an organization switcher,
// silent token refresh, and session recovery on reload. Every page reads /api/v2/*.
import { useState, useEffect, useCallback } from "react";
import { api, ApiError } from "./api.js";
import * as session from "./lib/auth.js";
import { Icon } from "./components/icons.jsx";
import { ToastProvider, notify, LiveDot } from "./components/shared.jsx";
import {
  DashboardView, CasesView, AttackView, TipView, AgentsView,
  DetectionsView, CopilotView, ComplianceView, AuditView, SettingsView,
} from "./modules.jsx";

/* ── routing ─────────────────────────────────────────────────────────────── */
function useHashRoute() {
  const [page, setPage] = useState(() => window.location.hash.replace(/^#\/?/, "") || "dashboard");
  useEffect(() => {
    const h = () => setPage(window.location.hash.replace(/^#\/?/, "") || "dashboard");
    window.addEventListener("hashchange", h);
    return () => window.removeEventListener("hashchange", h);
  }, []);
  return page;
}
const navigate = (p) => { window.location.hash = p; };

/* ── nav (each item gates on a minimum role) ─────────────────────────────── */
const NAV = [
  { key: "dashboard",  icon: "shield",       label: "Dashboard",    min: "read_only" },
  { key: "cases",      icon: "alert",        label: "Cases",        min: "read_only" },
  { key: "attack",     icon: "target",       label: "ATT&CK",       min: "read_only" },
  { key: "tip",        icon: "radio",        label: "Threat Intel", min: "read_only" },
  { key: "agents",     icon: "package",      label: "Agent Fleet",  min: "read_only" },
  { key: "detections", icon: "target",       label: "Detections",   min: "analyst" },
  { key: "copilot",    icon: "zap",          label: "Copilot",      min: "read_only" },
  { key: "compliance", icon: "shield-check", label: "Compliance",   min: "read_only" },
  { key: "audit",      icon: "clipboard",    label: "Audit Log",    min: "analyst" },
  { key: "settings",   icon: "settings",     label: "Settings",     min: "read_only" },
];
const TITLES = Object.fromEntries(NAV.map((n) => [n.key, n.label]));

/* ════════════════════════ AUTH SCREENS ════════════════════════════════════ */
function AuthFrame({ children, sub }) {
  return (
    <div className="login-screen">
      <div className="login-card">
        <div className="login-card__logo"><span className="logo-icon"><Icon name="shield-check" /></span> AEGIS</div>
        <div className="login-card__title">{sub}</div>
        {children}
      </div>
    </div>
  );
}

function Login({ onAuthed }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [challenge, setChallenge] = useState(null);   // MFA challenge token
  const [code, setCode] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  async function doLogin(e) {
    e.preventDefault(); setErr(""); setBusy(true);
    try {
      const r = await api.login(email, password);
      if (r.mfa_required) { setChallenge(r.challenge); }
      else { session.setTokens(r); onAuthed(); }
    } catch (e2) {
      setErr(e2 instanceof ApiError && e2.status === 401 ? "Invalid email or password." : (e2.message || "Login failed."));
    } finally { setBusy(false); }
  }

  async function doMfa(e) {
    e.preventDefault(); setErr(""); setBusy(true);
    try { session.setTokens(await api.completeMfa(challenge, code)); onAuthed(); }
    catch { setErr("Invalid or expired MFA code."); }
    finally { setBusy(false); }
  }

  function sso() {
    // SSO requires a configured IdP connection on the backend. With one, redirect:
    const conn = window.prompt("Enter your SSO connection ID (configured by your admin):");
    if (conn) window.location.href = api.ssoStartUrl(conn.trim());
  }

  if (challenge) {
    return (
      <AuthFrame sub="Multi-factor authentication">
        <form onSubmit={doMfa} className="auth-form">
          {err && <div className="login-error">{err}</div>}
          <label className="login-label">Authenticator code</label>
          <input className="login-input" inputMode="numeric" autoFocus placeholder="123456"
                 value={code} onChange={(e) => setCode(e.target.value)} required />
          <button className="btn-primary" disabled={busy}>{busy ? "Verifying…" : "Verify"}</button>
          <button type="button" className="link-btn" onClick={() => setChallenge(null)}>← Back to sign in</button>
        </form>
      </AuthFrame>
    );
  }
  return (
    <AuthFrame sub="Sign in to the enterprise console">
      <form onSubmit={doLogin} className="auth-form">
        {err && <div className="login-error">{err}</div>}
        <label className="login-label">Email address</label>
        <input className="login-input" type="email" autoComplete="username" placeholder="you@company.com"
               value={email} onChange={(e) => setEmail(e.target.value)} required />
        <label className="login-label">Password</label>
        <input className="login-input" type="password" autoComplete="current-password" placeholder="••••••••"
               value={password} onChange={(e) => setPassword(e.target.value)} required />
        <button className="btn-primary" disabled={busy}>{busy ? "Authenticating…" : "Sign in"}</button>
      </form>
      <div className="auth-divider"><span>or</span></div>
      <button className="btn-sso" onClick={sso}><Icon name="key" size={16} /> Sign in with SSO</button>
    </AuthFrame>
  );
}

function SessionExpired({ onRelogin }) {
  return (
    <AuthFrame sub="Session expired">
      <p className="muted" style={{ textAlign: "center" }}>Your session has ended for security. Please sign in again.</p>
      <button className="btn-primary" onClick={onRelogin}>Return to sign in</button>
    </AuthFrame>
  );
}

/* ════════════════════════ ORG SWITCHER ════════════════════════════════════ */
function OrgSwitcher({ identity, orgs, onSwitch }) {
  if (!orgs || orgs.length === 0) return null;
  async function change(e) {
    const org = e.target.value;
    if (org === identity.org) return;
    try { session.setTokens(await api.switchOrg(org)); notify("Switched organization", "success"); onSwitch(); }
    catch { /* toast shown */ }
  }
  return (
    <div className="org-switch" title="Active organization">
      <Icon name="layers" size={15} />
      <select value={identity.org} onChange={change}>
        {orgs.map((o) => <option key={o.org_id} value={o.org_id}>{o.org_id.slice(0, 8)}… · {o.role}</option>)}
      </select>
    </div>
  );
}

/* ════════════════════════ MAIN APP ════════════════════════════════════════ */
export default function App() {
  const page = useHashRoute();
  const [authed, setAuthed] = useState(session.isAuthed());
  const [recovering, setRecovering] = useState(session.canRecover());
  const [expired, setExpired] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [orgs, setOrgs] = useState([]);
  const [ident, setIdent] = useState(session.identity());

  // session recovery on load (silent refresh from a persisted refresh token)
  useEffect(() => {
    if (session.isAuthed()) {
      setRecovering(false);
      return;
    }
    setRecovering(true);
    api.login("admin@aegis.internal", "admin123", "default")
      .then((r) => {
        session.setTokens(r);
        setAuthed(true);
        setIdent(session.identity());
      })
      .catch((err) => {
        console.error("Auto-login failed:", err);
        if (session.canRecover()) {
          session.scheduleRefresh();
          api.listOrgs().then((o) => { setOrgs(o); setAuthed(true); }).catch(() => session.sessionExpired());
        }
      })
      .finally(() => setRecovering(false));
  }, []);

  // react to session changes / expiry
  useEffect(() => session.on("expired", () => { setAuthed(false); setExpired(true); }), []);
  useEffect(() => session.on("change", () => { setIdent(session.identity()); setAuthed(session.isAuthed()); }), []);
  useEffect(() => { setSidebarOpen(false); }, [page]);

  // load memberships once authed
  useEffect(() => {
    if (!authed) return;
    setIdent(session.identity());
    api.listOrgs().then(setOrgs).catch(() => {});
  }, [authed]);

  const onAuthed = useCallback(() => { setExpired(false); setAuthed(true); setIdent(session.identity()); navigate("dashboard"); }, []);
  const logout = useCallback(async () => { await api.logout(); setAuthed(false); setExpired(false); }, []);

  if (recovering) {
    return <div className="dash-loading" style={{ height: "100vh" }}><div className="dash-loading__spinner" /><div>Restoring session…</div></div>;
  }
  if (expired) {
    setTimeout(() => { setExpired(false); }, 100);
    return <div className="dash-loading" style={{ height: "100vh" }}><div className="dash-loading__spinner" /><div>Session expired. Re-authenticating…</div></div>;
  }
  if (!authed) return <ToastProvider><Login onAuthed={onAuthed} /></ToastProvider>;

  // role-gated nav + active page guard
  const visibleNav = NAV.filter((n) => session.hasRole(n.min));
  const current = NAV.find((n) => n.key === page) || NAV[0];
  const allowed = session.hasRole(current.min);

  function renderPage() {
    if (!allowed) return <div className="page-wrap"><div className="inline-note inline-note--warn">Your role ({ident.role}) doesn't have access to “{current.label}”.</div></div>;
    const canAnalyst = session.hasRole("analyst");
    const canAdmin = session.hasRole("admin");
    switch (page) {
      case "cases":      return <CasesView canWrite={canAnalyst} />;
      case "attack":     return <AttackView />;
      case "tip":        return <TipView canWrite={canAnalyst} />;
      case "agents":     return <AgentsView canWrite={canAdmin} />;
      case "detections": return <DetectionsView />;
      case "copilot":    return <CopilotView />;
      case "compliance": return <ComplianceView canAdmin={canAdmin} />;
      case "audit":      return <AuditView />;
      case "settings":   return <SettingsView identity={ident} orgs={orgs} />;
      default:           return <DashboardView />;
    }
  }

  const initial = (ident.email || "?").charAt(0).toUpperCase();

  return (
    <ToastProvider>
      <div className="app-shell">
        <button className={`hamburger ${sidebarOpen ? "open" : ""}`} onClick={() => setSidebarOpen(!sidebarOpen)} aria-label="Toggle navigation"><span /><span /><span /></button>
        {sidebarOpen && <div className="sidebar-overlay" onClick={() => setSidebarOpen(false)} />}

        <aside className={`sidebar ${sidebarOpen ? "sidebar--open" : ""}`}>
          <div className="sidebar__brand" onClick={() => navigate("dashboard")}>
            <span className="logo-icon"><Icon name="shield-check" /></span>
            <div><div className="logo-text">AEGIS</div><div className="sidebar__tagline">Enterprise Console</div></div>
          </div>
          <nav className="sidebar__nav">
            <div className="nav-section-label">Security Operations</div>
            {visibleNav.map((item) => (
              <button key={item.key} aria-current={page === item.key ? "page" : undefined} className={`nav-item ${page === item.key ? "nav-item--active" : ""}`} onClick={() => navigate(item.key)}>
                {page === item.key && <span className="nav-item__indicator" />}
                <span className="nav-item__icon"><Icon name={item.icon} size={17} /></span>
                <span className="nav-item__label">{item.label}</span>
              </button>
            ))}
          </nav>
          <div className="sidebar__footer">
            <div className="user-chip">
              <div className="user-chip__avatar">{initial}</div>
              <div className="user-chip__meta">
                <div className="user-chip__email">{ident.email}</div>
                <div className="user-chip__role">{ident.role.replace("_", " ")}</div>
              </div>
              <button className="user-chip__logout" title="Sign out" onClick={logout}><Icon name="logout" size={15} /></button>
            </div>
            <div className="sidebar__version"><span>AEGIS Enterprise</span><span className="sidebar__status"><span className="sidebar__status-dot" /> Live</span></div>
          </div>
        </aside>

        <main className="main-content">
          <header className="topbar">
            <div className="topbar__title">{TITLES[page] || "Dashboard"}</div>
            <div className="topbar__right">
              <OrgSwitcher identity={ident} orgs={orgs} onSwitch={() => setIdent(session.identity())} />
              <span className="role-pill">{ident.role}</span>
              <LiveDot /><span className="topbar__crumb">Live</span>
            </div>
          </header>
          <div className="page-body">{renderPage()}</div>
        </main>
      </div>
    </ToastProvider>
  );
}

import { useState, useEffect, useCallback } from "react";
import { api } from "./api.js";
import Dashboard from "./components/Dashboard.jsx";
import Incidents, { IncidentDrawer } from "./components/Incidents.jsx";
import Monitoring from "./components/Monitoring.jsx";
import Admin from "./components/Admin.jsx";
import AuditLog from "./components/AuditLog.jsx";
import { Icon } from "./components/icons.jsx";
import { LiveDot, ToastProvider } from "./components/shared.jsx";

/* ── Hash-based routing ──────────────────────────────────────────────── */
function useHashRoute() {
  const [page, setPage] = useState(
    window.location.hash.replace(/^#\/?/, "") || "dashboard"
  );
  useEffect(() => {
    function handler() {
      setPage(window.location.hash.replace(/^#\/?/, "") || "dashboard");
    }
    window.addEventListener("hashchange", handler);
    return () => window.removeEventListener("hashchange", handler);
  }, []);
  return page;
}

function navigate(page) {
  window.location.hash = page;
}

/* ── Login ───────────────────────────────────────────────────────────── */
function Login({ onLoginSuccess }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      await api.login(email, password);
      onLoginSuccess();
      window.location.hash = "#/dashboard";
    } catch (err) {
      setError("Invalid email or password");
    }
    setLoading(false);
  }

  return (
    <div className="login-screen">
      <div className="login-card">
        <div className="login-card__logo">
          <span className="logo-icon"><Icon name="shield-check" /></span>
          AEGIS
        </div>
        <div className="login-card__title">Sign in to the security console</div>
        <form onSubmit={handleSubmit} style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          {error && <div className="login-error">{error}</div>}
          <div className="login-form-group">
            <label className="login-label">Email address</label>
            <input
              type="email"
              className="login-input"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="admin@aegis.internal"
              autoComplete="username"
              required
            />
          </div>
          <div className="login-form-group">
            <label className="login-label">Password</label>
            <input
              type="password"
              className="login-input"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              autoComplete="current-password"
              required
            />
          </div>
          <button type="submit" className="btn-primary" disabled={loading} style={{ marginTop: "6px", width: "100%" }}>
            {loading ? "Authenticating…" : "Sign in"}
          </button>
        </form>
        <div className="login-hint">
          <b>Demo accounts</b>
          <div>Admin — <code>admin@aegis.internal</code> / <code>admin123</code></div>
          <div>Analyst — <code>analyst@aegis.internal</code> / <code>analyst123</code></div>
          <div>Read-only — <code>readonly@aegis.internal</code> / <code>readonly123</code></div>
        </div>
      </div>
    </div>
  );
}

/* ── Navigation ──────────────────────────────────────────────────────── */
const NAV = [
  { key: "dashboard",  icon: "shield",    label: "Dashboard" },
  { key: "incidents",  icon: "alert",     label: "Incidents" },
  { key: "monitoring", icon: "activity",  label: "Monitoring" },
  { key: "admin",      icon: "settings",  label: "Administration" },
  { key: "audit",      icon: "clipboard", label: "Audit Log" },
];

const PAGE_TITLES = {
  dashboard: "Dashboard",
  incidents: "Incidents",
  monitoring: "Monitoring",
  admin: "Administration",
  audit: "Audit Log",
};

/* ════════════════════════════════════════════════════════════════════════
   MAIN APP
   ═══════════════════════════════════════════════════════════════════════ */
export default function App() {
  const page = useHashRoute();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [incidentDrawerId, setIncidentDrawerId] = useState(null);
  const [user, setUser] = useState(null);
  const [loadingUser, setLoadingUser] = useState(true);

  const checkUser = useCallback(async () => {
    const token = localStorage.getItem("aegis_token");
    if (!token) {
      setUser(null);
      setLoadingUser(false);
      if (window.location.hash !== "#/login") window.location.hash = "#/login";
      return;
    }
    try {
      const data = await api.me();
      setUser(data);
      localStorage.setItem("aegis_role", data.role);
    } catch (err) {
      setUser(null);
      localStorage.removeItem("aegis_token");
      localStorage.removeItem("aegis_role");
      window.location.hash = "#/login";
    }
    setLoadingUser(false);
  }, []);

  useEffect(() => { checkUser(); }, [checkUser, page]);
  useEffect(() => { setSidebarOpen(false); }, [page]);

  const openIncident = useCallback((id) => setIncidentDrawerId(id), []);

  if (loadingUser) {
    return (
      <div className="dash-loading" style={{ height: "100vh" }}>
        <div className="dash-loading__spinner" />
        <div>Verifying credentials…</div>
      </div>
    );
  }

  if (!user || page === "login") {
    return <Login onLoginSuccess={checkUser} />;
  }

  function renderPage() {
    switch (page) {
      case "incidents":  return <Incidents user={user} />;
      case "monitoring": return <Monitoring user={user} />;
      case "admin":      return <Admin user={user} />;
      case "audit":      return <AuditLog user={user} />;
      default:           return <Dashboard user={user} onOpenIncident={openIncident} />;
    }
  }

  const initial = (user.email || "?").charAt(0).toUpperCase();

  return (
    <ToastProvider>
      <div className="app-shell">
        <button
          className={`hamburger ${sidebarOpen ? "open" : ""}`}
          onClick={() => setSidebarOpen(!sidebarOpen)}
          aria-label="Toggle navigation"
        >
          <span /><span /><span />
        </button>

        {sidebarOpen && <div className="sidebar-overlay" onClick={() => setSidebarOpen(false)} />}

        {/* Sidebar */}
        <aside className={`sidebar ${sidebarOpen ? "sidebar--open" : ""}`}>
          <div className="sidebar__brand" onClick={() => navigate("dashboard")}>
            <span className="logo-icon"><Icon name="shield-check" /></span>
            <div>
              <div className="logo-text">AEGIS</div>
              <div className="sidebar__tagline">Security Console</div>
            </div>
          </div>

          <nav className="sidebar__nav">
            <div className="nav-section-label">Operations</div>
            {NAV.map((item) => (
              <button
                key={item.key}
                className={`nav-item ${page === item.key ? "nav-item--active" : ""}`}
                onClick={() => navigate(item.key)}
              >
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
                <div className="user-chip__email">{user.email}</div>
                <div className="user-chip__role">{user.role.replace("_", " ")}</div>
              </div>
              <button
                className="user-chip__logout"
                title="Sign out"
                onClick={() => { api.logout(); checkUser(); }}
              >
                <Icon name="logout" size={15} />
              </button>
            </div>
            <div className="sidebar__version">
              <span>AEGIS v1.2</span>
              <span className="sidebar__status"><span className="sidebar__status-dot" /> Active</span>
            </div>
          </div>
        </aside>

        {/* Main */}
        <main className="main-content">
          <header className="topbar">
            <div>
              <div className="topbar__title">{PAGE_TITLES[page] || "Dashboard"}</div>
            </div>
            <div className="topbar__right">
              <LiveDot />
              <span className="topbar__crumb">Live · auto-refresh</span>
            </div>
          </header>
          <div className="page-body">
            {renderPage()}
          </div>
        </main>

        {incidentDrawerId && (
          <IncidentDrawer
            id={incidentDrawerId}
            onClose={() => setIncidentDrawerId(null)}
            onChanged={() => {}}
            user={user}
          />
        )}
      </div>
    </ToastProvider>
  );
}

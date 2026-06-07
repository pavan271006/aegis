// AEGIS Enterprise — Full API client with JWT support

// Base URL for the backend API.
//  • Local dev / same-origin (Cloud Run behind Hosting): leave VITE_API_BASE unset → "".
//  • Split hosting (frontend on Firebase, backend on Render): set
//    VITE_API_BASE=https://your-service.onrender.com at build time.
const API_BASE = (import.meta.env.VITE_API_BASE || "").replace(/\/$/, "");

function getHeaders() {
  const headers = { "Content-Type": "application/json" };
  const token = localStorage.getItem("aegis_token");
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }
  return headers;
}

async function get(path) {
  const r = await fetch(API_BASE + path, { headers: getHeaders() });
  if (r.status === 401) {
    localStorage.removeItem("aegis_token");
    window.location.hash = "#/login";
  }
  if (!r.ok) throw new Error(`${path} -> ${r.status}`);
  return r.json();
}

async function post(path, body) {
  const r = await fetch(API_BASE + path, {
    method: "POST",
    headers: getHeaders(),
    body: body ? JSON.stringify(body) : undefined,
  });
  if (r.status === 401) {
    localStorage.removeItem("aegis_token");
    window.location.hash = "#/login";
  }
  if (!r.ok) throw new Error(`${path} -> ${r.status}`);
  return r.json();
}

async function del(path) {
  const r = await fetch(API_BASE + path, {
    method: "DELETE",
    headers: getHeaders(),
  });
  if (r.status === 401) {
    localStorage.removeItem("aegis_token");
    window.location.hash = "#/login";
  }
  if (!r.ok) throw new Error(`${path} -> ${r.status}`);
  return r.json();
}

export const api = {
  /* ── Authentication ────────────────────────────────── */
  login: async (email, password) => {
    const res = await post("/api/auth/login", { email, password });
    if (res.access_token) {
      localStorage.setItem("aegis_token", res.access_token);
    }
    return res;
  },
  logout: () => {
    localStorage.removeItem("aegis_token");
    window.location.hash = "#/login";
  },
  me: () => get("/api/auth/me"),

  /* ── Dashboard ─────────────────────────────────────── */
  dashboard:      ()  => get("/api/dashboard"),
  dashboardStats: ()  => get("/api/dashboard/stats"),
  postureTrends:  ()  => get("/api/dashboard/posture-trends"),

  /* ── Incidents ─────────────────────────────────────── */
  incidents:      ()     => get("/api/incidents"),
  incident:       (id)   => get(`/api/incidents/${id}`),
  resolve:        (id)   => post(`/api/incidents/${id}/resolve`),
  approveAction:  (id)   => post(`/api/incidents/actions/${id}/approve`),
  reportUrl:      (id)   => `${API_BASE}/api/incidents/${id}/report.html`,

  /* ── Monitoring ────────────────────────────────────── */
  monitoringHistory: ()  => get("/api/monitoring/history/1"),
  triggerCheck:      ()  => post("/api/monitoring/check/1"),
  crowdsec:          ()  => get("/api/monitoring/crowdsec"),

  /* ── Admin ─────────────────────────────────────────── */
  sites:          ()              => get("/api/admin/sites"),
  addSite:        (body)          => post("/api/admin/sites", body),
  allowlist:      ()              => get("/api/admin/allowlist"),
  addAllowlist:   (value, note)   => post(`/api/admin/allowlist?value=${encodeURIComponent(value)}&note=${encodeURIComponent(note || "")}`),
  removeAllowlist:(id)            => del(`/api/admin/allowlist/${id}`),
  honeypots:      ()              => get("/api/admin/honeypots"),
  addHoneypot:    (path, note)    => post(`/api/admin/honeypots?path=${encodeURIComponent(path)}&note=${encodeURIComponent(note || "")}`),
  removeHoneypot: (id)            => del(`/api/admin/honeypots/${id}`),
  quarantine:     ()              => get("/api/admin/quarantine"),
  config:         ()              => get("/api/admin/config"),
  updateConfig:   (body)          => post("/api/admin/config", body),
  advisor:        ()              => get("/api/admin/advisor"),
  harden:         ()              => post("/api/admin/harden"),
  threatFeed:     ()              => get("/api/admin/threat-feed"),

  /* ── Admin: Backups ────────────────────────────────── */
  backups:        ()              => get("/api/admin/backups"),
  runBackup:      ()              => post("/api/admin/backups"),
  restoreBackup:  (name)          => post(`/api/admin/backups/${encodeURIComponent(name)}/restore`),
  deleteBackup:   (name)          => del(`/api/admin/backups/${encodeURIComponent(name)}`),

  /* ── Admin: Simulator ──────────────────────────────── */
  startSimulator: (mode)          => post(`/api/admin/simulator/start?mode=${mode}`),
  stopSimulator:  ()              => post("/api/admin/simulator/stop"),
  simulatorStatus:()              => get("/api/admin/simulator/status"),

  /* ── Admin: Bug Hunter Scanner ─────────────────────── */
  triggerScanner: (siteId)        => post(`/api/admin/scanner/trigger?site_id=${siteId}`),
  scannerStatus:  ()              => get("/api/admin/scanner/status"),
  vulnerabilities:()              => get("/api/admin/scanner/vulnerabilities"),

  /* ── Audit ─────────────────────────────────────────── */
  auditLog:       ()              => get("/api/admin/audit-log"),

  /* ── Health ────────────────────────────────────────── */
  health:         ()              => get("/health"),
};

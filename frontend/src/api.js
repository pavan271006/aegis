// AEGIS Enterprise — v2 API client.
//
// Every request carries the v2 RS256 access token as a Bearer. On a 401 the client
// transparently refreshes once and retries; if that fails the session is expired.
// Errors are normalised to ApiError{status,message} and surfaced as toasts. No page
// in this app talks to the legacy /api/* single-tenant endpoints — only /api/v2/*.

import * as session from "./lib/auth.js";
import { notify } from "./components/shared.jsx";

const BASE = (import.meta.env.VITE_API_BASE || "").replace(/\/$/, "");
export const API_BASE = BASE;

export class ApiError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

const MESSAGES = {
  400: "Bad request.",
  403: "You don't have permission to do that.",
  404: "Not found.",
  423: "Account temporarily locked. Try again later.",
  429: "Rate limit reached — slow down a moment.",
  500: "Server error. Please try again.",
};

let _refreshing = null;                                   // de-dupe concurrent refreshes
async function refreshOnce() {
  if (_refreshing) return _refreshing;
  const rt = session.getRefresh();
  if (!rt) return Promise.resolve(false);
  _refreshing = (async () => {
    try {
      const r = await fetch(BASE + "/api/v2/auth/refresh", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refresh_token: rt }),
      });
      if (!r.ok) return false;
      session.setTokens(await r.json());
      return true;
    } catch { return false; } finally { _refreshing = null; }
  })();
  return _refreshing;
}
session.registerRefresher(async () => { if (!(await refreshOnce())) throw new Error("refresh failed"); });

async function request(path, { method = "GET", body, query, auth = true, raw = false } = {}) {
  const url = new URL(BASE + path, window.location.origin);
  if (query) Object.entries(query).forEach(([k, v]) => v != null && url.searchParams.set(k, v));

  const build = () => {
    const headers = { "Content-Type": "application/json" };
    const tok = session.getAccess();
    if (auth && tok) headers["Authorization"] = `Bearer ${tok}`;
    return fetch(url.toString().replace(window.location.origin, ""), {
      method, headers, body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  };

  let res = await build();
  if (res.status === 401 && auth && session.getRefresh()) {
    if (await refreshOnce()) res = await build();
  }

  if (res.status === 401 && auth) { session.sessionExpired(); throw new ApiError(401, "Session expired."); }
  if (!res.ok) {
    let detail = MESSAGES[res.status] || `Request failed (${res.status}).`;
    try { const j = await res.json(); if (j && j.detail) detail = typeof j.detail === "string" ? j.detail : detail; } catch { /* noop */ }
    if (res.status !== 404) notify(detail, "error");          // 404s are often expected/empty
    throw new ApiError(res.status, detail);
  }
  if (raw) return res;
  if (res.status === 204) return null;
  return res.json().catch(() => null);
}

const get = (p, query) => request(p, { query });
const post = (p, body, query) => request(p, { method: "POST", body, query });
const del = (p) => request(p, { method: "DELETE" });

export const api = {
  // ── auth (v2) ──────────────────────────────────────────────────────────
  login: (email, password, org) => request("/api/v2/auth/login", { method: "POST", body: { email, password, org }, auth: false }),
  devLogin: () => request("/api/v2/auth/dev-login", { method: "POST", auth: false }),   // DEV: credential-free owner session (404 in prod)
  completeMfa: (challenge, code) => request("/api/v2/auth/mfa", { method: "POST", body: { challenge, code }, auth: false }),
  logout: async () => {
    const rt = session.getRefresh();
    if (rt) { try { await request("/api/v2/auth/logout", { method: "POST", body: { refresh_token: rt }, auth: false }); } catch { /* noop */ } }
    session.clearTokens();
  },
  listOrgs: () => get("/api/v2/auth/orgs"),
  switchOrg: (org) => post("/api/v2/auth/switch", undefined, { org }),
  mfaEnroll: () => post("/api/v2/auth/mfa/enroll"),
  mfaConfirm: (code) => post("/api/v2/auth/mfa/confirm", undefined, { code }),
  ssoStartUrl: (connId) => `${BASE}/api/v2/sso/${connId}/login`,

  // ── cases (Incidents → Cases) ────────────────────────────────────────────
  cases: () => get("/api/v2/cases"),
  case: (id) => get(`/api/v2/cases/${id}`),
  caseTimeline: (id) => get(`/api/v2/cases/${id}/timeline`),
  createCase: (body) => post("/api/v2/cases", body),
  assignCase: (id, assignee) => post(`/api/v2/cases/${id}/assign`, { assignee }),
  setCaseStatus: (id, status) => post(`/api/v2/cases/${id}/status`, { status }),
  addCaseNote: (id, note) => post(`/api/v2/cases/${id}/notes`, { note }),
  runPlaybook: (id, playbook) => post(`/api/v2/cases/${id}/run-playbook`, { playbook }),

  // ── ATT&CK ───────────────────────────────────────────────────────────────
  attackTechniques: () => get("/api/v2/attack/techniques"),
  attackCoverage: () => get("/api/v2/attack/coverage"),
  attackReport: () => get("/api/v2/attack/report"),

  // ── Threat Intelligence ──────────────────────────────────────────────────
  tipIndicators: () => get("/api/v2/tip/indicators"),
  tipActors: () => get("/api/v2/tip/actors"),
  tipPoll: () => post("/api/v2/tip/poll"),

  // ── Agent Fleet (Monitoring) ─────────────────────────────────────────────
  agents: () => get("/api/v2/agents"),
  agentManifest: () => get("/api/v2/agents/manifest"),
  mintAgentToken: () => post("/api/v2/agents/tokens"),
  revokeAgent: (id) => post(`/api/v2/agents/${id}/revoke`),

  // ── Detections ───────────────────────────────────────────────────────────
  sendFeedback: (body) => post("/api/v2/detections/feedback", body),

  // ── Copilot ──────────────────────────────────────────────────────────────
  copilotAsk: (question) => post("/api/v2/copilot/ask", { question }),
  copilotSummary: () => post("/api/v2/copilot/summary"),

  // ── Compliance / Audit ───────────────────────────────────────────────────
  auditVerify: () => get("/api/v2/compliance/audit/verify"),
  gdprExport: () => get("/api/v2/compliance/gdpr/export"),
  runRetention: () => post("/api/v2/compliance/retention/run"),
  validateBackup: () => post("/api/v2/compliance/backup/validate"),

  // ── health ───────────────────────────────────────────────────────────────
  health: () => request("/health", { auth: false }),
};

// AEGIS Enterprise — session + token manager (v2 auth).
//
// Holds the access + refresh token pair, decodes the RS256 access token to read
// identity/role/org/mfa claims (there is no /me endpoint — the JWT IS the identity),
// schedules a silent refresh shortly before expiry, and emits a "session-expired"
// event when refresh is no longer possible. Tokens are persisted so the session
// survives a page reload (session recovery); refresh tokens rotate on every use.

const ACCESS_KEY = "aegis_access";
const REFRESH_KEY = "aegis_refresh";
const ORG_KEY = "aegis_org";

const listeners = { expired: new Set(), change: new Set() };
export function on(event, fn) {
  (listeners[event] ||= new Set()).add(fn);
  return () => listeners[event].delete(fn);
}
function emit(event) {
  (listeners[event] || []).forEach((fn) => { try { fn(); } catch { /* noop */ } });
}

// ── storage ────────────────────────────────────────────────────────────────
export function getAccess() { return localStorage.getItem(ACCESS_KEY) || ""; }
export function getRefresh() { return localStorage.getItem(REFRESH_KEY) || ""; }
export function getActiveOrg() { return localStorage.getItem(ORG_KEY) || ""; }

export function setTokens({ access_token, refresh_token, org_id }) {
  if (access_token) localStorage.setItem(ACCESS_KEY, access_token);
  if (refresh_token) localStorage.setItem(REFRESH_KEY, refresh_token);
  if (org_id) localStorage.setItem(ORG_KEY, org_id);
  scheduleRefresh();
  emit("change");
}

export function clearTokens() {
  [ACCESS_KEY, REFRESH_KEY, ORG_KEY].forEach((k) => localStorage.removeItem(k));
  if (_timer) clearTimeout(_timer);
  emit("change");
}

// ── JWT decode (verification is the server's job) ──────────────────────────
export function decode(token = getAccess()) {
  try {
    const p = token.split(".")[1];
    return JSON.parse(decodeURIComponent(escape(atob(p.replace(/-/g, "+").replace(/_/g, "/")))));
  } catch { return null; }
}

export function identity() {
  const c = decode() || {};
  return {
    userId: c.sub, email: c.email || "", org: c.org || getActiveOrg(),
    role: c.role || "read_only", mfa: !!c.mfa, exp: c.exp || 0,
  };
}

function expired() {
  const c = decode();
  return !c || !c.exp || Date.now() / 1000 >= c.exp;
}
export function isAuthed() { return !!getAccess() && !expired(); }
// We can recover a session (silent refresh) if the access token is gone/expired
// but a refresh token is still present.
export function canRecover() { return !isAuthed() && !!getRefresh(); }

// ── role gate ──────────────────────────────────────────────────────────────
const RANK = { read_only: 0, analyst: 1, admin: 2, owner: 3 };
export function hasRole(min) { return (RANK[identity().role] ?? -1) >= (RANK[min] ?? 99); }

// ── silent refresh ─────────────────────────────────────────────────────────
let _timer = null;
let _refresher = null;                       // injected by api.js (avoid circular import)
export function registerRefresher(fn) { _refresher = fn; scheduleRefresh(); }

export function scheduleRefresh() {
  if (_timer) clearTimeout(_timer);
  const c = decode();
  if (!c || !c.exp || !_refresher) return;
  const ms = Math.max((c.exp - 60) * 1000 - Date.now(), 5000); // 60s before expiry
  _timer = setTimeout(() => { _refresher().catch(() => sessionExpired()); }, ms);
}

export function sessionExpired() { clearTokens(); emit("expired"); }

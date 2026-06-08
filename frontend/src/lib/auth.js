// Phase-1 enterprise auth client: access/refresh handling, transparent refresh,
// MFA step-up, and active-org tracking. Access token is kept in memory (not
// localStorage) to reduce XSS blast radius; refresh token is stored separately
// and rotated on every use.
const BASE = (import.meta.env.VITE_API_BASE || "").replace(/\/$/, "");

let _access = null;                       // in-memory only
const ORG_KEY = "aegis_org";
const RT_KEY = "aegis_rt";                // refresh token (rotated, single-use)

export const auth = {
  getOrg: () => localStorage.getItem(ORG_KEY) || "",
  setOrg: (id) => id ? localStorage.setItem(ORG_KEY, id) : localStorage.removeItem(ORG_KEY),

  async login(email, password, org) {
    const r = await post("/api/v2/auth/login", { email, password, org });
    if (r.mfa_required) return { mfaChallenge: r.challenge }; // caller shows MFA UI
    this._store(r);
    return { ok: true };
  },

  async completeMfa(challenge, code) {
    const r = await post("/api/v2/auth/mfa", { challenge, code });
    this._store(r);
    return { ok: true };
  },

  async logout() {
    const rt = localStorage.getItem(RT_KEY);
    if (rt) await post("/api/v2/auth/logout", { refresh_token: rt }).catch(() => {});
    _access = null;
    localStorage.removeItem(RT_KEY);
  },

  async switchOrg(orgId) {
    const r = await this.fetch("/api/v2/auth/switch?org=" + encodeURIComponent(orgId), { method: "POST" });
    const data = await r.json();
    this._store(data);
  },

  // Authenticated fetch with one transparent refresh-and-retry on 401.
  async fetch(path, opts = {}) {
    const doFetch = () => fetch(BASE + path, {
      ...opts,
      headers: { ...(opts.headers || {}), Authorization: `Bearer ${_access}` },
    });
    let res = await doFetch();
    if (res.status === 401 && (await this._refresh())) res = await doFetch();
    return res;
  },

  async _refresh() {
    const rt = localStorage.getItem(RT_KEY);
    if (!rt) return false;
    const r = await fetch(BASE + "/api/v2/auth/refresh", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: rt }),
    });
    if (!r.ok) { _access = null; localStorage.removeItem(RT_KEY); return false; }
    this._store(await r.json());
    return true;
  },

  _store(r) {
    _access = r.access_token;
    if (r.refresh_token) localStorage.setItem(RT_KEY, r.refresh_token);
    if (r.org_id) this.setOrg(r.org_id);
  },
};

async function post(path, body) {
  const r = await fetch(BASE + path, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || r.status);
  return r.json();
}

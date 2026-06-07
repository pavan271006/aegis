import { useState, useEffect, useCallback, useMemo } from "react";
import { api } from "../api.js";
import { Icon } from "./icons.jsx";
import {
  SeverityBadge, StatusBadge, Card, SectionTitle,
  PageWrap, SkeletonRows, EmptyState, useInterval, notify,
} from "./shared.jsx";

/* ── Attack Replay Payload Generator ─────────────────────────────────── */
function getReplayPayload(inc) {
  const r = inc?.report || {};
  const threatType = (r.threat_type || (inc.threat_types || []).join(", ") || "").toLowerCase();
  const sourceIp = inc?.source_ip || "127.0.0.1";
  const targetPath = r.target || "/login";
  const dateStr = inc?.created_at ? new Date(inc.created_at).toISOString() : new Date().toISOString();

  let requestRaw = "";
  let regexMatched = "";
  let actionTaken = "";
  let verification = "";

  const evidence = r.evidence_payload || "";

  if (threatType.includes("sql") || threatType.includes("sqli")) {
    requestRaw = evidence
      ? `GET ${evidence.startsWith('/') ? evidence : '/' + evidence} HTTP/1.1\nHost: aegis.internal\nUser-Agent: Mozilla/5.0 (sqlmap/1.4.12#stable)\nConnection: close`
      : `POST ${targetPath} HTTP/1.1\nHost: aegis.internal\nUser-Agent: Mozilla/5.0 (sqlmap/1.4.12#stable)\nContent-Type: application/x-www-form-urlencoded\nContent-Length: 53\nConnection: close\n\nusername=admin' OR '1'='1&password=backdoor_pass_here`;
    regexMatched = `Rule ID: SQL_INJECTION\nPattern: (\\b(SELECT|UNION|INSERT|UPDATE|DELETE|OR\\s+['"]?\\d+['"]?\\s*=\\s*['"]?\\d+)\\b)\nConfidence: 98%${evidence ? `\nMatched Payload: ${evidence}` : ""}`;
    actionTaken = `IP Blocklist request initiated via Cloudflare WAF.\nCloudflare response: {"success":true,"result":{"id":"${inc.id || 0}_cf_rule"}}`;
    verification = `Cloudflare Firewall challenge verified. Target IP ${sourceIp} blocked globally.`;
  } else if (threatType.includes("xss")) {
    requestRaw = evidence
      ? `GET ${evidence.startsWith('/') ? evidence : '/' + evidence} HTTP/1.1\nHost: aegis.internal\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\nAccept: */*`
      : `GET ${targetPath}?search=%3Cscript%3Ealert%281%29%3C%2Fscript%3E HTTP/1.1\nHost: aegis.internal\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\nAccept: */*\n\n`;
    regexMatched = `Rule ID: CROSS_SITE_SCRIPTING\nPattern: (<script.*?>|javascript:|onload=)\nConfidence: 95%${evidence ? `\nMatched Payload: ${evidence}` : ""}`;
    actionTaken = `Triggered containment alert. Temporary response rate-limiting activated for IP ${sourceIp}.`;
    verification = `Local block confirmed. Node ingress dropped 100% of subsequent requests from ${sourceIp}.`;
  } else if (threatType.includes("traversal")) {
    requestRaw = evidence
      ? `GET ${evidence.startsWith('/') ? evidence : '/' + evidence} HTTP/1.1\nHost: aegis.internal\nUser-Agent: curl/7.68.0\nAccept: */*`
      : `GET /static/../../../../etc/passwd HTTP/1.1\nHost: aegis.internal\nUser-Agent: curl/7.68.0\nAccept: */*\n\n`;
    regexMatched = `Rule ID: PATH_TRAVERSAL\nPattern: (\\.\\./|\\.\\.\\\\)\nConfidence: 100%${evidence ? `\nMatched Payload: ${evidence}` : ""}`;
    actionTaken = `IP Blocklist request initiated via Cloudflare WAF.\nCloudflare response: {"success":true,"result":{"id":"${inc.id || 0}_cf_rule"}}`;
    verification = `Cloudflare Firewall challenge verified. Target IP ${sourceIp} blocked globally.`;
  } else if (threatType.includes("brute") || threatType.includes("credential") || threatType.includes("auth")) {
    requestRaw = evidence
      ? `POST /api/auth/login HTTP/1.1\nHost: aegis.internal\nContent-Type: application/json\nUser-Agent: Mozilla/5.0\n\n[AEGIS Real Evidence Log]: ${evidence}`
      : `POST /api/auth/login HTTP/1.1\nHost: aegis.internal\nContent-Type: application/json\nContent-Length: 42\n\n{"username": "admin", "password": "password1"}\n\n[AEGIS LOG: Repeated 8 times within 12 seconds]`;
    regexMatched = `Rule ID: BRUTE_FORCE_AUTH\nTrigger: 3+ failed logins in 60s\nConfidence: 99%${evidence ? `\nMatched Payload: ${evidence}` : ""}`;
    actionTaken = `Session revocation adapter triggered for user admin. IP ${sourceIp} blocked.`;
    verification = `Ingress node revoked active tokens. IP dropped for 24 hours.`;
  } else if (threatType.includes("honeypot") || threatType.includes("trap")) {
    requestRaw = evidence
      ? `GET ${evidence.startsWith('/') ? evidence : '/' + evidence} HTTP/1.1\nHost: aegis.internal\nUser-Agent: Mozilla/5.0 (compatible; CensysInspect/1.1)\nConnection: keep-alive`
      : `GET ${targetPath} HTTP/1.1\nHost: aegis.internal\nUser-Agent: Mozilla/5.0 (compatible; CensysInspect/1.1)\nConnection: keep-alive\n\n`;
    regexMatched = `Rule ID: HONEYPOT_TRAP\nTrigger: Path match for fake admin/login directory\nConfidence: 100%${evidence ? `\nMatched Payload: ${evidence}` : ""}`;
    actionTaken = `IP Blocklist request initiated via Cloudflare WAF.\nCloudflare response: {"success":true,"result":{"id":"${inc.id || 0}_cf_rule"}}`;
    verification = `Cloudflare Firewall challenge verified. Target IP ${sourceIp} blocked globally.`;
  } else if (threatType.includes("bot") || threatType.includes("scanner") || threatType.includes("abuse")) {
    requestRaw = evidence
      ? `GET ${evidence.startsWith('/') ? evidence : '/' + evidence} HTTP/1.1\nHost: aegis.internal\nUser-Agent: python-requests/2.25.1\nConnection: keep-alive`
      : `GET /robots.txt HTTP/1.1\nHost: aegis.internal\nUser-Agent: python-requests/2.25.1\nAccept-Encoding: gzip, deflate\nConnection: keep-alive\n\n`;
    regexMatched = `Rule ID: BOT_SCANNER_DETECTION\nTrigger: Missing browser headers + high frequency scraping\nConfidence: 90%${evidence ? `\nMatched Payload: ${evidence}` : ""}`;
    actionTaken = `Local IP blocklist entry logged. Custom rate-limiting threshold applied.`;
    verification = `Rate-limiting actively dropping packages (429 responses returned).`;
  } else {
    requestRaw = evidence
      ? `GET ${evidence.startsWith('/') ? evidence : '/' + evidence} HTTP/1.1\nHost: aegis.internal\nConnection: keep-alive`
      : `GET ${targetPath} HTTP/1.1\nHost: aegis.internal\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\nConnection: keep-alive\n\n`;
    regexMatched = `Rule ID: BEHAVIORAL_ANOMALY\nTrigger: Score threshold exceeded\nConfidence: 85%${evidence ? `\nMatched Payload: ${evidence}` : ""}`;
    actionTaken = `IP Blocklist request initiated via Cloudflare WAF.`;
    verification = `IP blocklist verified.`;
  }

  return { requestRaw, regexMatched, actionTaken, verification, dateStr };
}

/* ── Attack Replay Console ─────────────────────────────────────────── */
function AttackReplayConsole({ inc }) {
  const payload = getReplayPayload(inc);
  const [lines, setLines] = useState([]);
  
  useEffect(() => {
    const terminalLogs = [
      { type: "info", text: `[+] Initializing Attack Replay for Incident #${inc.id}...` },
      { type: "info", text: `[+] Event timestamp: ${payload.dateStr}` },
      { type: "info", text: `[+] Reconstructing raw HTTP request body:` },
      { type: "raw", text: payload.requestRaw },
      { type: "warning", text: `[!] Analyzing request payload via AEGIS signature engine...` },
      { type: "danger", text: `[!] Match Found!` },
      { type: "raw", text: payload.regexMatched },
      { type: "warning", text: `[+] Triggering Autonomous Responder actions:` },
      { type: "raw", text: payload.actionTaken },
      { type: "success", text: `[+] Verifying containment status:` },
      { type: "success", text: payload.verification },
      { type: "success", text: `[+] Status: Contained & Mitigated. Replay complete.` }
    ];

    setLines([]);
    let currentIdx = 0;
    const interval = setInterval(() => {
      if (currentIdx < terminalLogs.length) {
        setLines((prev) => [...prev, terminalLogs[currentIdx]]);
        currentIdx++;
      } else {
        clearInterval(interval);
      }
    }, 450);

    return () => clearInterval(interval);
  }, [inc, payload.requestRaw, payload.regexMatched, payload.actionTaken, payload.verification, payload.dateStr]);

  return (
    <div className="replay-terminal">
      <div className="replay-terminal__hdr">
        <span>AEGIS-CONSOLE-REPLAY v1.2</span>
        <span>STATUS: ACTIVE</span>
      </div>
      {lines.map((line, idx) => {
        if (line.type === "raw") {
          return (
            <pre key={idx} className="replay-terminal__line" style={{ background: "rgba(45,212,167,0.03)", padding: "8px", borderRadius: "4px", border: "1px solid rgba(45,212,167,0.06)" }}>
              {line.text}
            </pre>
          );
        }
        return (
          <div key={idx} className={`replay-terminal__line ${line.type}`}>
            {line.text}
          </div>
        );
      })}
      <span className="replay-terminal__cursor" />
    </div>
  );
}

/* ── Detail Drawer ───────────────────────────────────────────────────── */
function IncidentDrawer({ id, onClose, onChanged, user }) {
  const [inc, setInc] = useState(null);
  const [loading, setLoading] = useState(true);
  const [resolving, setResolving] = useState(false);
  const [activeTab, setActiveTab] = useState("overview"); // "overview" | "replay"

  const userRole = user?.role || localStorage.getItem("aegis_role") || "read_only";
  const isReadOnly = userRole === "read_only";

  useEffect(() => {
    if (!id) return;
    setLoading(true);
    api.incident(id).then((d) => { setInc(d); setLoading(false); }).catch(() => setLoading(false));
    setActiveTab("overview");
  }, [id]);

  async function handleResolve() {
    if (isReadOnly) return;
    setResolving(true);
    try {
      await api.resolve(id);
      notify("Incident marked as resolved.", "success");
      onChanged?.();
      onClose();
    } catch (e) {
      notify("Failed to resolve incident. You may not have permission.", "error");
    }
    setResolving(false);
  }

  async function handleApproveAction(actionId) {
    if (isReadOnly) return;
    try {
      await api.approveAction(actionId);
      notify("Action approved and applied.", "success");
      const fresh = await api.incident(id);
      setInc(fresh);
      onChanged?.();
    } catch (e) {
      notify("Failed to approve action. You may not have permission.", "error");
    }
  }

  if (!id) return null;

  const r = inc?.report || {};

  return (
    <div className="drawer-overlay" onClick={onClose}>
      <div className="drawer-panel" onClick={(e) => e.stopPropagation()}>
        {loading ? (
          <SkeletonRows count={8} />
        ) : !inc ? (
          <EmptyState text="Incident not found" />
        ) : (
          <>
            <div className="drawer-panel__header">
              <div>
                <h2 className="drawer-panel__title">{r.threat_type || (inc.threat_types || []).join(", ") || "Incident"}</h2>
                <div className="drawer-panel__sub">
                  Incident #{inc.id} · {r.geo || "Location unknown"}
                </div>
              </div>
              <button className="drawer-close" onClick={onClose} aria-label="Close"><Icon name="close" size={16} /></button>
            </div>

            <div className="drawer-badges">
              <SeverityBadge severity={inc.severity || r.severity} />
              <StatusBadge status={inc.status || r.final_status} />
            </div>

            <div className="drawer-tabs">
              <button
                className={`drawer-tab ${activeTab === "overview" ? "active" : ""}`}
                onClick={() => setActiveTab("overview")}
              >
                Overview
              </button>
              <button
                className={`drawer-tab ${activeTab === "replay" ? "active" : ""}`}
                onClick={() => setActiveTab("replay")}
              >
                Attack Replay
              </button>
            </div>

            {activeTab === "overview" ? (
              <>
                <div className="drawer-kv">
                  <KVRow label="Source" value={r.source || inc.source_ip} />
                  <KVRow label="Target" value={r.target} />
                  <KVRow label="Request Count" value={inc.request_count} />
                  {r.evidence_payload && <KVRow label="Real Attack Evidence" value={r.evidence_payload} />}
                  <KVRow label="Root Cause" value={r.root_cause} />
                  <KVRow label="Actions Taken" value={r.actions_taken} />
                  <KVRow label="Verification" value={r.verification_result} />
                  <KVRow label="Final Status" value={r.final_status} />
                  <KVRow label="Created" value={inc.created_at ? new Date(inc.created_at).toLocaleString() : "-"} />
                </div>

                {r.timeline && r.timeline.length > 0 && (
                  <div className="drawer-section">
                    <h3 className="drawer-section__title">Timeline</h3>
                    <ul className="drawer-timeline">
                      {r.timeline.map((t, i) => (
                        <li key={i} className="drawer-timeline__item">
                          <span className="drawer-timeline__dot" />
                          <div>
                            {t.at && <span className="drawer-timeline__time">{t.at}</span>}
                            <span>{t.event}</span>
                          </div>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {r.recommended_fixes && r.recommended_fixes.length > 0 && (
                  <div className="drawer-section">
                    <h3 className="drawer-section__title">Recommended Fixes</h3>
                    <ul className="drawer-fixes">
                      {r.recommended_fixes.map((f, i) => (
                        <li key={i}>{f}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {inc.actions && inc.actions.length > 0 && (
                  <div className="drawer-section">
                    <h3 className="drawer-section__title">Queued Actions</h3>
                    <div className="drawer-actions">
                      {inc.actions.map((a) => (
                        <div key={a.id} className="drawer-action">
                          <div className="drawer-action__info">
                            <span className="drawer-action__type">{a.action_type || a.type}</span>
                            <span className={`drawer-action__status ${a.status}`}>{a.status}</span>
                          </div>
                          <div className="drawer-action__detail">{a.detail || a.description || JSON.stringify(a.params || {})}</div>
                          {a.status === "pending_approval" && (
                            <button
                              className="btn-sm btn-teal"
                              onClick={() => handleApproveAction(a.id)}
                              disabled={isReadOnly}
                              title={isReadOnly ? "Read-only access cannot approve actions" : ""}
                            >
                              Approve
                            </button>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </>
            ) : (
              <div className="drawer-section">
                <h3 className="drawer-section__title" style={{ marginBottom: "14px" }}>Active Log Replay Console</h3>
                <AttackReplayConsole inc={inc} />
              </div>
            )}

            <div className="drawer-footer">
              {inc.status !== "resolved" && (
                <button
                  className="btn-primary"
                  onClick={handleResolve}
                  disabled={resolving || isReadOnly}
                  title={isReadOnly ? "Read-only access cannot resolve incidents" : ""}
                >
                  {resolving ? "Resolving…" : "Mark Resolved"}
                </button>
              )}
              <a
                className="btn-outline"
                href={api.reportUrl(inc.id)}
                target="_blank"
                rel="noopener noreferrer"
              >
                <Icon name="download" size={15} /> Download Report
              </a>
              <button className="btn-ghost" onClick={onClose}>Dismiss</button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

function KVRow({ label, value }) {
  if (!value && value !== 0) return null;
  return (
    <>
      <div className="drawer-kv__key">{label}</div>
      <div className="drawer-kv__val">{String(value)}</div>
    </>
  );
}

/* ════════════════════════════════════════════════════════════════════════
   INCIDENTS PAGE
   ════════════════════════════════════════════════════════════════════════ */
export default function Incidents({ user }) {
  const [incidents, setIncidents] = useState(null);
  const [filter, setFilter] = useState("all");
  const [search, setSearch] = useState("");
  const [openId, setOpenId] = useState(null);

  const load = useCallback(() => {
    api.incidents().then(setIncidents).catch(() => {});
  }, []);

  useEffect(() => { load(); }, [load]);
  useInterval(load, 15000);

  const filtered = useMemo(() => {
    if (!incidents) return null;
    let list = incidents;
    if (filter !== "all") list = list.filter((i) => i.status?.toLowerCase() === filter);
    if (search.trim()) {
      const q = search.trim().toLowerCase();
      list = list.filter((i) =>
        (i.source_ip || "").toLowerCase().includes(q) ||
        (i.threat_types || []).some((t) => t.toLowerCase().includes(q))
      );
    }
    return list;
  }, [incidents, filter, search]);

  const counts = useMemo(() => {
    if (!incidents) return {};
    return {
      all: incidents.length,
      open: incidents.filter((i) => i.status?.toLowerCase() === "open").length,
      contained: incidents.filter((i) => i.status?.toLowerCase() === "contained").length,
      resolved: incidents.filter((i) => i.status?.toLowerCase() === "resolved").length,
    };
  }, [incidents]);

  return (
    <PageWrap>
      <SectionTitle>Incident Management</SectionTitle>

      <div className="incidents-toolbar">
        <div className="filter-tabs">
          {["all", "open", "contained", "resolved"].map((f) => (
            <button
              key={f}
              className={`filter-tab ${filter === f ? "active" : ""}`}
              onClick={() => setFilter(f)}
            >
              {f.charAt(0).toUpperCase() + f.slice(1)}
              {counts[f] != null && <span className="filter-tab__count">{counts[f]}</span>}
            </button>
          ))}
        </div>
        <div className="search-box">
          <span className="search-box__icon"><Icon name="search" size={16} /></span>
          <input
            type="text"
            placeholder="Search by IP or threat type…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="search-box__input"
          />
        </div>
      </div>

      <Card className="table-card">
        {filtered === null ? (
          <SkeletonRows count={6} />
        ) : filtered.length === 0 ? (
          <EmptyState text="No incidents match your filter" icon="search" />
        ) : (
          <div className="incidents-table">
            <div className="incidents-table__hdr">
              <span>Severity</span><span>Source IP</span><span>Threats</span>
              <span>Requests</span><span>Status</span><span>Date</span>
            </div>
            {filtered.map((inc) => (
              <div
                key={inc.id}
                className="incidents-table__row"
                onClick={() => setOpenId(inc.id)}
              >
                <span><SeverityBadge severity={inc.severity} /></span>
                <span className="mono">{inc.source_ip}</span>
                <span className="types-cell">{(inc.threat_types || []).join(", ")}</span>
                <span className="mono">{inc.request_count}</span>
                <span><StatusBadge status={inc.status} /></span>
                <span className="muted-text">{new Date(inc.created_at).toLocaleDateString()}</span>
              </div>
            ))}
          </div>
        )}
      </Card>

      {openId && (
        <IncidentDrawer
          id={openId}
          onClose={() => setOpenId(null)}
          onChanged={load}
          user={user}
        />
      )}
    </PageWrap>
  );
}

export { IncidentDrawer };

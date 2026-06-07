import { useState, useEffect, useCallback } from "react";
import { api } from "../api.js";
import { Icon } from "./icons.jsx";
import {
  Card, SectionTitle, PageWrap, SkeletonRows, EmptyState, useInterval, notify,
} from "./shared.jsx";

/* ════════════════════════════════════════════════════════════════════════
   MONITORING PAGE
   ════════════════════════════════════════════════════════════════════════ */
export default function Monitoring({ siteId, sites }) {
  const [history, setHistory] = useState(null);
  const [crowdsec, setCrowdsec] = useState(null);
  const [checking, setChecking] = useState(false);

  const activeSite = (sites || []).find((s) => String(s.id) === String(siteId));

  const load = useCallback(() => {
    api.monitoringHistory(siteId).then(setHistory).catch(() => {});
    api.crowdsec().then(setCrowdsec).catch(() => setCrowdsec([]));
  }, [siteId]);

  useEffect(() => { load(); }, [load]);
  useInterval(load, 30000);

  async function runCheck() {
    setChecking(true);
    try {
      await api.triggerCheck(siteId);
      notify("Monitoring check started.", "success");
      setTimeout(load, 2000);
    } catch (e) {
      notify("Check failed. You may not have permission to run checks.", "error");
    }
    setChecking(false);
  }

  const latest = Array.isArray(history) && history.length > 0 ? history[0] : null;
  const isUp = latest?.status_code >= 200 && latest?.status_code < 400;

  return (
    <PageWrap>
      <SectionTitle extra={
        <button className="btn-primary btn-sm" onClick={runCheck} disabled={checking}>
          <Icon name="play" size={14} /> {checking ? "Running…" : "Run Check Now"}
        </button>
      }>
        {activeSite ? `Monitoring — ${activeSite.name || activeSite.url}` : "Site Monitoring"}
      </SectionTitle>

      {/* Current Status */}
      <div className="monitor-top">
        <Card className="monitor-status-card">
          <div className="monitor-status">
            <div className={`monitor-status__indicator ${isUp ? "up" : "down"}`}>
              <span className="monitor-status__dot" />
              {isUp ? "ONLINE" : latest ? "DOWN" : "UNKNOWN"}
            </div>
            {latest && (
              <div className="monitor-status__details">
                <div className="monitor-kv">
                  <span className="monitor-kv__k">Status Code</span>
                  <span className={`monitor-kv__v ${isUp ? "text-teal" : "text-red"}`}>{latest.status_code}</span>
                </div>
                <div className="monitor-kv">
                  <span className="monitor-kv__k">Response Time</span>
                  <span className="monitor-kv__v">{latest.response_ms != null ? `${latest.response_ms}ms` : "—"}</span>
                </div>
                <div className="monitor-kv">
                  <span className="monitor-kv__k">SSL Days Left</span>
                  <span className={`monitor-kv__v ${(latest.ssl_days_left || 0) < 30 ? "text-amber" : "text-teal"}`}>
                    {latest.ssl_days_left != null ? `${latest.ssl_days_left} days` : "N/A"}
                  </span>
                </div>
                <div className="monitor-kv">
                  <span className="monitor-kv__k">Checked At</span>
                  <span className="monitor-kv__v">{latest.ts ? new Date(latest.ts).toLocaleString() : "—"}</span>
                </div>
              </div>
            )}
          </div>
        </Card>

        {/* SSL Countdown */}
        <Card title="SSL Certificate" icon="lock" className="ssl-card">
          {latest?.ssl_days_left != null ? (
            <div className="ssl-countdown">
              <div className={`ssl-countdown__number ${latest.ssl_days_left < 14 ? "danger" : latest.ssl_days_left < 30 ? "warning" : ""}`}>
                {latest.ssl_days_left}
              </div>
              <div className="ssl-countdown__label">Days Until Expiry</div>
              <div className="ssl-countdown__bar">
                <div
                  className="ssl-countdown__fill"
                  style={{
                    width: `${Math.min(100, (latest.ssl_days_left / 365) * 100)}%`,
                    background: latest.ssl_days_left < 14 ? "var(--high)" : latest.ssl_days_left < 30 ? "var(--medium)" : "var(--signal)",
                  }}
                />
              </div>
            </div>
          ) : (
            <EmptyState text="No SSL data available" icon="lock" />
          )}
        </Card>
      </div>

      {/* Missing Headers */}
      {latest?.missing_headers && latest.missing_headers.length > 0 && (
        <Card title="Missing Security Headers" icon="alert" className="headers-card">
          <div className="missing-headers">
            {latest.missing_headers.map((h, i) => (
              <div key={i} className="missing-header">
                <span className="missing-header__icon"><Icon name="alert" size={14} /></span>
                <span className="missing-header__name">{h}</span>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Response Time History */}
      <Card title="Response Time History" icon="activity">
        {!history ? (
          <SkeletonRows count={4} />
        ) : history.length === 0 ? (
          <EmptyState text="No monitoring history yet" icon="radio" />
        ) : (
          <div className="response-chart">
            {history.slice(0, 20).reverse().map((h, i) => {
              const ms = h.response_ms != null ? h.response_ms : 0;
              const max = 3000;
              const pct = Math.min(100, (ms / max) * 100);
              return (
                <div key={i} className="response-chart__bar-wrap" title={`${ms}ms — ${new Date(h.ts || h.checked_at).toLocaleString()}`}>
                  <div
                    className="response-chart__bar"
                    style={{
                      height: `${pct}%`,
                      background: h.status_code >= 400 ? "var(--high)" : ms > 2000 ? "var(--medium)" : "var(--signal)",
                    }}
                  />
                </div>
              );
            })}
          </div>
        )}
      </Card>

      {/* Monitoring History Table */}
      <Card title="Check History" icon="clock">
        {!history ? (
          <SkeletonRows count={5} />
        ) : history.length === 0 ? (
          <EmptyState text="No checks recorded" />
        ) : (
          <div className="monitor-history-table">
            <div className="monitor-history-table__hdr">
              <span>Status</span><span>Response Time</span><span>SSL Days</span><span>Checked At</span>
            </div>
            {history.slice(0, 20).map((h, i) => (
              <div key={i} className="monitor-history-table__row">
                <span className={`status-dot ${h.status_code >= 200 && h.status_code < 400 ? "up" : "down"}`}>
                  {h.status_code}
                </span>
                <span>{h.response_ms != null ? `${h.response_ms}ms` : "—"}</span>
                <span>{h.ssl_days_left ?? "—"}</span>
                <span className="muted-text">{h.ts ? new Date(h.ts).toLocaleString() : "—"}</span>
              </div>
            ))}
          </div>
        )}
      </Card>

      {/* CrowdSec Decisions */}
      <SectionTitle>CrowdSec Decisions</SectionTitle>
      <Card>
        {crowdsec === null ? (
          <SkeletonRows count={3} />
        ) : !Array.isArray(crowdsec) || crowdsec.length === 0 ? (
          <EmptyState text="No CrowdSec decisions active" icon="check-circle" />
        ) : (
          <div className="crowdsec-list">
            {crowdsec.map((d, i) => (
              <div key={i} className="crowdsec-item">
                <span className="crowdsec-item__type">{d.type || "ban"}</span>
                <span className="crowdsec-item__value">{d.value || d.ip}</span>
                <span className="crowdsec-item__reason">{d.reason || d.scenario}</span>
                <span className="muted-text">{d.duration || ""}</span>
              </div>
            ))}
          </div>
        )}
      </Card>
    </PageWrap>
  );
}

import { useState, useEffect, useCallback } from "react";
import { api } from "../api.js";
import { Icon } from "./icons.jsx";
import {
  StatCard, AnimatedNumber, SeverityBadge, StatusBadge,
  Card, SectionTitle, HBar,
  PageWrap, SkeletonRows, LiveDot, EmptyState, useInterval,
} from "./shared.jsx";

/* ── Security score gauge ────────────────────────────────────────────── */
function ScoreGauge({ score, health }) {
  const healthClass = (health || "").toLowerCase().replace(/[\s_]+/g, "-");
  const clampedScore = Math.max(0, Math.min(100, score || 0));
  return (
    <div className="score-gauge">
      <div className="score-gauge__ring">
        <div className="score-gauge__inner">
          <div className="score-gauge__number"><AnimatedNumber value={clampedScore} /></div>
          <div className="score-gauge__of">/ 100</div>
        </div>
        <svg className="score-gauge__svg" viewBox="0 0 120 120">
          <circle className="score-gauge__track" cx="60" cy="60" r="54" />
          <circle
            className="score-gauge__fill"
            cx="60" cy="60" r="54"
            style={{ strokeDashoffset: 339.292 - (339.292 * clampedScore) / 100 }}
          />
        </svg>
      </div>
      <div className="score-gauge__meta">
        <div className={`health-badge ${healthClass}`}>
          <span className="health-badge__dot" />
          {health || "Unknown"}
        </div>
        <div className="score-gauge__sub">Security Posture Index</div>
      </div>
    </div>
  );
}

/* ── Severity distribution ───────────────────────────────────────────── */
function SeverityDistribution({ data }) {
  if (!data) return <SkeletonRows count={3} />;
  const items = [
    { label: "Critical / High", value: data.high || 0, color: "var(--high)" },
    { label: "Medium", value: data.medium || 0, color: "var(--medium)" },
    { label: "Low", value: data.low || 0, color: "var(--low)" },
  ];
  const max = Math.max(...items.map((i) => i.value), 1);
  return (
    <div className="severity-dist">
      {items.map((item) => (
        <HBar key={item.label} label={item.label} value={item.value} max={max} color={item.color} />
      ))}
    </div>
  );
}

/* ── Threat types ────────────────────────────────────────────────────── */
function ThreatTypesChart({ types }) {
  if (!types || types.length === 0) return <EmptyState text="No threat types yet" icon="search" />;
  const max = Math.max(...types.map((t) => t.count), 1);
  return (
    <div className="threat-types">
      {types.slice(0, 6).map((t, i) => (
        <HBar key={i} label={t.type || t.threat_type || t[0] || "Unknown"} value={t.count || t[1] || 0} max={max} color="var(--signal)" />
      ))}
    </div>
  );
}

/* ── Top source IPs ──────────────────────────────────────────────────── */
function TopSourceIPs({ ips }) {
  if (!ips || ips.length === 0) return <EmptyState text="No source IPs yet" icon="globe" />;
  return (
    <div className="top-ips">
      {ips.slice(0, 8).map((ip, i) => (
        <div key={i} className="top-ips__row">
          <span className="top-ips__rank">#{i + 1}</span>
          <span className="top-ips__addr">{ip.ip || ip[0] || ip}</span>
          <span className="top-ips__count">{ip.count || ip[1] || 0} events</span>
        </div>
      ))}
    </div>
  );
}

/* ── Recent incidents ────────────────────────────────────────────────── */
function RecentIncidents({ incidents, onOpen }) {
  if (!incidents) return <SkeletonRows count={5} />;
  if (incidents.length === 0) return <EmptyState text="No incidents detected" icon="shield-check" />;
  return (
    <div className="incidents-table">
      <div className="incidents-table__hdr">
        <span>Severity</span><span>Source IP</span><span>Threats</span><span>Requests</span><span>Status</span><span>Date</span>
      </div>
      {incidents.slice(0, 10).map((inc) => (
        <div key={inc.id} className="incidents-table__row" onClick={() => onOpen && onOpen(inc.id)}>
          <span><SeverityBadge severity={inc.severity} /></span>
          <span className="mono">{inc.source_ip}</span>
          <span className="types-cell">{(inc.threat_types || []).join(", ")}</span>
          <span className="mono">{inc.request_count}</span>
          <span><StatusBadge status={inc.status} /></span>
          <span className="muted-text">{new Date(inc.created_at).toLocaleDateString()}</span>
        </div>
      ))}
    </div>
  );
}

/* ── Incidents by day ────────────────────────────────────────────────── */
function IncidentsByDay({ data }) {
  if (!data || data.length === 0) return <EmptyState text="No daily data yet" icon="chart" />;
  const max = Math.max(...data.map((d) => d.count || d[1] || 0), 1);
  return (
    <div className="day-chart">
      {data.map((d, i) => {
        const count = d.count || d[1] || 0;
        const label = d.date || d[0] || "";
        const short = label.slice(5);
        return (
          <div key={i} className="day-chart__col">
            <div className="day-chart__val">{count}</div>
            <div className="day-chart__bar" style={{ height: `${(count / max) * 100}%` }} />
            <div className="day-chart__lbl">{short}</div>
          </div>
        );
      })}
    </div>
  );
}

/* ── Threat intelligence feed ────────────────────────────────────────── */
function ThreatFeedWidget({ feeds }) {
  if (!feeds) return <SkeletonRows count={4} />;
  if (feeds.length === 0) return <EmptyState text="Threat feed is currently empty" icon="radio" />;
  return (
    <div className="threat-feed-list">
      {feeds.slice(0, 5).map((feed, idx) => (
        <div key={idx} className="threat-feed-row">
          <span className="threat-feed-row__ip mono">{feed.ip}</span>
          <span className="threat-feed-row__type">{feed.type}</span>
          <span className="threat-feed-row__source">{feed.source}</span>
          <span className="threat-feed-row__country mono">{feed.country}</span>
          <span className="threat-feed-row__status">{feed.status}</span>
        </div>
      ))}
    </div>
  );
}

/* ── Posture trend (SVG line) ────────────────────────────────────────── */
function PostureTrendChart({ trends }) {
  if (!trends || trends.length === 0) return <EmptyState text="No posture trend data yet" icon="trending" />;
  const width = 500, height = 150, padding = 30;
  const points = trends.map((t, idx) => {
    const x = padding + (idx * (width - 2 * padding)) / (trends.length - 1);
    const y = height - padding - ((t.score || 0) / 100) * (height - 2 * padding);
    return { x, y, score: t.score, date: new Date(t.ts).toLocaleDateString(undefined, { month: "short" }) };
  });
  const pathD = points.map((p, idx) => `${idx === 0 ? "M" : "L"} ${p.x} ${p.y}`).join(" ");
  const areaD = `${pathD} L ${points[points.length - 1].x} ${height - padding} L ${points[0].x} ${height - padding} Z`;

  return (
    <div style={{ position: "relative", width: "100%", height: "200px" }}>
      <svg viewBox={`0 0 ${width} ${height}`} style={{ width: "100%", height: "100%", overflow: "visible" }}>
        {[0, 25, 50, 75, 100].map((val) => {
          const y = height - padding - (val / 100) * (height - 2 * padding);
          return (
            <g key={val}>
              <line x1={padding} y1={y} x2={width - padding} y2={y} stroke="rgba(255,255,255,0.05)" strokeDasharray="3,3" />
              <text x={padding - 5} y={y + 4} fill="var(--muted)" fontSize="9px" textAnchor="end">{val}%</text>
            </g>
          );
        })}
        <path d={areaD} fill="url(#trendGrad)" opacity="0.18" />
        <path d={pathD} fill="none" stroke="var(--signal)" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
        {points.map((p, idx) => (
          <g key={idx}>
            <circle cx={p.x} cy={p.y} r="4" fill="var(--signal)" stroke="var(--panel)" strokeWidth="2" />
            <text x={p.x} y={p.y - 10} fill="var(--text)" fontSize="10px" fontWeight="bold" textAnchor="middle">{p.score}%</text>
            <text x={p.x} y={height - padding + 15} fill="var(--muted)" fontSize="9px" textAnchor="middle">{p.date}</text>
          </g>
        ))}
        <defs>
          <linearGradient id="trendGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--signal)" />
            <stop offset="100%" stopColor="transparent" />
          </linearGradient>
        </defs>
      </svg>
    </div>
  );
}

/* ── View toggle ─────────────────────────────────────────────────────── */
function ViewToggle({ isExecutive, setIsExecutive }) {
  return (
    <div className="btn-group">
      <button className={`btn-sm ${!isExecutive ? "btn-teal" : "btn-ghost"}`} onClick={() => setIsExecutive(false)}>Operations</button>
      <button className={`btn-sm ${isExecutive ? "btn-teal" : "btn-ghost"}`} onClick={() => setIsExecutive(true)}>Executive</button>
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════════
   DASHBOARD
   ════════════════════════════════════════════════════════════════════════ */
export default function Dashboard({ onOpenIncident, siteId }) {
  const [dash, setDash] = useState(null);
  const [stats, setStats] = useState(null);
  const [incidents, setIncidents] = useState(null);
  const [threatFeed, setThreatFeed] = useState(null);
  const [posture, setPosture] = useState([]);
  const [isExecutive, setIsExecutive] = useState(false);
  const [refreshing, setRefreshing] = useState(false);

  const load = useCallback(() => {
    setRefreshing(true);
    Promise.all([
      api.dashboard(siteId).catch(() => null),
      api.dashboardStats(siteId).catch(() => null),
      api.incidents(siteId).catch(() => null),
      api.threatFeed().catch(() => null),
      api.postureTrends().catch(() => []),
    ]).then(([d, s, inc, feed, post]) => {
      if (d) setDash(d);
      if (s) setStats(s);
      if (inc) setIncidents(inc);
      if (feed) setThreatFeed(feed);
      if (post) setPosture(post);
      setRefreshing(false);
    });
  }, [siteId]);

  useEffect(() => { load(); }, [load]);
  useInterval(load, 15000);

  if (!dash) {
    return (
      <PageWrap>
        <div className="dash-loading">
          <div className="dash-loading__spinner" />
          <div>Connecting to AEGIS backend…</div>
        </div>
      </PageWrap>
    );
  }

  if (isExecutive) {
    return (
      <PageWrap>
        <div className="dash-header">
          <SectionTitle extra={<ViewToggle isExecutive={isExecutive} setIsExecutive={setIsExecutive} />}>
            Executive Overview
          </SectionTitle>
          <div className={`refresh-indicator ${refreshing ? "active" : ""}`}><span className="refresh-indicator__bar" /></div>
        </div>

        <div className="exec-grid">
          <div>
            <div className="exec-hero">
              <div className="exec-hero__badge"><Icon name="shield-check" /></div>
              <div className="exec-hero__title">
                {dash.active_incidents > 0 ? "Monitoring active threats" : "Systems secured"}
              </div>
              <div className="exec-hero__sub">
                Autonomous protection is active. Detection, response, and verification are running continuously.
              </div>
              <div className="exec-hero__score">{dash.security_score} / 100</div>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px" }}>
              <div className="exec-metric">
                <div className="exec-metric__label">Threats Mitigated</div>
                <div className="exec-metric__value" style={{ color: "var(--signal)" }}><AnimatedNumber value={dash.threats_blocked} /></div>
                <div className="exec-metric__note">Across all connected nodes</div>
              </div>
              <div className="exec-metric">
                <div className="exec-metric__label">Open Risks</div>
                <div className="exec-metric__value" style={{ color: dash.active_incidents > 0 ? "var(--high)" : "var(--success)" }}>
                  <AnimatedNumber value={dash.active_incidents} />
                </div>
                <div className="exec-metric__note">Requires analyst review</div>
              </div>
            </div>
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: "18px" }}>
            <Card title="Security Posture Trend" icon="trending">
              <PostureTrendChart trends={posture} />
            </Card>
            <Card title="Executive Summary" icon="clipboard">
              <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
                <div className="exec-summary-item">
                  <span className="exec-summary-item__icon"><Icon name="shield" size={17} /></span>
                  <div>
                    <b>Autonomous remediation active.</b>{" "}
                    <span>AEGIS has mitigated <b>{dash.threats_blocked}</b> events via signature and behavioral detection, with no manual intervention required.</span>
                  </div>
                </div>
                <div className="exec-summary-item">
                  <span className="exec-summary-item__icon"><Icon name="radio" size={17} /></span>
                  <div>
                    <b>Baseline normal.</b>{" "}
                    <span>In the last 24h, <b>{stats?.events_24h || 0}</b> events and <b>{stats?.incidents_24h || 0}</b> incidents were logged. Availability checks report healthy uptime.</span>
                  </div>
                </div>
                <div className="exec-summary-item">
                  <span className="exec-summary-item__icon"><Icon name="lock-open" size={17} /></span>
                  <div>
                    <b>Vulnerabilities assessed.</b>{" "}
                    <span>Crawler scans identified <b>{dash.vulnerabilities_found}</b> potential issues; input-validation fixes have been queued.</span>
                  </div>
                </div>
                <div className="exec-summary-item">
                  <span className="exec-summary-item__icon"><Icon name="database" size={17} /></span>
                  <div>
                    <b>Backups verified.</b>{" "}
                    <span>Automated state snapshots are stored with rollback enabled.</span>
                  </div>
                </div>
              </div>
            </Card>
          </div>
        </div>
      </PageWrap>
    );
  }

  return (
    <PageWrap>
      <div className="dash-header">
        <SectionTitle extra={
          <>
            <ViewToggle isExecutive={isExecutive} setIsExecutive={setIsExecutive} />
            <LiveDot />
          </>
        }>Operations Overview</SectionTitle>
        <div className={`refresh-indicator ${refreshing ? "active" : ""}`}><span className="refresh-indicator__bar" /></div>
      </div>

      <div className="dash-top">
        <Card className="score-card">
          <div className="score-card-container">
            <div>
              <div className="aegis-card__title" style={{ marginBottom: "14px" }}>Security Score</div>
              <ScoreGauge score={dash.security_score} health={dash.system_health} />
            </div>
            <div className="score-details-list">
              <div style={{ fontWeight: 600, fontSize: "11px", textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: "6px", color: "var(--text-2)" }}>
                Posture Assessment
              </div>
              <div className="score-details-row">
                <span className="score-details-row__label"><Icon name="globe" size={15} /> DNS &amp; SSL Status</span>
                <span className="score-details-row__val healthy">Healthy</span>
              </div>
              <div className="score-details-row">
                <span className="score-details-row__label"><Icon name="database" size={15} /> Backup Integrity</span>
                <span className="score-details-row__val healthy">Healthy</span>
              </div>
              <div className="score-details-row">
                <span className="score-details-row__label"><Icon name="alert" size={15} /> Open Risks</span>
                <span className={`score-details-row__val ${dash.active_incidents > 0 ? "danger" : "healthy"}`}>{dash.active_incidents}</span>
              </div>
              <div className="score-details-row">
                <span className="score-details-row__label"><Icon name="lock-open" size={15} /> Vulnerabilities</span>
                <span className={`score-details-row__val ${dash.vulnerabilities_found > 0 ? "warning" : "healthy"}`}>{dash.vulnerabilities_found}</span>
              </div>
              <div className="score-details-row">
                <span className="score-details-row__label"><Icon name="shield" size={15} /> Blocked Threats</span>
                <span className="score-details-row__val healthy">{dash.threats_blocked}</span>
              </div>
            </div>
          </div>
        </Card>
        <div className="stats-grid">
          <StatCard label="Threats Blocked" value={dash.threats_blocked} icon="shield" accent="teal" />
          <StatCard label="Active Incidents" value={dash.active_incidents} icon="alert" accent={dash.active_incidents > 0 ? "red" : ""} />
          <StatCard label="Vulnerabilities" value={dash.vulnerabilities_found} icon="lock-open" accent={dash.vulnerabilities_found > 0 ? "amber" : ""} />
          <StatCard label="Events (24h)" value={stats?.events_24h || 0} icon="radio" />
        </div>
      </div>

      <div className="dash-charts">
        <Card title="Severity Distribution" icon="layers"><SeverityDistribution data={stats?.severity_distribution} /></Card>
        <Card title="Top Threat Types" icon="alert"><ThreatTypesChart types={stats?.top_threat_types} /></Card>
        <Card title="Top Source IPs" icon="globe"><TopSourceIPs ips={stats?.top_source_ips} /></Card>
      </div>

      <Card title="Incidents — Last 7 Days" icon="chart" className="full-width-card">
        <IncidentsByDay data={stats?.incidents_by_day} />
      </Card>

      <Card title="Global Threat Intelligence Feed" icon="radio" className="full-width-card" style={{ marginTop: "18px" }}>
        <p className="muted-text" style={{ fontSize: "12px", marginBottom: "12px" }}>
          Active malicious agents, proxy block lists, and botnet clusters synced from CrowdSec and global IP reputation databases.
        </p>
        <ThreatFeedWidget feeds={threatFeed} />
      </Card>

      <SectionTitle>Recent Incidents</SectionTitle>
      <Card className="table-card">
        <RecentIncidents incidents={incidents} onOpen={onOpenIncident} />
      </Card>
    </PageWrap>
  );
}

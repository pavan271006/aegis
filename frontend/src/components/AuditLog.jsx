import { useState, useEffect, useCallback, useMemo } from "react";
import { api } from "../api.js";
import {
  Card, SectionTitle, PageWrap, SkeletonRows, EmptyState, useInterval,
} from "./shared.jsx";

/* ════════════════════════════════════════════════════════════════════════
   AUDIT LOG PAGE
   ════════════════════════════════════════════════════════════════════════ */
export default function AuditLog() {
  const [logs, setLogs] = useState(null);
  const [filterActor, setFilterActor] = useState("all");

  const load = useCallback(() => {
    api.auditLog().then(setLogs).catch(() => setLogs([]));
  }, []);

  useEffect(() => { load(); }, [load]);
  useInterval(load, 15000);

  const filtered = useMemo(() => {
    if (!logs) return null;
    if (filterActor === "all") return logs;
    return logs.filter((l) => (l.actor || "").toLowerCase() === filterActor);
  }, [logs, filterActor]);

  const actors = useMemo(() => {
    if (!logs) return [];
    const set = new Set(logs.map((l) => (l.actor || "unknown").toLowerCase()));
    return Array.from(set);
  }, [logs]);

  return (
    <PageWrap>
      <SectionTitle>Audit Log</SectionTitle>

      <div className="audit-toolbar">
        <div className="filter-tabs">
          <button
            className={`filter-tab ${filterActor === "all" ? "active" : ""}`}
            onClick={() => setFilterActor("all")}
          >
            All
          </button>
          {actors.map((a) => (
            <button
              key={a}
              className={`filter-tab ${filterActor === a ? "active" : ""}`}
              onClick={() => setFilterActor(a)}
            >
              {a.charAt(0).toUpperCase() + a.slice(1)}
            </button>
          ))}
        </div>
      </div>

      <Card className="table-card">
        {filtered === null ? (
          <SkeletonRows count={8} />
        ) : filtered.length === 0 ? (
          <EmptyState text="No audit entries" icon="clipboard" />
        ) : (
          <div className="audit-list">
            {filtered.map((entry, i) => (
              <div key={entry.id || i} className="audit-entry">
                <div className="audit-entry__time">
                  {entry.ts ? new Date(entry.ts).toLocaleString() : "—"}
                </div>
                <div className={`audit-entry__actor ${(entry.actor || "").toLowerCase()}`}>
                  {entry.actor || "system"}
                </div>
                <div className="audit-entry__action">{entry.action}</div>
                <div className="audit-entry__detail">
                  {typeof entry.details === "object" ? JSON.stringify(entry.details) : entry.details || entry.detail || ""}
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>
    </PageWrap>
  );
}

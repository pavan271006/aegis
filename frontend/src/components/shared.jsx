import { useState, useEffect, useRef, useCallback } from "react";
import { Icon } from "./icons.jsx";

/* ── Toast notifications ─────────────────────────────────────────────────
   Module-level bus so any component can call notify(msg, type) without
   threading context through props. Replaces window.alert().
   ──────────────────────────────────────────────────────────────────────── */
let _push = null;
export function notify(message, type = "info") {
  if (_push) _push(message, type);
  else if (typeof console !== "undefined") console.log(`[${type}] ${message}`);
}

const TOAST_ICON = { success: "check-circle", error: "alert", info: "radio" };

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);
  const remove = useCallback((id) => setToasts((t) => t.filter((x) => x.id !== id)), []);

  useEffect(() => {
    _push = (message, type) => {
      const id = Date.now() + Math.random();
      setToasts((t) => [...t, { id, message, type }]);
      setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 4200);
    };
    return () => { _push = null; };
  }, []);

  return (
    <>
      {children}
      <div className="toast-wrap">
        {toasts.map((t) => (
          <div key={t.id} className={`toast toast--${t.type}`} role="status">
            <span className="toast__icon"><Icon name={TOAST_ICON[t.type] || "radio"} size={17} /></span>
            <span className="toast__msg">{t.message}</span>
            <button className="toast__close" onClick={() => remove(t.id)} aria-label="Dismiss">
              <Icon name="close" size={14} />
            </button>
          </div>
        ))}
      </div>
    </>
  );
}

/* ── Animated count-up ───────────────────────────────────────────────── */
export function AnimatedNumber({ value, duration = 1000 }) {
  const [display, setDisplay] = useState(0);
  const prev = useRef(0);
  const raf = useRef(null);

  useEffect(() => {
    const from = prev.current;
    const to = typeof value === "number" ? value : parseInt(value) || 0;
    const start = performance.now();
    function tick(now) {
      const t = Math.min((now - start) / duration, 1);
      const ease = 1 - Math.pow(1 - t, 3);
      setDisplay(Math.round(from + (to - from) * ease));
      if (t < 1) raf.current = requestAnimationFrame(tick);
    }
    raf.current = requestAnimationFrame(tick);
    prev.current = to;
    return () => cancelAnimationFrame(raf.current);
  }, [value, duration]);

  return <span>{display.toLocaleString()}</span>;
}

/* ── Badges ──────────────────────────────────────────────────────────── */
export function SeverityBadge({ severity }) {
  const s = (severity || "info").toLowerCase();
  return <span className={`sev-badge ${s}`}>{s}</span>;
}

export function StatusBadge({ status }) {
  const s = (status || "unknown").toLowerCase();
  const cls = s === "resolved" ? "resolved" : s === "contained" ? "contained" : "open";
  return <span className={`status-badge ${cls}`}>{status}</span>;
}

/* ── Stat card ───────────────────────────────────────────────────────── */
export function StatCard({ label, value, icon, accent }) {
  return (
    <div className={`stat-card ${accent || ""}`}>
      <div className="stat-card__icon"><Icon name={icon} size={20} /></div>
      <div className="stat-card__body">
        <div className="stat-card__label">{label}</div>
        <div className="stat-card__value"><AnimatedNumber value={value} /></div>
      </div>
    </div>
  );
}

/* ── Skeletons ───────────────────────────────────────────────────────── */
export function Skeleton({ width, height, style }) {
  return <div className="skeleton" style={{ width: width || "100%", height: height || 18, ...style }} />;
}

export function SkeletonRows({ count = 4 }) {
  return (
    <div className="skeleton-rows">
      {Array.from({ length: count }).map((_, i) => (
        <Skeleton key={i} height={42} style={{ marginBottom: 8, borderRadius: 10 }} />
      ))}
    </div>
  );
}

/* ── Page transition ─────────────────────────────────────────────────── */
export function PageWrap({ children }) {
  const [visible, setVisible] = useState(false);
  useEffect(() => {
    const t = requestAnimationFrame(() => setVisible(true));
    return () => cancelAnimationFrame(t);
  }, []);
  return <div className={`page-wrap ${visible ? "page-wrap--in" : ""}`}>{children}</div>;
}

/* ── Section title ───────────────────────────────────────────────────── */
export function SectionTitle({ children, extra }) {
  return (
    <div className="section-hdr">
      <h2 className="section-title">{children}</h2>
      {extra && <div className="section-extra">{extra}</div>}
    </div>
  );
}

/* ── Empty state ─────────────────────────────────────────────────────── */
export function EmptyState({ icon, text }) {
  return (
    <div className="empty-state">
      <div className="empty-state__icon"><Icon name={icon || "search"} size={22} /></div>
      <div className="empty-state__text">{text || "No data available"}</div>
    </div>
  );
}

/* ── Live indicator ──────────────────────────────────────────────────── */
export function LiveDot() {
  return (
    <span className="live-dot" title="Auto-refreshing">
      <span className="live-dot__ping" />
      <span className="live-dot__core" />
    </span>
  );
}

/* ── Horizontal bar ──────────────────────────────────────────────────── */
export function HBar({ label, value, max, color }) {
  const pct = max > 0 ? (value / max) * 100 : 0;
  return (
    <div className="hbar">
      <div className="hbar__label">{label}</div>
      <div className="hbar__track">
        <div className="hbar__fill" style={{ width: `${pct}%`, background: color || "var(--signal)" }} />
      </div>
      <div className="hbar__val">{value}</div>
    </div>
  );
}

/* ── Mini bar chart ──────────────────────────────────────────────────── */
export function MiniBarChart({ data, labelKey, valueKey, height = 120 }) {
  if (!data || data.length === 0) return <EmptyState text="No chart data" icon="chart" />;
  const max = Math.max(...data.map((d) => d[valueKey]), 1);
  return (
    <div className="mini-bar-chart" style={{ height }}>
      {data.map((d, i) => (
        <div key={i} className="mini-bar-chart__col">
          <div className="mini-bar-chart__bar" style={{ height: `${(d[valueKey] / max) * 100}%` }} title={`${d[labelKey]}: ${d[valueKey]}`} />
          <div className="mini-bar-chart__lbl">{d[labelKey]}</div>
        </div>
      ))}
    </div>
  );
}

/* ── Card ────────────────────────────────────────────────────────────── */
export function Card({ title, icon, children, className, style }) {
  return (
    <div className={`aegis-card ${className || ""}`} style={style}>
      {title && (
        <div className="aegis-card__title">
          {icon && <Icon name={icon} size={15} />}
          {title}
        </div>
      )}
      <div className="aegis-card__body">{children}</div>
    </div>
  );
}

/* ── useInterval ─────────────────────────────────────────────────────── */
export function useInterval(callback, delay) {
  const saved = useRef();
  useEffect(() => { saved.current = callback; }, [callback]);
  useEffect(() => {
    if (delay === null) return;
    const id = setInterval(() => saved.current(), delay);
    return () => clearInterval(id);
  }, [delay]);
}

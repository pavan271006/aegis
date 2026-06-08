// AEGIS ingest load test (k6). Ramps through the four daily-volume tiers and
// enforces SLO thresholds (the run FAILS if p95 or error rate regress).
//
//   k6 run -e HOST=https://api.aegis.example.com -e API_KEY=... load/k6_ingest.js
//
// Stages approximate sustained + peak RPS for each tier; adjust VUs to your infra.
import http from "k6/http";
import { check, sleep } from "k6";
import { Trend, Counter } from "k6/metrics";

const HOST = __ENV.HOST || "http://localhost:8000";
const API_KEY = __ENV.API_KEY || "change-me";

const ingestLatency = new Trend("ingest_latency_ms", true);
const detections = new Counter("attack_batches_sent");

export const options = {
  scenarios: {
    tiered: {
      executor: "ramping-arrival-rate",
      startRate: 1, timeUnit: "1s", preAllocatedVUs: 50, maxVUs: 400,
      stages: [
        { target: 1, duration: "2m" },    // ~100k/day equivalent warm-up
        { target: 12, duration: "5m" },   // ~1M/day sustained
        { target: 116, duration: "3m" },  // 10x peak burst
        { target: 12, duration: "5m" },   // recover
        { target: 0, duration: "1m" },
      ],
    },
  },
  thresholds: {
    http_req_duration: ["p(95)<800", "p(99)<2000"],
    http_req_failed: ["rate<0.01"],
    ingest_latency_ms: ["p(95)<800"],
  },
};

function ip() { return `203.0.113.${Math.floor(Math.random() * 254) + 1}`; }

export default function () {
  const n = 20 + Math.floor(Math.random() * 40);
  const lines = [];
  for (let i = 0; i < n; i++) {
    lines.push(`${ip()} - - [01/Jun/2024:12:00:00 +0000] "GET /products HTTP/1.1" 200 512 "-" "Mozilla/5.0"`);
  }
  if (Math.random() < 0.1) {
    lines.push(`${ip()} - - [01/Jun/2024:12:00:00 +0000] "GET /p?id=1 UNION SELECT pw FROM users-- HTTP/1.1" 200 0 "-" "sqlmap"`);
    detections.add(1);
  }
  const res = http.post(`${HOST}/api/ingest`,
    JSON.stringify({ site_id: 1, log_lines: lines }),
    { headers: { "Content-Type": "application/json", "X-API-Key": API_KEY } });
  ingestLatency.add(res.timings.duration);
  check(res, { "ingest 200": (r) => r.status === 200 });
  sleep(Math.random() * 0.5);
}

"""AEGIS load test (Locust). Drives the ingest closed loop + read paths.

Targets (events/day -> sustained RPS to hold for the run):
    1,000/day      ~0.012 rps   (smoke)
    10,000/day     ~0.12  rps
    100,000/day    ~1.2   rps
    1,000,000/day  ~11.6  rps    (bursty; also run a 10x peak: ~116 rps)

Run:  locust -f load/locustfile.py --host https://api.aegis.example.com \
        -u 120 -r 20 --run-time 15m --csv results/run
Watch alongside Prometheus /metrics: aegis_http_request_seconds (p50/p95/p99),
aegis_ingest_lag_seconds, aegis_detections_total, DB + Redis dashboards.
"""
import json
import random
import time

from locust import HttpUser, between, events, task

API_KEY = "REPLACE"        # shipper key for /api/ingest
BEARER = "REPLACE"         # console JWT for read paths

ATTACK_LINES = [
    '{ip} - - [01/Jun/2024:12:00:00 +0000] "GET /p?id=1 UNION SELECT pw FROM users-- HTTP/1.1" 200 0 "-" "sqlmap"',
    '{ip} - - [01/Jun/2024:12:00:00 +0000] "POST /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"',
    '{ip} - - [01/Jun/2024:12:00:00 +0000] "GET /.env HTTP/1.1" 404 0 "-" "curl/7.68"',
]
BENIGN = '{ip} - - [01/Jun/2024:12:00:00 +0000] "GET /products HTTP/1.1" 200 512 "-" "Mozilla/5.0"'


def _ip():
    return f"203.0.113.{random.randint(1, 254)}"


class Shipper(HttpUser):
    """Simulates the agent shipping a batch of log lines each tick."""
    wait_time = between(1, 3)

    @task(5)
    def ingest_batch(self):
        n = random.randint(20, 60)
        lines = [BENIGN.format(ip=_ip()) for _ in range(n)]
        if random.random() < 0.1:                      # 10% of batches carry an attack
            lines.append(random.choice(ATTACK_LINES).format(ip=_ip()))
        self.client.post("/api/ingest", name="POST /api/ingest",
                         headers={"X-API-Key": API_KEY},
                         json={"site_id": 1, "log_lines": lines})


class Analyst(HttpUser):
    """Simulates a console operator polling dashboards/incidents."""
    wait_time = between(2, 8)

    def on_start(self):
        self.h = {"Authorization": f"Bearer {BEARER}"}

    @task(3)
    def dashboard(self):
        self.client.get("/api/dashboard", name="GET /api/dashboard", headers=self.h)

    @task(2)
    def incidents(self):
        self.client.get("/api/incidents", name="GET /api/incidents", headers=self.h)

    @task(1)
    def stats(self):
        self.client.get("/api/dashboard/stats", name="GET /api/dashboard/stats", headers=self.h)


# SLO gate: fail the run in CI if p95 latency or error rate regress.
@events.quitting.add_listener
def _assert_slos(environment, **_):
    stats = environment.stats.total
    p95 = stats.get_response_time_percentile(0.95)
    err = stats.fail_ratio
    print(f"SLO check: p95={p95}ms err={err:.3%}")
    if p95 and p95 > 800:
        environment.process_exit_code = 1
    if err > 0.01:
        environment.process_exit_code = 1

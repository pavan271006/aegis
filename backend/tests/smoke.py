"""Smoke test: boots the app, ingests known attacks, asserts incidents are
detected and benign traffic is not. Run by CI: python -m tests.smoke"""
import warnings
warnings.filterwarnings("ignore")

from fastapi.testclient import TestClient
from app.main import app


def mk(ip, method, path, status):
    return (f'{ip} - - [01/Jun/2024:12:00:00 +0000] "{method} {path} HTTP/1.1" '
            f'{status} 512 "-" "Mozilla/5.0"')


def run():
    with TestClient(app) as c:
        assert c.get("/health").json()["status"] == "ok"

        lines = [mk("10.0.0.5", "GET", "/products", 200) for _ in range(10)]
        lines.append(mk("203.0.113.10", "GET",
                        "/p?id=1%20UNION%20SELECT%20pw%20FROM%20users--", 200))
        lines += [mk("192.0.2.50", "POST", "/login", 401) for _ in range(12)]
        lines.append('192.0.2.77 - - [01/Jun/2024:12:00:00 +0000] '
                     '"GET /.env HTTP/1.1" 404 0 "-" "sqlmap/1.7"')

        r = c.post("/api/ingest", json={"site_id": 1, "log_lines": lines},
                   headers={"X-API-Key": "change-me"})
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["incidents_created"] >= 3, data

        incs = c.get("/api/incidents").json()
        ips = {i["source_ip"] for i in incs}
        assert "203.0.113.10" in ips        # sqli detected
        assert "192.0.2.50" in ips          # credential stuffing detected
        assert "192.0.2.77" in ips          # honeypot detected
        assert "10.0.0.5" not in ips        # benign NOT flagged (no false positive)

        # auth must be enforced
        assert c.post("/api/ingest", json={"site_id": 1, "log_lines": []}).status_code == 401
        print("SMOKE TEST PASSED:", len(incs), "incidents,", "0 false positives")


if __name__ == "__main__":
    run()

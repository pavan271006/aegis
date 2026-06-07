#!/usr/bin/env python3
"""shipper.py -- runs on the client's web server. Tails the access log and
POSTs new lines to AEGIS Lite's /api/ingest endpoint. This is how real traffic
reaches the detection engine.

Tracks its position in a small offset file so it only sends new lines. Run it
from cron every minute, or as a systemd service.

Env:
  AEGIS_URL     e.g. https://aegis.yourdomain.com
  AEGIS_API_KEY the API_KEY from your backend .env
  LOG_PATH      e.g. /var/log/nginx/access.log
  SITE_ID       defaults to 1
  OFFSET_FILE   defaults to /tmp/aegis_offset
"""
import os
import json
import urllib.request

URL = os.environ.get("AEGIS_URL", "http://localhost:8000").rstrip("/")
KEY = os.environ.get("AEGIS_API_KEY", "change-me")
LOG_PATH = os.environ.get("LOG_PATH", "/var/log/nginx/access.log")
SITE_ID = int(os.environ.get("SITE_ID", "1"))
OFFSET_FILE = os.environ.get("OFFSET_FILE", "/tmp/aegis_offset")
BATCH = 500


def read_offset():
    try:
        with open(OFFSET_FILE) as f:
            return int(f.read().strip())
    except Exception:  # noqa: BLE001
        return 0


def write_offset(n):
    with open(OFFSET_FILE, "w") as f:
        f.write(str(n))


def ship(lines):
    body = json.dumps({"site_id": SITE_ID, "log_lines": lines}).encode()
    req = urllib.request.Request(
        f"{URL}/api/ingest", data=body, method="POST",
        headers={"Content-Type": "application/json", "X-API-Key": KEY},
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def main():
    size = os.path.getsize(LOG_PATH)
    offset = read_offset()
    if offset > size:        # log was rotated
        offset = 0
    if offset == size:
        print("[shipper] no new lines")
        return
    with open(LOG_PATH, "r", errors="ignore") as f:
        f.seek(offset)
        lines = f.readlines()
        new_offset = f.tell()
    for i in range(0, len(lines), BATCH):
        result = ship([ln.rstrip("\n") for ln in lines[i:i + BATCH]])
        print(f"[shipper] sent batch: {result}")
    write_offset(new_offset)


if __name__ == "__main__":
    main()

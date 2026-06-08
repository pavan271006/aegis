"""SIEM event forwarding.

`emit()` durably enqueues a normalized event (Redis list); a background worker
drains it and fans out to every enabled SIEM connection for that org. Formatters:
JSON and ArcSight CEF. Sinks: Splunk HEC, Microsoft Sentinel (Log Analytics),
Elastic bulk, syslog (TCP/UDP), generic signed webhook. Per-connection
last_ok/last_error are recorded for the admin UI."""
import base64
import datetime as dt
import hashlib
import hmac
import json
import socket

import httpx
import redis

from . import crypto
from .models_p2 import SiemConnection
from .settings import get_settings
from .tenancy import tenant_session

_r = redis.Redis.from_url(get_settings().redis_url, decode_responses=True)
QUEUE = "siem:queue"


# ── public API ─────────────────────────────────────────────────────────────
def emit(org_id: str, event_type: str, payload: dict) -> None:
    """Enqueue an event for forwarding (call from incident/auth/audit paths)."""
    evt = {
        "ts": dt.datetime.now(dt.timezone.utc).isoformat(),
        "org_id": str(org_id), "type": event_type,
        "product": "AEGIS", "payload": payload,
    }
    try:
        _r.rpush(QUEUE, json.dumps(evt))
    except redis.RedisError:
        pass  # never let telemetry forwarding break the request path


# ── formatters ───────────────────────────────────────────────────────────
def to_json(evt: dict) -> str:
    return json.dumps(evt, separators=(",", ":"))


def _cef_escape(value) -> str:
    return str(value).replace("\\", "\\\\").replace("=", "\\=")


def to_cef(evt: dict) -> str:
    p = evt.get("payload", {})
    sev = {"high": 8, "medium": 5, "low": 2}.get(p.get("severity", ""), 3)
    fields = {"src": p.get("source_ip"), "act": p.get("action"),
              "msg": p.get("threat_types")}
    ext = " ".join(f"{k}={_cef_escape(v)}" for k, v in fields.items() if v)
    return (f"CEF:0|AEGIS|AEGIS|2.0|{evt['type']}|{evt['type']}|{sev}|"
            f"rt={evt['ts']} {ext}")


def _format(conn: SiemConnection, evt: dict) -> str:
    return to_cef(evt) if conn.format == "cef" else to_json(evt)


# ── sinks ──────────────────────────────────────────────────────────────────
def _send(conn: SiemConnection, evt: dict) -> None:
    secret = crypto.decrypt(conn.secret_enc).decode() if conn.secret_enc else ""
    body = _format(conn, evt)
    if conn.kind == "splunk_hec":
        httpx.post(conn.endpoint, headers={"Authorization": f"Splunk {secret}"},
                   json={"event": evt, "sourcetype": "aegis"}, timeout=8,
                   verify=conn.options.get("verify_tls", True)).raise_for_status()
    elif conn.kind == "sentinel":
        _send_sentinel(conn, secret, evt)
    elif conn.kind == "elastic":
        ndjson = json.dumps({"index": {}}) + "\n" + to_json(evt) + "\n"
        httpx.post(conn.endpoint.rstrip("/") + "/aegis-events/_bulk",
                   headers={"Authorization": f"ApiKey {secret}",
                            "Content-Type": "application/x-ndjson"},
                   content=ndjson, timeout=8).raise_for_status()
    elif conn.kind in ("syslog",):
        host, _, port = conn.endpoint.partition(":")
        proto = conn.options.get("proto", "udp")
        s = socket.socket(socket.AF_INET,
                          socket.SOCK_DGRAM if proto == "udp" else socket.SOCK_STREAM)
        s.settimeout(5)
        if proto != "udp":
            s.connect((host, int(port or 514)))
            s.sendall((body + "\n").encode())
        else:
            s.sendto((body + "\n").encode(), (host, int(port or 514)))
        s.close()
    else:  # webhook / chronicle (generic signed POST)
        sig = hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()
        httpx.post(conn.endpoint, content=body, timeout=8,
                   headers={"Content-Type": "application/json",
                            "X-AEGIS-Signature": f"sha256={sig}"}).raise_for_status()


def _send_sentinel(conn: SiemConnection, shared_key: str, evt: dict) -> None:
    """Microsoft Sentinel / Log Analytics HTTP Data Collector (signed request)."""
    workspace = conn.options["workspace_id"]
    body = to_json(evt)
    rfc1123 = dt.datetime.now(dt.timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
    to_sign = f"POST\n{len(body)}\napplication/json\nx-ms-date:{rfc1123}\n/api/logs"
    digest = hmac.new(base64.b64decode(shared_key), to_sign.encode(), hashlib.sha256).digest()
    auth = f"SharedKey {workspace}:{base64.b64encode(digest).decode()}"
    url = f"https://{workspace}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
    httpx.post(url, content=body, timeout=8, headers={
        "Content-Type": "application/json", "Authorization": auth,
        "Log-Type": "AEGIS", "x-ms-date": rfc1123,
    }).raise_for_status()


# ── worker (run as a sidecar / background task) ────────────────────────────
def drain_once(block_seconds: int = 5) -> bool:
    item = _r.blpop(QUEUE, timeout=block_seconds)
    if not item:
        return False
    evt = json.loads(item[1])
    with tenant_session(evt["org_id"]) as db:
        conns = db.query(SiemConnection).filter(SiemConnection.enabled.is_(True)).all()
        for conn in conns:
            try:
                _send(conn, evt)
                conn.last_ok_at = dt.datetime.now(dt.timezone.utc)
                conn.last_error = None
            except Exception as e:   # noqa: BLE001 — record, keep draining
                conn.last_error = str(e)[:500]
                _r.rpush(QUEUE + ":dlq", json.dumps({"conn": str(conn.id), "evt": evt}))
    return True


def run_worker() -> None:  # pragma: no cover
    while True:
        try:
            drain_once()
        except Exception:
            pass

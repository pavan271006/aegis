"""CrowdSec integration. CrowdSec is a free, open-source behavioral IPS that
auto-detects scans/brute-force and shares a community blocklist.

Two directions:
  * pull_decisions(): read CrowdSec's current bans (its LAPI) so AEGIS can show
    them and optionally mirror them into Cloudflare.
  * Events from CrowdSec can also be POSTed to /ingest with source='crowdsec'.

No-op unless CROWDSEC_URL + CROWDSEC_API_KEY are set."""
import httpx

from ..config import settings


def configured() -> bool:
    return bool(settings.crowdsec_url and settings.crowdsec_api_key)


def pull_decisions() -> list:
    """Return current CrowdSec ban decisions: [{ip, scenario, duration}, ...]."""
    if not configured():
        return []
    try:
        r = httpx.get(
            f"{settings.crowdsec_url.rstrip('/')}/v1/decisions",
            headers={"X-Api-Key": settings.crowdsec_api_key}, timeout=15,
        )
        out = []
        for d in r.json() or []:
            out.append({"ip": d.get("value"), "scenario": d.get("scenario", ""),
                        "duration": d.get("duration", ""), "type": d.get("type", "ban")})
        return out
    except Exception:  # noqa: BLE001
        return []


def push_decision(ip: str, reason: str, duration: str = "24h") -> dict:
    """Push an AEGIS detection back to CrowdSec LAPI as a new decision."""
    if not configured():
        return {"ok": False, "detail": "crowdsec not configured"}
    try:
        r = httpx.post(
            f"{settings.crowdsec_url.rstrip('/')}/v1/decisions",
            headers={"X-Api-Key": settings.crowdsec_api_key},
            json=[{
                "duration": duration,
                "origin": "aegis-lite",
                "scenario": f"aegis/{reason}",
                "scope": "ip",
                "type": "ban",
                "value": ip,
            }],
            timeout=15,
        )
        return {"ok": r.status_code in (200, 201), "detail": r.text}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "detail": str(e)}

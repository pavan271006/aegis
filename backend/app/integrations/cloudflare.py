"""Cloudflare integration: create/verify/delete IP Access Rules (free plan).
All calls are no-ops unless a token + zone are configured."""
import httpx

from ..config import settings

BASE = "https://api.cloudflare.com/client/v4"


def _headers():
    return {"Authorization": f"Bearer {settings.cf_api_token}", "Content-Type": "application/json"}


def configured() -> bool:
    return bool(settings.cf_api_token and settings.cf_zone_id)


def block_ip(ip: str, note: str) -> dict:
    if not configured():
        return {"ok": False, "rule_id": None, "detail": "cloudflare not configured"}
    try:
        r = httpx.post(
            f"{BASE}/zones/{settings.cf_zone_id}/firewall/access_rules/rules",
            headers=_headers(), timeout=20,
            json={"mode": "block", "configuration": {"target": "ip", "value": ip},
                  "notes": f"AEGIS Lite: {note}"},
        )
        data = r.json()
        rid = (data.get("result") or {}).get("id")
        return {"ok": data.get("success", False), "rule_id": rid, "detail": data.get("errors")}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "rule_id": None, "detail": str(e)}


def verify_block(ip: str) -> bool:
    if not configured():
        return False
    try:
        r = httpx.get(
            f"{BASE}/zones/{settings.cf_zone_id}/firewall/access_rules/rules",
            headers=_headers(), timeout=20,
            params={"configuration.target": "ip", "configuration.value": ip},
        )
        return bool(r.json().get("result"))
    except Exception:  # noqa: BLE001
        return False


def unblock(rule_id: str) -> bool:
    if not configured() or not rule_id:
        return False
    try:
        r = httpx.delete(
            f"{BASE}/zones/{settings.cf_zone_id}/firewall/access_rules/rules/{rule_id}",
            headers=_headers(), timeout=20,
        )
        return r.json().get("success", False)
    except Exception:  # noqa: BLE001
        return False

"""Wazuh integration — pull alerts and convert to AEGIS events.

No-op unless WAZUH_URL + WAZUH_USER + WAZUH_PASSWORD are set in config."""
import logging

import httpx

from ..config import settings

log = logging.getLogger(__name__)


def configured() -> bool:
    """Return True if Wazuh connection details are configured."""
    return bool(settings.wazuh_url and settings.wazuh_user and settings.wazuh_password)


def _authenticate() -> str | None:
    """Authenticate with Wazuh API and return a JWT token."""
    if not configured():
        return None
    try:
        r = httpx.post(
            f"{settings.wazuh_url.rstrip('/')}/security/user/authenticate",
            auth=(settings.wazuh_user, settings.wazuh_password),
            verify=False,  # Wazuh often uses self-signed certs
            timeout=15,
        )
        r.raise_for_status()
        return r.json().get("data", {}).get("token")
    except Exception as e:  # noqa: BLE001
        log.warning("Wazuh authentication failed: %s", e)
        return None


def pull_alerts(since_minutes: int = 5) -> list[dict]:
    """Pull recent alerts from Wazuh and convert them to AEGIS event dicts.

    Each returned dict has the same shape as EventIn:
    ``{ip, method, path, status, user_agent, source}``.
    """
    if not configured():
        return []

    token = _authenticate()
    if not token:
        return []

    try:
        r = httpx.get(
            f"{settings.wazuh_url.rstrip('/')}/alerts",
            headers={"Authorization": f"Bearer {token}"},
            params={"limit": 500, "sort": "-timestamp",
                    "q": f"timestamp>{since_minutes}m"},
            verify=False,
            timeout=20,
        )
        r.raise_for_status()
        raw_alerts = r.json().get("data", {}).get("affected_items", [])
    except Exception as e:  # noqa: BLE001
        log.warning("Wazuh pull_alerts failed: %s", e)
        return []

    events = []
    for alert in raw_alerts:
        agent = alert.get("agent", {})
        data = alert.get("data", {})
        rule = alert.get("rule", {})

        ip = (data.get("srcip") or data.get("src_ip")
              or agent.get("ip") or "0.0.0.0")
        path = data.get("url", rule.get("description", ""))
        events.append({
            "ip": ip,
            "method": data.get("method", "GET"),
            "path": path[:500],
            "status": int(data.get("status", 0)) or 0,
            "user_agent": data.get("user_agent", ""),
            "source": "wazuh",
        })

    log.info("Pulled %d alerts from Wazuh", len(events))
    return events

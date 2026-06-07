"""Free GeoIP enrichment via ip-api.com (no key, rate-limited free tier).
Returns 'City, Country' for context in incidents. Fails open (returns '')."""
import httpx

from ..config import settings


def lookup(ip: str) -> str:
    if not settings.geoip_enabled or not ip:
        return ""
    # skip private ranges
    if ip.startswith(("10.", "192.168.", "127.", "172.16.")):
        return "private/internal"
    try:
        r = httpx.get(f"http://ip-api.com/json/{ip}",
                      params={"fields": "status,country,city"}, timeout=8)
        d = r.json()
        if d.get("status") == "success":
            return ", ".join(x for x in (d.get("city"), d.get("country")) if x)
    except Exception:  # noqa: BLE001
        pass
    return ""

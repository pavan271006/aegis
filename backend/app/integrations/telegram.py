"""Telegram alerting. Sends incident alerts and a weekly digest.
No-op unless TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID are set."""
import httpx

from ..config import settings


def configured() -> bool:
    return bool(settings.telegram_bot_token and settings.telegram_chat_id)


def send(text: str) -> bool:
    if not configured():
        try:
            print("[telegram] not configured; message:\n" + text)
        except UnicodeEncodeError:
            print("[telegram] not configured; message:\n" + text.encode("ascii", errors="replace").decode("ascii"))
        return False
    try:
        httpx.post(
            f"https://api.telegram.org/bot{settings.telegram_bot_token}/sendMessage",
            json={"chat_id": settings.telegram_chat_id, "text": text}, timeout=15,
        )
        return True
    except Exception as e:  # noqa: BLE001
        print(f"[telegram] failed: {e}")
        return False


def alert_incident(report: dict) -> None:
    send(
        f"🚨 AEGIS Lite incident\n"
        f"Threat: {report['threat_type']}\n"
        f"Source: {report['source']}\n"
        f"Severity: {report['severity']}\n"
        f"Action: {report['actions_taken']}\n"
        f"Status: {report['final_status']}"
    )


def weekly_digest(stats: dict) -> None:
    send(
        f"📊 AEGIS Lite weekly digest\n"
        f"Security score: {stats.get('security_score')}\n"
        f"Threats blocked: {stats.get('threats_blocked')}\n"
        f"Active incidents: {stats.get('active_incidents')}\n"
        f"Vulnerabilities: {stats.get('vulnerabilities_found')}\n"
        f"Health: {stats.get('system_health')}"
    )

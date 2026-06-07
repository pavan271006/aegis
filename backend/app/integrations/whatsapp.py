"""WhatsApp alerting. Formats and sends structured incident alerts.
Fallback print contains UnicodeEncodeError protection on Windows consoles."""
import httpx

from ..config import settings


def configured() -> bool:
    # Currently a stub for custom WhatsApp API or Twilio hook integration
    return False


def send(text: str) -> bool:
    if not configured():
        try:
            print("[whatsapp] not configured; message:\n" + text)
        except UnicodeEncodeError:
            print("[whatsapp] not configured; message:\n" + text.encode("ascii", errors="replace").decode("ascii"))
        return False
    return True


def alert_incident(report: dict) -> None:
    send(
        f"🚨 *AEGIS Security incident*\n"
        f"*Threat:* {report['threat_type']}\n"
        f"*Source:* {report['source']}\n"
        f"*Severity:* {report['severity']}\n"
        f"*Action:* {report['actions_taken']}\n"
        f"*Status:* {report['final_status']}"
    )

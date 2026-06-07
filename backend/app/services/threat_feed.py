"""Threat Intelligence Feed service.

Simulates and synchronizes threat feeds of known malicious botnets, Tor nodes,
and phishing IPs. Automatically imports them as blocked targets."""
import logging
from sqlalchemy.orm import Session
from ..integrations import crowdsec

log = logging.getLogger(__name__)

# Seeding a set of known malicious feeds for demonstration
GLOBAL_FEEDS = [
    {"ip": "185.220.101.5", "type": "Tor Exit Node", "source": "Tor Project", "country": "DE", "status": "blocked"},
    {"ip": "45.143.203.14", "type": "BruteForce Botnet", "source": "Blocklist.de", "country": "RU", "status": "blocked"},
    {"ip": "81.92.203.22", "type": "Phishing Host", "source": "PhishTank", "country": "NL", "status": "blocked"},
    {"ip": "103.245.14.92", "type": "Web Scanner", "source": "CrowdSec Community", "country": "CN", "status": "blocked"},
    {"ip": "194.26.192.17", "type": "Malware C2 Server", "source": "Spamhaus", "country": "UA", "status": "blocked"},
]


def get_active_feeds(db: Session) -> list[dict]:
    """Retrieve combined threat intelligence lists (global seeds + CrowdSec decisions)."""
    feed_list = list(GLOBAL_FEEDS)

    # Fetch real live decisions from CrowdSec if configured
    decisions = crowdsec.pull_decisions()
    for d in decisions:
        feed_list.append({
            "ip": d.get("ip") or d.get("value"),
            "type": d.get("scenario") or "Community Ban",
            "source": "CrowdSec LAPI",
            "country": "Unknown",
            "status": "blocked"
        })

    return feed_list

import random
import threading
import time
import httpx
from ..config import settings

_running = False
_thread = None
_mode = "clean" # clean | attack
_request_count = 0

CLEAN_PATHS = [
    "/", "/index.html", "/products", "/pricing", "/about", "/contact",
    "/static/js/main.js", "/static/css/styles.css", "/blog/post-1", "/help"
]

CLEAN_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"
]

ATTACK_PAYLOADS = [
    {"path": "/?id=1%20UNION%20SELECT%20username%20FROM%20users--", "ua": "sqlmap/1.4.12", "status": 200, "source": "test_sqli"},
    {"path": "/?q=<script>alert('xss')</script>", "ua": "Mozilla/5.0 (Windows NT 10.0)", "status": 200, "source": "test_xss"},
    {"path": "/.env", "ua": "Mozilla/5.0", "status": 404, "source": "honeypot"},
    {"path": "/wp-admin/setup-config.php", "ua": "Mozilla/5.0", "status": 404, "source": "honeypot"},
    {"path": "/../../etc/passwd", "ua": "curl/7.68.0", "status": 400, "source": "test_traversal"},
    {"path": "/login", "ua": "Mozilla/5.0", "status": 401, "source": "test_brute_force"}, # failed auth
]


def start_simulator(mode: str = "clean"):
    global _running, _thread, _mode, _request_count
    if _running:
        _mode = mode
        return
        
    _running = True
    _mode = mode
    _request_count = 0
    
    _thread = threading.Thread(target=_simulation_loop)
    _thread.daemon = True
    _thread.start()


def stop_simulator():
    global _running
    _running = False


def get_status() -> dict:
    return {
        "running": _running,
        "mode": _mode,
        "requests_generated": _request_count
    }


def _simulation_loop():
    global _running, _request_count
    
    api_key = settings.api_key or "test-key"
    url = "http://localhost:8000/api/ingest"
    
    # Wait for app start
    time.sleep(2)
    
    while _running:
        events = []
        
        # Determine requests to send
        if _mode == "clean":
            # 1-3 clean requests
            for _ in range(random.randint(1, 3)):
                events.append({
                    "ip": f"192.168.1.{random.randint(10, 250)}",
                    "path": random.choice(CLEAN_PATHS),
                    "status": random.choice([200, 200, 200, 302, 404]),
                    "user_agent": random.choice(CLEAN_UAS),
                    "source": "log"
                })
        else: # attack mode
            # Mix clean and malicious requests
            for _ in range(random.randint(1, 2)):
                events.append({
                    "ip": f"192.168.1.{random.randint(10, 250)}",
                    "path": random.choice(CLEAN_PATHS),
                    "status": 200,
                    "user_agent": random.choice(CLEAN_UAS),
                    "source": "log"
                })
            # Add a malicious payload
            payload = random.choice(ATTACK_PAYLOADS)
            
            # Simulated attacker IP
            attacker_ip = f"185.220.101.{random.randint(1, 20)}"
            events.append({
                "ip": attacker_ip,
                "path": payload["path"],
                "status": payload["status"],
                "user_agent": payload["ua"],
                "source": payload["source"]
            })
            
        # Ship to local Ingestion endpoint
        try:
            with httpx.Client() as client:
                r = client.post(
                    url,
                    headers={"X-API-Key": api_key, "Content-Type": "application/json"},
                    json={"site_id": 1, "events": events, "log_lines": []},
                    timeout=5.0
                )
                if r.status_code == 200:
                    _request_count += len(events)
        except Exception:
            # backend down or restarting
            pass
            
        # Sleep interval
        time.sleep(random.uniform(1.0, 3.0))

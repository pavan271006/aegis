import re
import threading
import httpx
from sqlalchemy.orm import Session
from ..models import Vulnerability, Site
from ..database import SessionLocal

# Global scanning state
scan_status = {
    "status": "idle",
    "scanned_count": 0,
    "current_url": "",
    "vulnerabilities_found": 0,
    "urls_found": []
}

# Regex helpers for zero-dependency HTML parsing
LINK_REGEX = re.compile(r'href=["\'](https?://[^\s"\'>]+|/[^\s"\'>]*)["\']', re.IGNORECASE)
FORM_REGEX = re.compile(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>', re.IGNORECASE)
INPUT_REGEX = re.compile(r'<input[^>]*name=["\']([^"\']*)["\']', re.IGNORECASE)

SQL_ERRORS = [
    "sql syntax",
    "sqlite3.operationalerror",
    "mysql_fetch",
    "you have an error in your sql syntax",
    "unclosed quotation mark",
    "postgresql query failed"
]


def start_scan(site_id: int):
    """Trigger background crawler & scanner thread."""
    global scan_status
    if scan_status["status"] == "running":
        return
        
    scan_status = {
        "status": "running",
        "scanned_count": 0,
        "current_url": "",
        "vulnerabilities_found": 0,
        "urls_found": []
    }
    
    thread = threading.Thread(target=_run_crawler_and_scanner, args=(site_id,))
    thread.daemon = True
    thread.start()


def get_status() -> dict:
    return scan_status


def _run_crawler_and_scanner(site_id: int):
    global scan_status
    db = SessionLocal()
    try:
        site = db.get(Site, site_id)
        if not site:
            scan_status["status"] = "failed"
            return
            
        start_url = site.url
        base_domain = start_url.split("//")[-1].split("/")[0]
        
        to_crawl = [start_url]
        crawled = set()
        vulnerabilities = []
        
        while to_crawl and len(crawled) < 15: # limit scan bounds for local safety
            url = to_crawl.pop(0)
            if url in crawled:
                continue
                
            crawled.add(url)
            scan_status["current_url"] = url
            scan_status["scanned_count"] = len(crawled)
            
            try:
                # 1. Fetch Page
                response = httpx.get(url, timeout=5.0, follow_redirects=True)
                html = response.text
                
                # 2. Extract Links
                links = LINK_REGEX.findall(html)
                for link in links:
                    full_link = link
                    if link.startswith("/"):
                        full_link = f"{start_url.rstrip('/')}{link}"
                    
                    # Ensure same domain crawler limits
                    if base_domain in full_link and full_link not in crawled and full_link not in to_crawl:
                        to_crawl.append(full_link)
                        if full_link not in scan_status["urls_found"]:
                            scan_status["urls_found"].append(full_link)

                # 3. Discover and Scan Forms
                forms = FORM_REGEX.findall(html)
                for form_action in forms:
                    action_url = form_action
                    if form_action.startswith("/"):
                        action_url = f"{start_url.rstrip('/')}{form_action}"
                    elif not form_action.startswith("http"):
                        action_url = f"{url.rstrip('/')}/{form_action}"
                        
                    # Find input parameters in the page context
                    inputs = INPUT_REGEX.findall(html)
                    if inputs:
                        # Test SQL Injection vulnerability
                        _test_sqli(db, site_id, action_url, inputs)
                        # Test Cross Site Scripting vulnerability
                        _test_xss(db, site_id, action_url, inputs)
                        
            except Exception:
                pass
                
        scan_status["status"] = "done"
    finally:
        db.close()


def _test_sqli(db: Session, site_id: int, url: str, inputs: list[str]):
    global scan_status
    # Probe SQL Injection payload
    payload = "1' OR '1'='1"
    data = {inp: payload for inp in inputs}
    try:
        r = httpx.post(url, data=data, timeout=3.0)
        body = r.text.lower()
        if any(err in body for err in SQL_ERRORS):
            # Vulnerability found!
            vuln = Vulnerability(
                site_id=site_id,
                url=url,
                parameter=",".join(inputs),
                vuln_type="sqli",
                severity="high",
                evidence=f"Payload: {payload} | SQL error matched in response body.",
                status="open"
            )
            db.add(vuln)
            db.commit()
            scan_status["vulnerabilities_found"] += 1
            
            # Log in audit trail
            from .responder import audit
            audit(db, "vulnerability_discovered", {"url": url, "type": "sqli"})
    except Exception:
        pass


def _test_xss(db: Session, site_id: int, url: str, inputs: list[str]):
    global scan_status
    # Probe XSS payload
    payload = "<script>alert('xss')</script>"
    data = {inp: payload for inp in inputs}
    try:
        r = httpx.post(url, data=data, timeout=3.0)
        # Check if reflected unescaped
        if payload in r.text:
            vuln = Vulnerability(
                site_id=site_id,
                url=url,
                parameter=",".join(inputs),
                vuln_type="xss",
                severity="high",
                evidence=f"Payload: {payload} reflected verbatim in response body.",
                status="open"
            )
            db.add(vuln)
            db.commit()
            scan_status["vulnerabilities_found"] += 1
            
            from .responder import audit
            audit(db, "vulnerability_discovered", {"url": url, "type": "xss"})
    except Exception:
        pass

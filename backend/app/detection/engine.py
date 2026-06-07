"""The detection engine. Takes a batch of normalized events and returns
incidents grouped by source IP, with the evidence needed for reporting.

Detects: SQLi, XSS, path traversal, malware uploads, brute force / credential
stuffing, scanning, bot attacks, API abuse, basic DDoS patterns, suspicious
logins, and honeypot hits."""
import re
from collections import defaultdict
from urllib.parse import unquote

from .signatures import COMPILED, SEVERITY

AUTH_PATHS = ("/login", "/signin", "/auth", "/wp-login", "/admin", "/api/login")
BOT_UA = re.compile(r"(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|hydra|curl|python-requests|scrapy)", re.I)

RANK = {"high": 3, "medium": 2, "low": 1}


def _decode(path: str) -> str:
    return unquote(path or "").lower()


def signature_hits(path: str):
    target = _decode(path)
    hits = []
    for atype, patterns in COMPILED.items():
        if any(p.search(target) for p in patterns):
            hits.append(atype)
    return hits


def analyze(events, baseline, honeypot_paths, thresholds):
    """events: list of dicts {ip, method, path, status, user_agent, ts}.
    Returns: list of incident dicts."""
    findings = defaultdict(list)
    req_counts = defaultdict(int)
    failed_auth = defaultdict(int)
    not_found = defaultdict(int)
    distinct_paths = defaultdict(set)
    times = defaultdict(list)
    fast_hits = defaultdict(int)   # requests in a tight burst -> DDoS-ish

    hp = {p.lower() for p in honeypot_paths}

    for e in events:
        ip = e["ip"]
        req_counts[ip] += 1
        distinct_paths[ip].add(e.get("path", ""))
        if e.get("ts"):
            times[ip].append(e["ts"])

        # signatures
        for atype in signature_hits(e.get("path", "")):
            findings[ip].append({"type": atype, "severity": SEVERITY[atype],
                                 "evidence": (e.get("path") or "")[:200]})

        # honeypot: any hit on a fake path is malicious
        if _decode(e.get("path", "")) in hp:
            findings[ip].append({"type": "honeypot", "severity": "high",
                                 "evidence": f"hit honeypot {e.get('path')}"})

        # bot tooling by user-agent
        if BOT_UA.search(e.get("user_agent", "") or ""):
            findings[ip].append({"type": "bot_attack", "severity": "medium",
                                 "evidence": f"tool UA: {e.get('user_agent', '')[:80]}"})

        # behavioral counters
        if any(_decode(e.get("path", "")).startswith(p) for p in AUTH_PATHS) and e.get("status") in (401, 403, 400):
            failed_auth[ip] += 1
        if e.get("status") == 404:
            not_found[ip] += 1

    mean = baseline.get("mean_reqs_per_ip", 0.0)
    std = max(baseline.get("var_reqs_per_ip", 0.0) ** 0.5, 1.0)

    for ip in set(list(req_counts) + list(findings)):
        if failed_auth[ip] >= thresholds["failed_auth"]:
            ttype = "credential_stuffing" if failed_auth[ip] >= thresholds["failed_auth"] * 2 else "brute_force"
            findings[ip].append({"type": ttype, "severity": "high",
                                 "evidence": f"{failed_auth[ip]} failed login attempts"})
        if not_found[ip] >= thresholds["scan_404"] or len(distinct_paths[ip]) >= thresholds["scan_404"] + 5:
            findings[ip].append({"type": "scanning", "severity": "medium",
                                 "evidence": f"{not_found[ip]} 404s, {len(distinct_paths[ip])} distinct paths"})
        # API abuse: heavy hits concentrated on /api
        api_hits = sum(1 for e in events if e["ip"] == ip and _decode(e.get("path", "")).startswith("/api"))
        if api_hits >= thresholds["scan_404"]:
            findings[ip].append({"type": "api_abuse", "severity": "medium",
                                 "evidence": f"{api_hits} API requests in batch"})
        # rate anomaly / DDoS pattern vs learned baseline
        if baseline.get("runs", 0) >= 3:
            z = (req_counts[ip] - mean) / std
            if z >= thresholds["rate_z"]:
                ttype = "ddos_pattern" if z >= thresholds["rate_z"] * 2 else "rate_anomaly"
                findings[ip].append({"type": ttype, "severity": SEVERITY[ttype],
                                     "evidence": f"{req_counts[ip]} reqs (baseline {mean:.0f}, z={z:.1f})"})

    incidents = []
    for ip, flist in findings.items():
        if not flist:
            continue
        top = max(flist, key=lambda f: RANK.get(f["severity"], 0))
        ts_list = sorted(times[ip]) if times[ip] else []
        incidents.append({
            "source_ip": ip,
            "severity": top["severity"],
            "threat_types": sorted({f["type"] for f in flist}),
            "findings": flist,
            "request_count": req_counts[ip],
            "first_seen": ts_list[0] if ts_list else None,
            "last_seen": ts_list[-1] if ts_list else None,
        })
    incidents.sort(key=lambda i: RANK.get(i["severity"], 0), reverse=True)
    return incidents, dict(req_counts)


def update_baseline(baseline, per_ip_counts, alpha=0.2):
    if per_ip_counts:
        observed = sum(per_ip_counts.values()) / len(per_ip_counts)
        if baseline.get("runs", 0) == 0:
            baseline["mean_reqs_per_ip"] = observed
            baseline["var_reqs_per_ip"] = 0.0
        else:
            prev = baseline["mean_reqs_per_ip"]
            baseline["mean_reqs_per_ip"] = (1 - alpha) * prev + alpha * observed
            diff = observed - baseline["mean_reqs_per_ip"]
            baseline["var_reqs_per_ip"] = (1 - alpha) * baseline.get("var_reqs_per_ip", 0.0) + alpha * diff * diff
        baseline["runs"] = baseline.get("runs", 0) + 1
    return baseline

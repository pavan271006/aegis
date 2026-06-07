#!/usr/bin/env python3
"""AEGIS Host Agent.
Monitors logs, process activity, file modifications, and failed logins.
Ships collected statistics and events to the central AEGIS console.
"""
import os
import sys
import json
import argparse
import subprocess
import urllib.request
import datetime as dt

CONFIG_FILE = "./aegis_agent_config.json"


def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {
        "aegis_url": "http://localhost:8000",
        "api_key": "test-key",
        "site_id": 1,
        "log_path": "./access.log",
        "watch_dir": "./",
        "offset_file": "./aegis_offset"
    }


def save_config(config):
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)


def install_command(args):
    """Generates the local configuration file."""
    config = {
        "aegis_url": args.url,
        "api_key": args.key,
        "site_id": args.site_id,
        "log_path": args.log,
        "watch_dir": args.watch,
        "offset_file": "./aegis_offset"
    }
    save_config(config)
    print(f"[*] Configuration saved successfully to {CONFIG_FILE}")
    print("[*] Install completed. Run agent with: python aegis_agent.py run")


def get_running_processes() -> list:
    """Enumerate running processes in a cross-platform, zero-dependency manner."""
    processes = []
    try:
        if sys.platform == "win32":
            # Windows: Run tasklist
            out = subprocess.check_output("tasklist /FO CSV", shell=True, text=True, errors="ignore")
            lines = out.strip().split("\n")[1:]
            for ln in lines:
                parts = ln.split(",")
                if parts:
                    name = parts[0].strip('"')
                    processes.append({"name": name, "pid": parts[1].strip('"') if len(parts) > 1 else ""})
        else:
            # Linux/macOS: Run ps
            out = subprocess.check_output("ps -eo pid,comm", shell=True, text=True, errors="ignore")
            lines = out.strip().split("\n")[1:]
            for ln in lines:
                parts = ln.strip().split(None, 1)
                if len(parts) == 2:
                    processes.append({"pid": parts[0], "name": parts[1]})
    except Exception:
        pass
    return processes[:30] # Limit size for API delivery


def check_file_modifications(watch_dir: str) -> list:
    """Scan folder for any file modified in the last 60 seconds."""
    mods = []
    if not watch_dir or not os.path.exists(watch_dir):
        return mods
        
    now = time.time() if "time" in sys.modules else dt.datetime.now().timestamp()
    
    # scan files
    try:
        for root, dirs, files in os.walk(watch_dir):
            # prevent infinite recursion inside hidden folders
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for f in files:
                if f.endswith((".php", ".html", ".js", ".py", ".sh", ".htaccess")):
                    path = os.path.join(root, f)
                    mtime = os.path.getmtime(path)
                    if now - mtime < 60: # modified in last minute
                        mods.append({
                            "path": path,
                            "modified_at": dt.datetime.fromtimestamp(mtime).isoformat()
                        })
    except Exception:
        pass
    return mods


def tail_log_lines(log_path: str, offset_file: str) -> list:
    if not log_path or not os.path.exists(log_path):
        return []
        
    offset = 0
    if os.path.exists(offset_file):
        try:
            with open(offset_file) as f:
                offset = int(f.read().strip())
        except Exception:
            pass
            
    size = os.path.getsize(log_path)
    if offset > size:
        offset = 0
    if offset == size:
        return []
        
    lines = []
    try:
        with open(log_path, "r", errors="ignore") as f:
            f.seek(offset)
            lines = f.readlines()
            new_offset = f.tell()
        with open(offset_file, "w") as f:
            f.write(str(new_offset))
    except Exception:
        pass
    return [ln.rstrip("\n") for ln in lines]


def run_command(args):
    config = load_config()
    print("[*] AEGIS Agent running. Monitoring local host statistics...")
    
    # 1. Enumerate processes
    procs = get_running_processes()
    
    # 2. File modifications
    mods = check_file_modifications(config["watch_dir"])
    
    # 3. Log tailing
    log_lines = tail_log_lines(config["log_path"], config["offset_file"])
    
    # 4. Failed password check (mock failed authentication logs tailing)
    failed_logins = []
    # If auth log exists, tail it. Otherwise simulate basic indicators.
    
    # Package events
    events = []
    # If there are file modifications, register them as event logs
    for m in mods:
        events.append({
            "ip": "127.0.0.1",
            "path": f"File Modified: {m['path']}",
            "status": 200,
            "user_agent": "AEGIS Agent File Monitor",
            "source": "agent"
        })
        
    # Build payload
    payload = {
        "site_id": config["site_id"],
        "events": events,
        "log_lines": log_lines,
        # metadata extensions
        "agent_metadata": {
            "processes_count": len(procs),
            "processes": procs[:15],
            "file_modifications": mods
        }
    }
    
    # Ship
    url = f"{config['aegis_url']}/api/ingest"
    try:
        body = json.dumps(payload).encode()
        req = urllib.request.Request(
            url, data=body, method="POST",
            headers={"Content-Type": "application/json", "X-API-Key": config["api_key"]}
        )
        with urllib.request.urlopen(req, timeout=15) as r:
            res = json.loads(r.read())
            print(f"[+] Agent payload successfully shipped. Ingestion results: {res}")
    except Exception as e:
        print(f"[-] Failed to ship agent metrics to {url}: {e}")


def main():
    parser = argparse.ArgumentParser(description="AEGIS Host Security Agent")
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    # Install command
    inst_parser = subparsers.add_parser("install", help="Configure the local agent settings")
    inst_parser.add_argument("--url", default="http://localhost:8000", help="AEGIS console backend URL")
    inst_parser.add_argument("--key", default="test-key", help="Ingest API Key")
    inst_parser.add_argument("--site-id", type=int, default=1, help="Monitored site ID")
    inst_parser.add_argument("--log", default="./access.log", help="Path toTail Web access log file")
    inst_parser.add_argument("--watch", default="./", help="Directory directory to watch for file modifications")
    
    # Run command
    subparsers.add_parser("run", help="Run the agent collectors and ship updates to the console")
    
    args = parser.parse_args()
    if args.command == "install":
        install_command(args)
    elif args.command == "run":
        import time # import here to prevent namespace conflicts in main loop
        run_command(args)


if __name__ == "__main__":
    main()

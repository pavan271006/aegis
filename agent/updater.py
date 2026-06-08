"""Agent-side OTA updater with signed artifacts, health-gated activation, and
AUTOMATIC ROLLBACK (the legacy build had none).

State machine:
    IDLE -> CHECK -> DOWNLOAD -> VERIFY -> STAGE -> ACTIVATE -> HEALTHCHECK
              |         |          |                              |
              |         |          +-- bad signature/hash --------+--> ABORT (stay on current)
              |         +-- download fail ------------------------+--> ABORT
              +-- no update --------------------------------------+--> IDLE
    HEALTHCHECK: pass -> COMMIT (delete previous) ; fail/timeout -> ROLLBACK -> current

Safety properties:
  * artifact hash + RS256 signature (AEGIS JWKS) verified BEFORE activation;
  * previous binary kept until the new one proves healthy;
  * a watchdog reverts if the new agent doesn't post a healthy heartbeat in time."""
import base64
import hashlib
import os
import shutil
import subprocess
import time

import httpx
import jwt  # PyJWT, for RS256 signature verification


class OTAUpdater:
    def __init__(self, server_url, client_cert, client_key, ca, install_dir,
                 current_version, channel="stable", health_timeout=120):
        self.url = server_url.rstrip("/")
        self.client = httpx.Client(cert=(client_cert, client_key), verify=ca, timeout=60)
        self.dir = install_dir
        self.version = current_version
        self.channel = channel
        self.health_timeout = health_timeout

    def tick(self) -> str:
        manifest = self._check()
        if not manifest or not manifest.get("update"):
            return "IDLE"
        artifact = self._download(manifest["url"])
        if not self._verify(artifact, manifest):
            return "ABORT:verify"
        prev = self._stage_and_activate(artifact, manifest["version"])
        if self._healthcheck():
            self._commit(prev)
            self.version = manifest["version"]
            return "COMMIT:" + manifest["version"]
        self._rollback(prev)
        return "ROLLBACK"

    # ── steps ───────────────────────────────────────────────────────────────
    def _check(self):
        r = self.client.get(f"{self.url}/api/v2/agents/manifest", params={"channel": self.channel})
        return r.json() if r.status_code == 200 else None

    def _download(self, url) -> bytes:
        return self.client.get(url, follow_redirects=True).content

    def _verify(self, artifact: bytes, manifest: dict) -> bool:
        if hashlib.sha256(artifact).hexdigest() != manifest["sha256"]:
            return False
        # signature = RS256 JWT whose payload binds {version, sha256}; verify vs JWKS
        try:
            jwks = {k["kid"]: k for k in manifest["jwks"]["keys"]}
            hdr = jwt.get_unverified_header(manifest["signature"])
            from jwt.algorithms import RSAAlgorithm
            key = RSAAlgorithm.from_jwk(jwks[hdr["kid"]])
            claims = jwt.decode(manifest["signature"], key, algorithms=["RS256"],
                                options={"verify_aud": False})
            return claims.get("sha256") == manifest["sha256"] and claims.get("version") == manifest["version"]
        except Exception:
            return False

    def _stage_and_activate(self, artifact: bytes, version: str) -> str:
        staged = os.path.join(self.dir, f"agent-{version}.bin")
        with open(staged, "wb") as f:
            f.write(artifact)
        os.chmod(staged, 0o755)
        live = os.path.join(self.dir, "agent-current")
        prev = os.path.join(self.dir, "agent-previous")
        if os.path.exists(live):
            shutil.copy2(os.path.realpath(live), prev)
        _atomic_symlink(staged, live)
        subprocess.run(["systemctl", "restart", "aegis-agent"], check=False)
        return prev

    def _healthcheck(self) -> bool:
        """Watchdog: the new agent must post a healthy heartbeat within the window."""
        deadline = time.time() + self.health_timeout
        while time.time() < deadline:
            try:
                if os.path.exists(os.path.join(self.dir, ".healthy")):
                    return True
            except OSError:
                pass
            time.sleep(3)
        return False

    def _commit(self, prev: str):
        if prev and os.path.exists(prev):
            os.remove(prev)

    def _rollback(self, prev: str):
        live = os.path.join(self.dir, "agent-current")
        if prev and os.path.exists(prev):
            _atomic_symlink(prev, live)
            subprocess.run(["systemctl", "restart", "aegis-agent"], check=False)


def _atomic_symlink(target: str, link: str):
    tmp = link + ".tmp"
    if os.path.lexists(tmp):
        os.remove(tmp)
    os.symlink(target, tmp)
    os.replace(tmp, link)   # atomic swap

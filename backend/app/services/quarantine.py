"""Upload quarantine service.

Suspicious file uploads are moved to a quarantine directory alongside a JSON
metadata sidecar.  Files can be inspected, released, or permanently deleted
through the admin API."""
import json
import logging
import os
import uuid

from sqlalchemy.orm import Session

from ..config import settings
from ..models import QuarantinedFile

log = logging.getLogger(__name__)


def _ensure_dir() -> str:
    """Create quarantine directory if it doesn't exist."""
    d = settings.quarantine_dir
    os.makedirs(d, exist_ok=True)
    return d


def check_upload(filename: str, content_type: str, size: int) -> dict:
    """Validate an upload before acceptance.

    Returns ``{safe: bool, reason: str}``.
    """
    max_bytes = settings.max_upload_size_mb * 1024 * 1024
    if size > max_bytes:
        return {"safe": False, "reason": f"File exceeds {settings.max_upload_size_mb}MB limit"}

    allowed = {ext.strip().lower() for ext in settings.allowed_upload_extensions.split(",")}
    ext = os.path.splitext(filename)[1].lower()
    if ext not in allowed:
        return {"safe": False, "reason": f"Extension '{ext}' not allowed"}

    # Suspicious content-type heuristics
    suspicious_types = {"application/x-php", "application/x-httpd-php",
                        "application/x-executable", "application/x-sh"}
    if content_type.lower() in suspicious_types:
        return {"safe": False, "reason": f"Suspicious content-type: {content_type}"}

    return {"safe": True, "reason": ""}


def quarantine_file(
    db: Session,
    filename: str,
    content: bytes,
    reason: str,
    content_type: str = "",
    uploaded_by_ip: str = "",
) -> dict:
    """Move a file into quarantine and record metadata."""
    qdir = _ensure_dir()
    qid = uuid.uuid4().hex
    safe_name = f"{qid}_{filename.replace(os.sep, '_')}"
    qpath = os.path.join(qdir, safe_name)

    # Write file content
    with open(qpath, "wb") as f:
        f.write(content)

    # Write metadata sidecar
    meta = {
        "quarantine_id": qid,
        "original_name": filename,
        "content_type": content_type,
        "size_bytes": len(content),
        "reason": reason,
        "uploaded_by_ip": uploaded_by_ip,
    }
    with open(qpath + ".meta.json", "w") as f:
        json.dump(meta, f, indent=2)

    # Persist in DB
    row = QuarantinedFile(
        original_name=filename,
        quarantine_path=qpath,
        content_type=content_type,
        size_bytes=len(content),
        reason=reason,
        status="quarantined",
        uploaded_by_ip=uploaded_by_ip,
    )
    db.add(row)
    db.commit()

    log.info("Quarantined file %s (id=%d): %s", filename, row.id, reason)
    return {"id": row.id, "quarantine_id": qid, "status": "quarantined"}


def list_quarantined(db: Session) -> list:
    """Return all quarantined file records."""
    return db.query(QuarantinedFile).order_by(QuarantinedFile.created_at.desc()).all()


def release_file(db: Session, item_id: int) -> dict:
    """Mark a quarantined file as released (safe)."""
    row = db.get(QuarantinedFile, item_id)
    if not row:
        return {"ok": False, "detail": "not found"}
    row.status = "released"
    db.commit()
    log.info("Released quarantined file id=%d (%s)", item_id, row.original_name)
    return {"ok": True, "id": item_id, "status": "released"}


def delete_quarantined(db: Session, item_id: int) -> dict:
    """Permanently delete a quarantined file from disk and DB."""
    row = db.get(QuarantinedFile, item_id)
    if not row:
        return {"ok": False, "detail": "not found"}
    # Remove from disk
    for path in (row.quarantine_path, row.quarantine_path + ".meta.json"):
        try:
            if os.path.exists(path):
                os.remove(path)
        except OSError:  # noqa: BLE001
            log.warning("Failed to remove %s", path)
    row.status = "deleted"
    db.commit()
    log.info("Deleted quarantined file id=%d (%s)", item_id, row.original_name)
    return {"ok": True, "id": item_id, "status": "deleted"}

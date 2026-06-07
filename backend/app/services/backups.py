import os
import shutil
import zipfile
import datetime as dt
from sqlalchemy.orm import Session
from ..config import settings
from ..database import engine

BACKUP_DIR = "./backups"


def init_backup_dir():
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)


def create_backup(db: Session) -> dict:
    """Creates a ZIP backup of aegis.db and the quarantine directory."""
    init_backup_dir()
    
    timestamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_filename = f"aegis_backup_{timestamp}.zip"
    backup_path = os.path.join(BACKUP_DIR, backup_filename)
    
    # Locate sqlite file path
    db_path = "./aegis.db"
    if settings.database_url.startswith("sqlite:///"):
        db_path = settings.database_url.replace("sqlite:///", "")
        
    quarantine_path = settings.quarantine_dir or "./aegis_quarantine"
    
    try:
        # Dispose engine to flush connections
        engine.dispose()
        
        with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            # 1. Back up database file
            if os.path.exists(db_path):
                zip_file.write(db_path, arcname=os.path.basename(db_path))
                
            # 2. Back up quarantine directory recursively
            if os.path.exists(quarantine_path):
                for root, dirs, files in os.walk(quarantine_path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        # maintain directory structure in zip relative to parent
                        rel_path = os.path.relpath(file_path, os.path.dirname(quarantine_path))
                        zip_file.write(file_path, arcname=os.path.join("quarantine", rel_path))
                        
        size = os.path.getsize(backup_path)
        
        # Log in Audit Trail
        from .responder import audit
        audit(db, "create_backup", {"filename": backup_filename, "size_bytes": size}, actor="founder")
        
        return {
            "ok": True,
            "filename": backup_filename,
            "size_bytes": size,
            "created_at": dt.datetime.now().isoformat()
        }
    except Exception as e:
        return {"ok": False, "detail": str(e)}


def list_backups() -> list[dict]:
    init_backup_dir()
    backups = []
    for f in os.listdir(BACKUP_DIR):
        if f.startswith("aegis_backup_") and f.endswith(".zip"):
            path = os.path.join(BACKUP_DIR, f)
            stat = os.stat(path)
            # extract timestamp from filename YYYYMMDD_HHMMSS
            ts_str = f.replace("aegis_backup_", "").replace(".zip", "")
            try:
                dt_val = dt.datetime.strptime(ts_str, "%Y%m%d_%H%M%S")
                created_at = dt_val.isoformat()
            except Exception:
                created_at = dt.datetime.fromtimestamp(stat.st_mtime).isoformat()
                
            backups.append({
                "name": f,
                "size_bytes": stat.st_size,
                "created_at": created_at
            })
    # sort by newest first
    backups.sort(key=lambda x: x["created_at"], reverse=True)
    return backups


def restore_backup(db: Session, name: str) -> dict:
    """Restores database and quarantine folder from zip file."""
    backup_path = os.path.join(BACKUP_DIR, name)
    if not os.path.exists(backup_path):
        return {"ok": False, "detail": "Backup archive not found"}
        
    db_path = "./aegis.db"
    if settings.database_url.startswith("sqlite:///"):
        db_path = settings.database_url.replace("sqlite:///", "")
        
    quarantine_path = settings.quarantine_dir or "./aegis_quarantine"
    
    try:
        # Dispose connection pool to ensure no locked files
        engine.dispose()
        
        # Temp backup of current database in case of failure
        temp_db_path = db_path + ".tmp"
        if os.path.exists(db_path):
            shutil.copy2(db_path, temp_db_path)
            
        try:
            with zipfile.ZipFile(backup_path, 'r') as zip_file:
                # 1. Restore database
                db_member = os.path.basename(db_path)
                if db_member in zip_file.namelist():
                    zip_file.extract(db_member, path=os.path.dirname(db_path) or ".")
                    
                # 2. Restore quarantine folder
                # Clean up existing quarantine first
                if os.path.exists(quarantine_path):
                    shutil.rmtree(quarantine_path)
                os.makedirs(quarantine_path)
                
                for member in zip_file.namelist():
                    if member.startswith("quarantine/"):
                        # Extract relative to quarantine directory
                        rel_path = member.replace("quarantine/", "", 1)
                        if rel_path:
                            dest_file = os.path.join(quarantine_path, rel_path)
                            os.makedirs(os.path.dirname(dest_file), exist_ok=True)
                            with zip_file.open(member) as source, open(dest_file, "wb") as target:
                                shutil.copyfileobj(source, target)
                                
            # Remove tmp backup
            if os.path.exists(temp_db_path):
                os.remove(temp_db_path)
                
            # Log in Audit Trail
            from .responder import audit
            audit(db, "restore_backup", {"filename": name}, actor="founder")
            
            return {"ok": True, "detail": "Backup restored successfully."}
        except Exception as e:
            # Revert to temp backup if restore failed
            if os.path.exists(temp_db_path):
                shutil.move(temp_db_path, db_path)
            raise e
    except Exception as e:
        return {"ok": False, "detail": str(e)}


def delete_backup(db: Session, name: str) -> dict:
    backup_path = os.path.join(BACKUP_DIR, name)
    if not os.path.exists(backup_path):
        return {"ok": False, "detail": "Backup archive not found"}
    try:
        os.remove(backup_path)
        # Log in Audit Trail
        from .responder import audit
        audit(db, "delete_backup", {"filename": name}, actor="founder")
        return {"ok": True}
    except Exception as e:
        return {"ok": False, "detail": str(e)}

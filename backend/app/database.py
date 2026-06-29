"""SQLAlchemy engine + session. Works with both SQLite (dev) and PostgreSQL
(prod) — just change DATABASE_URL."""
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from .config import settings

connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, connect_args=connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


from sqlalchemy import event, text
from sqlalchemy.orm import Session

@event.listens_for(Session, "before_flush")
def before_flush(session, flush_context, instances):
    try:
        org_id = session.execute(text("SELECT current_setting('app.current_org', true)")).scalar()
        if org_id and org_id != "00000000-0000-0000-0000-000000000000":
            for obj in session.new:
                if hasattr(obj, "org_id") and getattr(obj, "org_id") is None:
                    obj.org_id = org_id
    except Exception:
        pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    from . import models  # noqa: F401  (register models)
    import os
    if os.getenv("AEGIS_ENTERPRISE") == "1":
        from .enterprise import models as ent_models  # noqa: F401
        from .enterprise import models_p2 as ent_models_p2  # noqa: F401
        from .enterprise import models_p3 as ent_models_p3  # noqa: F401
        from .enterprise import models_p4 as ent_models_p4  # noqa: F401
    Base.metadata.create_all(bind=engine)

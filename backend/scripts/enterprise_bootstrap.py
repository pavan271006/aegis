"""One-command enterprise bootstrap (validated against real Postgres).

Order matters and matches the expand/migrate/contract design:
  1. create the legacy base tables from the ORM,
  2. run the Alembic enterprise migrations (org model + RLS + auth tables),
  3. create the first Organization, an OWNER user, and the first RS256 signing key.

Run with the OWNER/migration DB credentials (NOT the aegis_app RLS role):

    DATABASE_URL=postgresql+psycopg2://owner:***@host/aegis \
    AEGIS_KEK=$(openssl rand -base64 48) \
    BOOTSTRAP_ORG="Acme" BOOTSTRAP_EMAIL=owner@acme.com BOOTSTRAP_PASSWORD='***' \
    python -m scripts.enterprise_bootstrap
"""
import os
import sys

REQUIRED = ["DATABASE_URL", "AEGIS_KEK", "BOOTSTRAP_EMAIL", "BOOTSTRAP_PASSWORD"]


def main() -> int:
    missing = [k for k in REQUIRED if not os.getenv(k)]
    if missing:
        print("Missing env:", ", ".join(missing))
        return 2
    # enterprise settings read AEGIS_DATABASE_URL; mirror DATABASE_URL into it.
    os.environ.setdefault("AEGIS_DATABASE_URL", os.environ["DATABASE_URL"])

    # 1) base ORM schema
    from app.database import engine, Base
    from app import models  # noqa: F401
    Base.metadata.create_all(bind=engine)
    print("[1/3] base ORM tables ready")

    # 2) enterprise migrations
    from alembic import command
    from alembic.config import Config
    cfg = Config("alembic.ini")
    cfg.set_main_option("script_location", "migrations")
    command.upgrade(cfg, "head")
    print("[2/3] migrations applied (RLS + tenant model live)")

    # 3) first org + owner + signing key (owner conn bypasses RLS)
    from sqlalchemy.orm import Session
    from app.models import User
    from app.enterprise.models import Membership, Organization
    from app.enterprise import passwords, keys
    org_name = os.getenv("BOOTSTRAP_ORG", "Default Organization")
    slug = org_name.lower().replace(" ", "-")
    email = os.environ["BOOTSTRAP_EMAIL"].lower()
    with Session(engine) as db:
        org = db.query(Organization).filter(Organization.slug == slug).first()
        if not org:
            org = Organization(name=org_name, slug=slug, plan="enterprise")
            db.add(org); db.flush()
        user = db.query(User).filter(User.email == email).first()
        if not user:
            user = User(email=email,
                        hashed_password=passwords.hash_password(os.environ["BOOTSTRAP_PASSWORD"]),
                        role="owner", is_active=True)
            db.add(user); db.flush()
        if not db.query(Membership).filter(Membership.user_id == user.id,
                                           Membership.org_id == org.id).first():
            db.add(Membership(user_id=user.id, org_id=org.id, role="owner"))
        keys.get_active(db)  # seed the first RS256 signing key (JWKS)
        db.commit()
        print(f"[3/3] org='{org_name}' owner='{email}' + signing key created")
    print("BOOTSTRAP COMPLETE — set AEGIS_ENTERPRISE=1 and start the app.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

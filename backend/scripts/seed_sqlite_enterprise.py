import os
import sys

# Load .env first so DATABASE_URL / AEGIS_* settings are available before any
# SQLAlchemy engine is created.
sys.path.insert(0, os.getcwd())
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.getcwd(), ".env"))
except ImportError:
    pass  # python-dotenv optional; env vars must already be set

# Override / guarantee the enterprise vars needed for seeding.
os.environ.setdefault("AEGIS_ENTERPRISE", "1")
os.environ.setdefault("AEGIS_KEK", "KKpMzYUQkhmM0qAoGWmtsIp_X3B_1bWVt4svQTXH22c=")
os.environ.setdefault("AEGIS_DATABASE_URL", os.environ.get("DATABASE_URL", "sqlite:///./aegis.db"))

from app.database import engine, init_db
from sqlalchemy.orm import Session
from app.models import User
from app.enterprise.models import Membership, Organization
from app.enterprise import passwords, keys

def main():
    print("Initializing SQLite database with enterprise tables...")
    init_db()
    
    org_name = "Default Organization"
    slug = "default"
    email = "admin@aegis.internal"
    password = "admin123"
    
    with Session(engine) as db:
        org = db.query(Organization).filter(Organization.slug == slug).first()
        if not org:
            org = Organization(name=org_name, slug=slug, plan="enterprise")
            db.add(org)
            db.flush()
            print(f"Created organization: {org_name} (slug: {slug})")
        else:
            print(f"Organization '{org_name}' already exists.")
            
        user = db.query(User).filter(User.email == email).first()
        if not user:
            user = User(
                email=email,
                hashed_password=passwords.hash_password(password),
                role="owner",
                is_active=True
            )
            db.add(user)
            db.flush()
            print(f"Created owner user: {email}")
        else:
            # Upgrade password just in case
            user.hashed_password = passwords.hash_password(password)
            user.role = "owner"
            db.flush()
            print(f"User '{email}' already exists, password updated.")
            
        membership = db.query(Membership).filter(
            Membership.user_id == user.id,
            Membership.org_id == org.id
        ).first()
        if not membership:
            membership = Membership(user_id=user.id, org_id=org.id, role="owner")
            db.add(membership)
            db.flush()
            print(f"Added membership for {email} in {org_name}")
        else:
            print("Membership already exists.")
            
        # Seed the first RS256 signing key (JWKS)
        keys.get_active(db)
        db.commit()
        print("Database seed complete.")

if __name__ == "__main__":
    main()

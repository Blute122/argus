"""Database seeding - creates default admin user and sample data."""
from backend.database.connection import SessionLocal
from backend.models.user import User, UserRole
from backend.security import hash_password


def seed_database():
    """Create default users if they don't exist."""
    db = SessionLocal()
    try:
        if db.query(User).count() == 0:
            users = [
                User(username="admin", email="admin@soc-lab.local",
                     password_hash=hash_password("admin123"),
                     full_name="SOC Administrator", role=UserRole.ADMIN),
                User(username="analyst1", email="analyst1@soc-lab.local",
                     password_hash=hash_password("analyst123"),
                     full_name="Sarah Chen", role=UserRole.ANALYST_L1),
                User(username="analyst2", email="analyst2@soc-lab.local",
                     password_hash=hash_password("analyst123"),
                     full_name="James Rodriguez", role=UserRole.ANALYST_L2),
                User(username="hunter", email="hunter@soc-lab.local",
                     password_hash=hash_password("hunter123"),
                     full_name="Alex Kovalev", role=UserRole.THREAT_HUNTER),
                User(username="responder", email="ir@soc-lab.local",
                     password_hash=hash_password("responder123"),
                     full_name="Maya Patel", role=UserRole.INCIDENT_RESPONDER),
            ]
            db.add_all(users)
            db.commit()
            print("[SEED] Default users created")
    finally:
        db.close()

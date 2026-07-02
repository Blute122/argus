"""Database seeding.

In DEMO_MODE, seeds the full training account set + sample assets. Otherwise
(real deployment) seeds only an admin account, whose password comes from
ADMIN_PASSWORD or is randomly generated and printed once.
"""
import secrets

from backend.config import settings
from backend.database.connection import SessionLocal
from backend.models.asset import Asset
from backend.models.vulnerability import Vulnerability
from backend.models.user import User, UserRole
from backend.security import hash_password


def _seed_admin_only(db):
    password = settings.admin_password or secrets.token_urlsafe(12)
    db.add(User(username="admin", email="admin@localhost",
                password_hash=hash_password(password),
                full_name="SOC Administrator", role=UserRole.ADMIN))
    db.commit()
    if settings.admin_password:
        print("[SEED] Admin account created (password from ADMIN_PASSWORD).")
    else:
        print("=" * 68)
        print("[SEED] Created admin account (shown once — store it now):")
        print(f"       username: admin   password: {password}")
        print("=" * 68)


def seed_database():
    """Create default users if they don't exist."""
    db = SessionLocal()
    try:
        if not settings.demo_mode:
            if db.query(User).count() == 0:
                _seed_admin_only(db)
            return

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
        if db.query(Asset).count() == 0:
            assets = [
                Asset(hostname="DC01", ip_address="10.0.1.10", asset_type="domain_controller",
                      operating_system="Windows Server 2022", owner="Identity Team",
                      business_unit="IT", criticality="critical", risk_score=86, status="online",
                      location="Primary Datacenter"),
                Asset(hostname="EXCHANGE01", ip_address="10.0.1.20", asset_type="server",
                      operating_system="Windows Server 2019", owner="Messaging Team",
                      business_unit="IT", criticality="high", risk_score=72, status="online",
                      location="Primary Datacenter"),
                Asset(hostname="SQL-SRV01", ip_address="10.0.2.30", asset_type="server",
                      operating_system="Windows Server 2022", owner="Data Platform",
                      business_unit="Finance", criticality="critical", risk_score=81, status="online",
                      location="Primary Datacenter"),
                Asset(hostname="WEB-SRV01", ip_address="10.0.3.40", asset_type="server",
                      operating_system="Ubuntu 24.04 LTS", owner="AppSec",
                      business_unit="Engineering", criticality="high", risk_score=68, status="degraded",
                      location="DMZ"),
                Asset(hostname="FILE-SRV01", ip_address="10.0.1.50", asset_type="server",
                      operating_system="Windows Server 2019", owner="Infrastructure",
                      business_unit="Operations", criticality="high", risk_score=64, status="online",
                      location="Primary Datacenter"),
                Asset(hostname="WS-PC001", ip_address="10.0.2.60", asset_type="workstation",
                      operating_system="Windows 11 Enterprise", owner="Sarah Chen",
                      business_unit="Security", criticality="medium", risk_score=44, status="online",
                      location="SOC Floor"),
                Asset(hostname="HR-PC01", ip_address="10.0.4.25", asset_type="workstation",
                      operating_system="Windows 11 Enterprise", owner="Karen Lee",
                      business_unit="HR", criticality="medium", risk_score=58, status="online",
                      location="Headquarters"),
                Asset(hostname="jump-box", ip_address="10.0.5.15", asset_type="server",
                      operating_system="Ubuntu 22.04 LTS", owner="DevOps",
                      business_unit="Engineering", criticality="critical", risk_score=79, status="online",
                      location="Cloud VPC"),
                Asset(hostname="aws-us-east-1", ip_address="10.10.1.5", asset_type="cloud",
                      operating_system="AWS Account", owner="Cloud Platform",
                      business_unit="Engineering", criticality="critical", risk_score=74, status="online",
                      location="us-east-1"),
            ]
            db.add_all(assets)
            db.commit()
            print("[SEED] Asset inventory created")
            
            # Add vulnerabilities to some high-risk assets
            vulns = [
                Vulnerability(asset_id=assets[0].id, cve_id="CVE-2020-1472", title="ZeroLogon Elevation of Privilege", description="An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller.", severity="critical", cvss_score="10.0", status="open"),
                Vulnerability(asset_id=assets[2].id, cve_id="CVE-2022-26809", title="RPC Remote Code Execution", description="A remote code execution vulnerability exists in Microsoft Remote Procedure Call (RPC).", severity="critical", cvss_score="9.8", status="open"),
                Vulnerability(asset_id=assets[3].id, cve_id="CVE-2021-44228", title="Log4Shell", description="Apache Log4j2 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.", severity="critical", cvss_score="10.0", status="open"),
                Vulnerability(asset_id=assets[3].id, cve_id="CVE-2023-38408", title="OpenSSH Forwarded ssh-agent RCE", description="Remote code execution vulnerability in OpenSSH's forwarded ssh-agent.", severity="high", cvss_score="8.1", status="open"),
                Vulnerability(asset_id=assets[7].id, cve_id="CVE-2021-4034", title="PwnKit Local Privilege Escalation", description="A local privilege escalation vulnerability was found on polkit's pkexec utility.", severity="high", cvss_score="7.8", status="open")
            ]
            db.add_all(vulns)
            db.commit()
            print("[SEED] Vulnerabilities added")
    finally:
        db.close()
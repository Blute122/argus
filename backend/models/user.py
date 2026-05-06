"""User model for authentication and RBAC."""

from sqlalchemy import Column, Integer, String, Boolean, DateTime, Enum as SQLEnum
from sqlalchemy.sql import func
from backend.database.connection import Base
import enum


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    ANALYST_L1 = "analyst_l1"
    ANALYST_L2 = "analyst_l2"
    ANALYST_L3 = "analyst_l3"
    THREAT_HUNTER = "threat_hunter"
    INCIDENT_RESPONDER = "incident_responder"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(120), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    full_name = Column(String(100), nullable=False)
    role = Column(SQLEnum(UserRole), default=UserRole.ANALYST_L1, nullable=False)
    is_active = Column(Boolean, default=True)
    mfa_enabled = Column(Boolean, default=False)
    mfa_secret = Column(String(32), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_login = Column(DateTime(timezone=True), nullable=True)
    avatar_url = Column(String(255), nullable=True)

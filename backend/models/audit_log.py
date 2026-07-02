"""Audit log: who did what, when, from where."""

from sqlalchemy import Column, Integer, String, DateTime, Text
from sqlalchemy.sql import func

from backend.database.connection import Base


class AuditLog(Base):
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    actor_id = Column(Integer, nullable=True)
    actor_username = Column(String(80), nullable=True, index=True)
    action = Column(String(80), nullable=False, index=True)   # e.g. login.success, rule.disable
    target_type = Column(String(40), nullable=True)           # e.g. incident, rule, user
    target_id = Column(String(120), nullable=True)
    detail = Column(Text, nullable=True)
    source_ip = Column(String(45), nullable=True)
    outcome = Column(String(20), default="success")           # success | failure

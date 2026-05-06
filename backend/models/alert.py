"""Alert model for correlated security alerts."""

from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey
from sqlalchemy.sql import func
from backend.database.connection import Base


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False, index=True)  # low, medium, high, critical
    status = Column(String(20), default="new", index=True)  # new, investigating, resolved, false_positive, escalated
    source_ip = Column(String(45), nullable=True)
    destination_ip = Column(String(45), nullable=True)
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True)
    rule_name = Column(String(200), nullable=False)
    mitre_tactic = Column(String(100), nullable=True)
    mitre_technique = Column(String(20), nullable=True)
    mitre_technique_name = Column(String(200), nullable=True)
    analyst_action = Column(Text, nullable=True)
    assigned_to = Column(Integer, ForeignKey("users.id"), nullable=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=True)
    log_ids = Column(Text, nullable=True)  # JSON list of related log IDs
    hostname = Column(String(100), nullable=True)
    username = Column(String(100), nullable=True)
    event_count = Column(Integer, default=1)
    first_seen = Column(DateTime(timezone=True), nullable=True)
    last_seen = Column(DateTime(timezone=True), nullable=True)
    geo_country = Column(String(50), nullable=True)
    recommended_action = Column(Text, nullable=True)

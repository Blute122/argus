"""Incident model for incident response workflow."""

from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey
from sqlalchemy.sql import func
from backend.database.connection import Base


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String(300), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False)  # low, medium, high, critical
    status = Column(String(20), default="open", index=True)  # open, investigating, contained, resolved, closed
    priority = Column(Integer, default=3)  # 1=highest, 5=lowest
    category = Column(String(100), nullable=True)  # malware, phishing, brute_force, data_exfil, etc.
    assigned_to = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    sla_deadline = Column(DateTime(timezone=True), nullable=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    closed_at = Column(DateTime(timezone=True), nullable=True)
    resolution_summary = Column(Text, nullable=True)
    evidence = Column(Text, nullable=True)  # JSON list of evidence items
    affected_assets = Column(Text, nullable=True)  # JSON list of affected hosts/IPs
    mitre_techniques = Column(Text, nullable=True)  # JSON list of MITRE techniques
    alert_count = Column(Integer, default=0)
    ioc_list = Column(Text, nullable=True)  # JSON list of IOCs


class IncidentNote(Base):
    __tablename__ = "incident_notes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False, index=True)
    author_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    content = Column(Text, nullable=False)
    note_type = Column(String(50), default="general")  # general, evidence, action, timeline
    created_at = Column(DateTime(timezone=True), server_default=func.now())

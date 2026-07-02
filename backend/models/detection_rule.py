"""Persisted state/metadata for detection rules (content lives in YAML)."""

from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text
from sqlalchemy.sql import func

from backend.database.connection import Base


class DetectionRule(Base):
    __tablename__ = "detection_rules"

    id = Column(String(120), primary_key=True)          # sigma id / filename
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    rule_type = Column(String(20), default="streaming")  # streaming | threshold
    severity = Column(String(20), default="medium")
    mitre_technique = Column(String(20), nullable=True)
    tags = Column(Text, nullable=True)                   # JSON list
    source = Column(String(20), default="builtin")       # builtin | custom
    enabled = Column(Boolean, default=True)
    match_count = Column(Integer, default=0)
    last_fired_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

"""Hunt query model for threat hunting module."""

from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey
from sqlalchemy.sql import func
from backend.database.connection import Base


class HuntQuery(Base):
    __tablename__ = "hunt_queries"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    query = Column(Text, nullable=False)
    query_type = Column(String(20), default="spl")  # spl (Splunk-like), kql, sql
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_run = Column(DateTime(timezone=True), nullable=True)
    results_count = Column(Integer, default=0)
    is_saved = Column(Integer, default=0)
    tags = Column(Text, nullable=True)  # JSON list of tags
    mitre_technique = Column(String(20), nullable=True)

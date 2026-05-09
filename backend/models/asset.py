"""Asset inventory model for SOC context and risk scoring."""

from sqlalchemy import Column, Integer, String, DateTime, Text
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from backend.database.connection import Base

class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    hostname = Column(String(100), unique=True, nullable=False, index=True)
    ip_address = Column(String(45), unique=True, nullable=False, index=True)
    asset_type = Column(String(50), nullable=False)  # workstation, server, domain_controller, cloud, network
    operating_system = Column(String(100), nullable=True)
    owner = Column(String(120), nullable=True)
    business_unit = Column(String(100), nullable=True)
    criticality = Column(String(20), default="medium", index=True)  # low, medium, high, critical
    risk_score = Column(Integer, default=30, index=True)
    status = Column(String(20), default="online", index=True)  # online, degraded, isolated, offline
    location = Column(String(100), nullable=True)
    tags = Column(Text, nullable=True)  # JSON list
    last_seen = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    notes = Column(Text, nullable=True)

    vulnerabilities = relationship('Vulnerability', back_populates='asset', cascade='all, delete-orphan')
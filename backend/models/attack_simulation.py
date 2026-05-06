"""Attack simulation model for safe attack chain simulations."""

from sqlalchemy import Column, Integer, String, DateTime, Text
from sqlalchemy.sql import func
from backend.database.connection import Base


class AttackSimulation(Base):
    __tablename__ = "attack_simulations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)
    attack_type = Column(String(100), nullable=False)  # recon, phishing, brute_force, persistence, etc.
    mitre_tactic = Column(String(100), nullable=True)
    mitre_technique = Column(String(20), nullable=True)
    mitre_technique_name = Column(String(200), nullable=True)
    status = Column(String(20), default="ready")  # ready, running, completed, stopped
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    generated_logs = Column(Integer, default=0)
    generated_alerts = Column(Integer, default=0)
    scenario_config = Column(Text, nullable=True)  # JSON config for the simulation
    results_summary = Column(Text, nullable=True)  # JSON summary of results
    created_at = Column(DateTime(timezone=True), server_default=func.now())

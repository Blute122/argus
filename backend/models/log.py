"""Log model for storing generated telemetry events."""

from sqlalchemy import Column, Integer, String, DateTime, Text, Float
from sqlalchemy.sql import func
from backend.database.connection import Base


class Log(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    source = Column(String(50), nullable=False, index=True)  # windows, linux, network, email, cloud
    source_ip = Column(String(45), nullable=True)
    destination_ip = Column(String(45), nullable=True)
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True)
    protocol = Column(String(10), nullable=True)
    event_type = Column(String(100), nullable=False, index=True)
    event_id = Column(String(20), nullable=True)  # Windows Event ID
    severity = Column(String(20), default="info")  # info, low, medium, high, critical
    raw_log = Column(Text, nullable=False)
    hostname = Column(String(100), nullable=True)
    username = Column(String(100), nullable=True)
    process_name = Column(String(200), nullable=True)
    process_id = Column(Integer, nullable=True)
    command_line = Column(Text, nullable=True)
    file_path = Column(String(500), nullable=True)
    registry_key = Column(String(500), nullable=True)
    dns_query = Column(String(255), nullable=True)
    url = Column(String(500), nullable=True)
    user_agent = Column(String(500), nullable=True)
    http_method = Column(String(10), nullable=True)
    http_status = Column(Integer, nullable=True)
    bytes_sent = Column(Integer, nullable=True)
    bytes_received = Column(Integer, nullable=True)
    mitre_tactic = Column(String(100), nullable=True)
    mitre_technique = Column(String(20), nullable=True)
    mitre_technique_name = Column(String(200), nullable=True)
    geo_country = Column(String(50), nullable=True)
    geo_city = Column(String(100), nullable=True)
    confidence = Column(Float, default=0.0)
    is_malicious = Column(Integer, default=0)  # 0 = benign, 1 = suspicious, 2 = malicious

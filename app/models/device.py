"""
GHOSTSENTINEL Ω — Device ORM Model
"""
import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Text, Boolean
from app.database import Base


class Device(Base):
    __tablename__ = "devices"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), nullable=False, index=True)
    ip_address = Column(String(45), nullable=False)
    mac_address = Column(String(17), nullable=True)
    hostname = Column(String(256), nullable=True)
    vendor = Column(String(256), nullable=True)
    open_ports = Column(Text, nullable=True)           # JSON list of port numbers
    services = Column(Text, nullable=True)             # JSON dict port→service
    is_potential_camera = Column(Boolean, default=False)
    camera_evidence = Column(Text, nullable=True)      # JSON of indicators found
    notes = Column(Text, nullable=True)
    discovered_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

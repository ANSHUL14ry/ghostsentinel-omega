"""
GHOSTSENTINEL Ω — Scan ORM Model
"""
import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Text, Enum as SAEnum
import enum
from app.database import Base


class ScanStatus(str, enum.Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    cancelled = "cancelled"
    error = "error"


class ScanType(str, enum.Enum):
    wifi_discovery = "wifi_discovery"
    security_audit = "security_audit"
    device_discovery = "device_discovery"
    password_audit = "password_audit"
    camera_inspection = "camera_inspection"


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_type = Column(SAEnum(ScanType), nullable=False)
    status = Column(SAEnum(ScanStatus), nullable=False, default=ScanStatus.pending)
    scope = Column(Text, nullable=True)       # JSON-serialised authorised scope
    started_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)
    result_summary = Column(Text, nullable=True)  # JSON summary (no secrets)

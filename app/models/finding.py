"""
GHOSTSENTINEL Ω — Finding ORM Model
"""
import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Text, Enum as SAEnum
import enum
from app.database import Base


class FindingSeverity(str, enum.Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class FindingStatus(str, enum.Enum):
    confirmed = "confirmed"
    potential = "potential"
    info_unavailable = "info_unavailable"
    not_tested = "not_tested"


class Finding(Base):
    __tablename__ = "findings"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), nullable=False, index=True)
    title = Column(String(256), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(SAEnum(FindingSeverity), nullable=False)
    status = Column(SAEnum(FindingStatus), nullable=False)
    evidence = Column(Text, nullable=True)             # JSON — no secrets
    remediation = Column(Text, nullable=True)
    references = Column(Text, nullable=True)           # JSON list of URLs/docs
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

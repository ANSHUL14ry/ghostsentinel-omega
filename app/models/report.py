"""
GHOSTSENTINEL Ω — Report ORM Model
"""
import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Text, Enum as SAEnum
import enum
from app.database import Base


class ReportFormat(str, enum.Enum):
    html = "html"
    json = "json"
    pdf = "pdf"


class Report(Base):
    __tablename__ = "reports"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), nullable=False, index=True)
    format = Column(SAEnum(ReportFormat), nullable=False)
    filename = Column(String(256), nullable=False)
    file_path = Column(Text, nullable=False)
    generated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    size_bytes = Column(Text, nullable=True)

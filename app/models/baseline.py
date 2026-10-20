"""
GHOSTSENTINEL Ω — Trusted Baseline ORM Model
Stores trusted wireless profiles for Rogue AP and Evil Twin detection.
"""
import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Text
from app.database import Base


class TrustedBaseline(Base):
    __tablename__ = "trusted_baselines"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    ssid = Column(String(256), nullable=False, index=True)
    allowed_bssids = Column(Text, nullable=False)        # JSON list of allowed MACs, e.g. '["00:11:22:33:44:55"]'
    expected_security = Column(String(128), nullable=False) # e.g. "WPA2", "WPA3"
    allowed_channels = Column(Text, nullable=True)       # JSON list of channels, e.g. '[1, 6, 11]'
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

"""
GHOSTSENTINEL Ω — Network ORM Model
"""
import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Integer, Float, Text
from app.database import Base


class Network(Base):
    __tablename__ = "networks"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), nullable=False, index=True)
    ssid = Column(String(256), nullable=True)          # None = hidden SSID
    bssid = Column(String(17), nullable=True)
    channel = Column(Integer, nullable=True)
    frequency_mhz = Column(Float, nullable=True)
    signal_dbm = Column(Integer, nullable=True)
    security = Column(String(128), nullable=True)      # e.g. "WPA2-PSK", "Open"
    encryption = Column(String(128), nullable=True)
    authentication = Column(String(128), nullable=True)
    wps_detected = Column(String(32), nullable=True)   # "yes" / "no" / "unknown"
    raw_data = Column(Text, nullable=True)             # JSON of full adapter output
    observed_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

"""
GHOSTSENTINEL Ω — Pydantic Schemas
API request/response types with strict validation.
"""
from __future__ import annotations
from datetime import datetime
from typing import Any, Optional, List
from pydantic import BaseModel, Field, field_validator
import re


# ── Common ────────────────────────────────────────────────────────────────────

class APIResponse(BaseModel):
    success: bool
    message: str
    data: Optional[Any] = None


class ErrorResponse(BaseModel):
    error: str
    type: str


# ── Scan ──────────────────────────────────────────────────────────────────────

class ScanOut(BaseModel):
    id: str
    scan_type: str
    status: str
    scope: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    result_summary: Optional[str] = None

    class Config:
        from_attributes = True


# ── Wi-Fi Network ─────────────────────────────────────────────────────────────

class NetworkOut(BaseModel):
    id: str
    scan_id: str
    ssid: Optional[str] = None
    bssid: Optional[str] = None
    channel: Optional[int] = None
    frequency_mhz: Optional[float] = None
    signal_dbm: Optional[int] = None
    security: Optional[str] = None
    encryption: Optional[str] = None
    authentication: Optional[str] = None
    wps_detected: Optional[str] = None
    observed_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# ── Device ────────────────────────────────────────────────────────────────────

class DeviceScanRequest(BaseModel):
    interface: str = Field(..., min_length=1, max_length=32)
    network_range: str = Field(..., min_length=7, max_length=43)
    authorized: bool = Field(..., description="Must be True — user confirms authorization")

    @field_validator("network_range")
    @classmethod
    def validate_cidr(cls, v: str) -> str:
        # Basic CIDR validation — must be private range
        cidr_pattern = re.compile(
            r'^(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
            r'172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|'
            r'192\.168\.\d{1,3}\.\d{1,3})'
            r'(/\d{1,2})?$'
        )
        if not cidr_pattern.match(v):
            raise ValueError(
                "Only private RFC-1918 network ranges are permitted "
                "(10.x.x.x, 172.16-31.x.x, 192.168.x.x). "
                "Scanning arbitrary public IP ranges is not allowed."
            )
        return v

    @field_validator("authorized")
    @classmethod
    def must_be_authorized(cls, v: bool) -> bool:
        if not v:
            raise ValueError("You must explicitly confirm authorization before scanning.")
        return v

    @field_validator("interface")
    @classmethod
    def validate_interface_name(cls, v: str) -> str:
        if not re.match(r'^[a-zA-Z0-9_\-\. ]+$', v):
            raise ValueError("Interface name contains invalid characters.")
        return v


class DeviceOut(BaseModel):
    id: str
    scan_id: str
    ip_address: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    open_ports: Optional[str] = None
    services: Optional[str] = None
    is_potential_camera: bool = False
    camera_evidence: Optional[str] = None
    notes: Optional[str] = None
    discovered_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# ── Finding ───────────────────────────────────────────────────────────────────

class FindingOut(BaseModel):
    id: str
    scan_id: str
    title: str
    description: str
    severity: str
    status: str
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    references: Optional[str] = None
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# ── Password Audit (no storage of plaintext) ──────────────────────────────────

class PasswordAuditRequest(BaseModel):
    password: str = Field(..., min_length=1, max_length=256)
    label: str = Field(default="unnamed", max_length=64)   # e.g. "test-01"

    class Config:
        # Prevent logging of this model
        json_schema_extra = {"sensitive": True}


class PasswordAuditResult(BaseModel):
    label: str
    score: int                     # 0-4  (zxcvbn scale)
    score_label: str               # Weak / Fair / Good / Strong / Very Strong
    crack_time_display: str        # Human-readable
    warning: Optional[str] = None
    suggestions: List[str] = []
    has_common_pattern: bool
    length: int
    # password field intentionally omitted


# ── Report ────────────────────────────────────────────────────────────────────

class ReportOut(BaseModel):
    id: str
    scan_id: str
    format: str
    filename: str
    generated_at: Optional[datetime] = None
    size_bytes: Optional[str] = None

    class Config:
        from_attributes = True


# ── Hardware / System Info ────────────────────────────────────────────────────

class HardwareInfo(BaseModel):
    os_name: str
    os_version: str
    python_version: str
    wireless_interfaces: List[str]
    nmap_available: bool
    nmap_version: Optional[str] = None
    monitor_mode_capable: List[str] = []
    local_ip: Optional[str] = None
    default_subnet: Optional[str] = None
    notes: List[str]


# ── Baseline & Rogue AP Schemas ──────────────────────────────────────────────

class BaselineCreate(BaseModel):
    ssid: str = Field(..., min_length=1, max_length=256)
    allowed_bssids: List[str] = Field(..., min_length=1)
    expected_security: str = Field(default="WPA2", min_length=1, max_length=64)
    allowed_channels: Optional[List[int]] = None
    notes: Optional[str] = Field(default=None, max_length=1000)

    @field_validator("allowed_bssids")
    @classmethod
    def validate_bssids(cls, v: List[str]) -> List[str]:
        cleaned = []
        mac_re = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")
        for mac in v:
            m = mac.strip().upper().replace("-", ":")
            if not mac_re.match(m):
                raise ValueError(f"Invalid MAC/BSSID format: '{mac}'")
            cleaned.append(m)
        return cleaned


class BaselineOut(BaseModel):
    id: str
    ssid: str
    allowed_bssids: str
    expected_security: str
    allowed_channels: Optional[str] = None
    notes: Optional[str] = None
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# ── Controlled Security Lab Schemas ──────────────────────────────────────────

class LabAssessmentRequest(BaseModel):
    target_ssid: str = Field(..., min_length=1, max_length=256)
    target_bssid: Optional[str] = Field(default=None, max_length=64)
    security: Optional[str] = Field(default=None, max_length=64)
    channel: Optional[int] = Field(default=None, ge=1, le=196)
    router_ip: Optional[str] = Field(default=None, max_length=45)
    wps_detected: Optional[str] = Field(default="unknown", max_length=16)
    authorized: bool = Field(..., description="Must be True — explicit permission required")

    @field_validator("authorized")
    @classmethod
    def must_be_authorized(cls, v: bool) -> bool:
        if not v:
            raise ValueError("Lab assessment requires explicit authorization.")
        return v

    @field_validator("router_ip")
    @classmethod
    def validate_router_ip(cls, v: Optional[str]) -> Optional[str]:
        if not v or not v.strip():
            return None
        import ipaddress
        try:
            ip = ipaddress.ip_address(v.strip())
            if not ip.is_private:
                raise ValueError("Only RFC-1918 private IP addresses are permitted for router testing.")
        except ValueError as e:
            raise ValueError(f"Invalid private IP: {e}")
        return v.strip()

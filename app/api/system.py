"""
GHOSTSENTINEL Ω — System / Hardware Diagnostics API
"""
from fastapi import APIRouter
from app.services.hardware_service import get_hardware_info
from app.schemas.schemas import HardwareInfo

router = APIRouter(prefix="/api/system", tags=["System"])


@router.get("/hardware", response_model=HardwareInfo, summary="Hardware and capability diagnostics")
def hardware_diagnostics():
    """
    Returns real OS, adapter, nmap, and capability information.
    Never fabricates capabilities.
    """
    return get_hardware_info()


@router.get("/health", summary="Application health check")
def health():
    return {"status": "ok", "app": "GHOSTSENTINEL Ω"}


@router.get("/license", summary="Get active license and feature entitlements")
def get_license():
    """Returns active edition tier, entitlements, and deployment metadata."""
    from app.core.licensing import get_current_license
    from dataclasses import asdict
    return asdict(get_current_license())

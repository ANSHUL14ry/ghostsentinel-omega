"""
GHOSTSENTINEL Ω — Device Discovery API (Module D)
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List

from app.database import get_db
from app.models.device import Device
from app.models.scan import Scan, ScanType
from app.services.scan_service import start_device_scan, cancel_scan, get_scan_status
from app.schemas.schemas import DeviceScanRequest, DeviceOut, ScanOut, APIResponse
from app.core.exceptions import ScopeViolationError

router = APIRouter(prefix="/api/devices", tags=["Device Discovery"])


@router.post("/scan", response_model=APIResponse, summary="Start authorised device discovery")
def start_scan(request: DeviceScanRequest, db: Session = Depends(get_db)):
    """
    Starts a device discovery scan on the specified private network range.
    Requires explicit authorization=true.
    Only RFC-1918 private ranges are permitted.
    """
    try:
        scan_id = start_device_scan(db, request.network_range)
        return APIResponse(
            success=True,
            message=f"Device scan started for {request.network_range}.",
            data={"scan_id": scan_id},
        )
    except ScopeViolationError as e:
        raise HTTPException(status_code=403, detail=str(e.message))


@router.get("/scan/{scan_id}/status", response_model=APIResponse, summary="Poll device scan status")
def poll_status(scan_id: str, db: Session = Depends(get_db)):
    status = get_scan_status(scan_id, db)
    if not status:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return APIResponse(success=True, message="Status retrieved.", data=status)


@router.post("/scan/{scan_id}/cancel", response_model=APIResponse, summary="Cancel device scan")
def cancel_scan_endpoint(scan_id: str, db: Session = Depends(get_db)):
    cancelled = cancel_scan(scan_id, db)
    if cancelled:
        return APIResponse(success=True, message="Cancellation signal sent.")
    return APIResponse(success=False, message="Scan not found or already completed.")


@router.get("/scan/{scan_id}/devices", response_model=List[DeviceOut], summary="Get discovered devices")
def get_devices(scan_id: str, db: Session = Depends(get_db)):
    devices = db.query(Device).filter(Device.scan_id == scan_id).all()
    return devices


@router.get("/scans", response_model=List[ScanOut], summary="List all device scans")
def list_scans(db: Session = Depends(get_db)):
    scans = db.query(Scan).filter(Scan.scan_type == ScanType.device_discovery).order_by(Scan.started_at.desc()).all()
    return scans

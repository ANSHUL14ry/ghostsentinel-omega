"""
GHOSTSENTINEL Ω — Wi-Fi Discovery API (Module A)
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List

from app.database import get_db
from app.models.network import Network
from app.models.scan import Scan
from app.services.scan_service import start_wifi_scan, cancel_scan, get_scan_status
from app.schemas.schemas import ScanOut, NetworkOut, APIResponse

router = APIRouter(prefix="/api/wifi", tags=["Wi-Fi Discovery"])


@router.post("/scan", response_model=APIResponse, summary="Start a new Wi-Fi discovery scan")
def start_scan(db: Session = Depends(get_db)):
    """
    Initiates a real Wi-Fi scan using OS-native tools.
    Returns immediately with a scan_id — poll /scan/{id}/status for progress.
    """
    scan_id = start_wifi_scan(db)
    return APIResponse(
        success=True,
        message="Wi-Fi scan started.",
        data={"scan_id": scan_id},
    )


@router.get("/scan/{scan_id}/status", response_model=APIResponse, summary="Poll scan status")
def poll_status(scan_id: str, db: Session = Depends(get_db)):
    status = get_scan_status(scan_id, db)
    if not status:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return APIResponse(success=True, message="Status retrieved.", data=status)


@router.post("/scan/{scan_id}/cancel", response_model=APIResponse, summary="Cancel a running scan")
def cancel_scan_endpoint(scan_id: str, db: Session = Depends(get_db)):
    cancelled = cancel_scan(scan_id, db)
    if cancelled:
        return APIResponse(success=True, message="Cancellation signal sent.")
    return APIResponse(success=False, message="Scan not found or already completed.")


@router.get("/scan/{scan_id}/networks", response_model=List[NetworkOut], summary="Get discovered networks")
def get_networks(scan_id: str, db: Session = Depends(get_db)):
    networks = db.query(Network).filter(Network.scan_id == scan_id).all()
    return networks


@router.get("/scans", response_model=List[ScanOut], summary="List all Wi-Fi scans")
def list_scans(db: Session = Depends(get_db)):
    from app.models.scan import ScanType
    scans = db.query(Scan).filter(Scan.scan_type == ScanType.wifi_discovery).order_by(Scan.started_at.desc()).all()
    return scans

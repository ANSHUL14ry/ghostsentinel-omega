"""
GHOSTSENTINEL Ω — Trusted Baseline & Rogue AP API (Module D)
"""
import json
import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.baseline import TrustedBaseline
from app.models.network import Network
from app.models.scan import Scan, ScanType, ScanStatus
from app.models.finding import Finding, FindingSeverity, FindingStatus
from app.scanners.wifi_scanner import WifiNetwork
from app.auditors.rogue_detector import audit_rogue_access_points
from app.schemas.schemas import BaselineCreate, BaselineOut, APIResponse

router = APIRouter(prefix="/api/baseline", tags=["Trusted Baseline & Rogue Detection"])


@router.get("/list", response_model=List[BaselineOut], summary="List all trusted baselines")
def list_baselines(db: Session = Depends(get_db)):
    """Retrieve all configured trusted network baselines."""
    baselines = db.query(TrustedBaseline).order_by(TrustedBaseline.created_at.desc()).all()
    return baselines


@router.post("/add", response_model=APIResponse, summary="Add or update a trusted baseline")
def add_baseline(payload: BaselineCreate, db: Session = Depends(get_db)):
    """
    Register a trusted network baseline for Rogue AP and Evil Twin detection.
    """
    # Check if a baseline already exists for this exact SSID
    existing = db.query(TrustedBaseline).filter(TrustedBaseline.ssid == payload.ssid).first()
    
    bssids_json = json.dumps(payload.allowed_bssids)
    channels_json = json.dumps(payload.allowed_channels or [])

    if existing:
        existing.allowed_bssids = bssids_json
        existing.expected_security = payload.expected_security
        existing.allowed_channels = channels_json
        existing.notes = payload.notes
        db.commit()
        db.refresh(existing)
        return APIResponse(
            success=True,
            message=f"Trusted baseline updated for '{payload.ssid}'",
            data={"id": existing.id, "ssid": existing.ssid},
        )

    new_baseline = TrustedBaseline(
        id=str(uuid.uuid4()),
        ssid=payload.ssid,
        allowed_bssids=bssids_json,
        expected_security=payload.expected_security,
        allowed_channels=channels_json,
        notes=payload.notes,
    )
    db.add(new_baseline)
    db.commit()
    db.refresh(new_baseline)

    return APIResponse(
        success=True,
        message=f"Trusted baseline created for '{payload.ssid}'",
        data={"id": new_baseline.id, "ssid": new_baseline.ssid},
    )


@router.delete("/{baseline_id}", response_model=APIResponse, summary="Delete a trusted baseline")
def delete_baseline(baseline_id: str, db: Session = Depends(get_db)):
    """Remove a trusted baseline by ID."""
    item = db.query(TrustedBaseline).filter(TrustedBaseline.id == baseline_id).first()
    if not item:
        raise HTTPException(status_code=404, detail=f"Baseline '{baseline_id}' not found.")
    
    ssid = item.ssid
    db.delete(item)
    db.commit()
    return APIResponse(
        success=True,
        message=f"Trusted baseline for '{ssid}' deleted successfully.",
    )


@router.post("/audit_rogues", response_model=APIResponse, summary="Execute Rogue AP audit against live/recent scan")
def audit_rogues(
    scan_id: Optional[str] = Query(None, description="Optional scan ID to audit; defaults to latest Wi-Fi scan"),
    db: Session = Depends(get_db),
):
    """
    Compare discovered networks against all trusted baselines.
    Detects Rogue APs, Evil Twins, security downgrades, and RF channel anomalies.
    """
    # 1. Determine which scan to evaluate
    if scan_id:
        target_scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not target_scan:
            raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")
    else:
        target_scan = (
            db.query(Scan)
            .filter(Scan.scan_type == ScanType.wifi_discovery, Scan.status == ScanStatus.completed)
            .order_by(Scan.started_at.desc())
            .first()
        )
        if not target_scan or not db.query(Network).filter(Network.scan_id == target_scan.id).first():
            # Run immediate live scan if no completed scan exists
            from app.scanners.wifi_scanner import scan_wifi
            res = scan_wifi()
            live_scan = Scan(
                id=str(uuid.uuid4()),
                scan_type=ScanType.wifi_discovery,
                status=ScanStatus.completed if res.success else ScanStatus.error,
                result_summary=json.dumps({"networks_found": len(res.networks), "method": res.method_used}),
            )
            db.add(live_scan)
            for net in res.networks:
                db_net = Network(
                    scan_id=live_scan.id,
                    ssid=net.ssid,
                    bssid=net.bssid,
                    channel=net.channel,
                    frequency_mhz=net.frequency_mhz,
                    signal_dbm=net.signal_dbm,
                    security=net.security,
                    encryption=net.encryption,
                    authentication=net.authentication,
                    wps_detected=net.wps_detected,
                    raw_data=net.raw_data,
                )
                db.add(db_net)
            db.commit()
            target_scan = live_scan

    # 2. Fetch discovered networks for target scan
    db_networks = db.query(Network).filter(Network.scan_id == target_scan.id).all()
    if not db_networks:
        return APIResponse(
            success=True,
            message="No networks were captured in this scan to compare.",
            data={
                "scan_id": target_scan.id,
                "total_baselines": 0,
                "rogues_detected": 0,
                "downgrades_detected": 0,
                "findings": [],
            },
        )

    # Convert DB networks to WifiNetwork dataclass
    wifi_networks: List[WifiNetwork] = []
    for d in db_networks:
        wifi_networks.append(WifiNetwork(
            ssid=d.ssid,
            bssid=d.bssid,
            channel=d.channel,
            frequency_mhz=d.frequency_mhz,
            signal_dbm=d.signal_dbm,
            security=d.security,
            encryption=d.encryption,
            authentication=d.authentication,
            wps_detected=d.wps_detected or "unknown",
        ))

    # 3. Fetch all active trusted baselines
    baselines = db.query(TrustedBaseline).all()
    if not baselines:
        return APIResponse(
            success=True,
            message="No trusted baselines configured. Please define at least one baseline to detect rogue APs.",
            data={
                "scan_id": target_scan.id,
                "total_baselines": 0,
                "rogues_detected": 0,
                "downgrades_detected": 0,
                "findings": [],
            },
        )

    # 4. Execute audit
    summary = audit_rogue_access_points(wifi_networks, baselines)

    # 5. Persist findings to database (avoid duplicate findings for same scan and title)
    existing_finding_titles = {
        f.title for f in db.query(Finding).filter(Finding.scan_id == target_scan.id).all()
    }
    
    new_findings_count = 0
    serialized_findings = []
    for f in summary.findings:
        sev_val = FindingSeverity(f.severity.lower()) if f.severity.lower() in FindingSeverity.__members__ else FindingSeverity.high
        stat_val = FindingStatus(f.status.lower()) if f.status.lower() in FindingStatus.__members__ else FindingStatus.confirmed
        
        serialized_findings.append({
            "title": f.title,
            "description": f.description,
            "severity": f.severity,
            "status": f.status,
            "evidence": f.evidence,
            "remediation": f.remediation,
            "references": f.references,
        })

        if f.title not in existing_finding_titles:
            db_finding = Finding(
                id=str(uuid.uuid4()),
                scan_id=target_scan.id,
                title=f.title,
                description=f.description,
                severity=sev_val,
                status=stat_val,
                evidence=json.dumps(f.evidence) if f.evidence else None,
                remediation=f.remediation,
                references=json.dumps(f.references) if f.references else None,
            )
            db.add(db_finding)
            new_findings_count += 1
            existing_finding_titles.add(f.title)

    if new_findings_count > 0:
        db.commit()

    return APIResponse(
        success=True,
        message=(
            f"Rogue AP audit completed against scan {target_scan.id[:8]}…: "
            f"{summary.rogue_aps_detected} rogue/evil twin(s), "
            f"{summary.downgrades_detected} downgrade(s) detected across {len(baselines)} baseline(s)."
        ),
        data={
            "scan_id": target_scan.id,
            "total_baselines": summary.total_baselines_checked,
            "matched_networks": summary.matched_networks,
            "rogues_detected": summary.rogue_aps_detected,
            "downgrades_detected": summary.downgrades_detected,
            "channel_anomalies": summary.channel_anomalies,
            "new_findings_stored": new_findings_count,
            "findings": serialized_findings,
        },
    )

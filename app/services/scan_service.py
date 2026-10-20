"""
GHOSTSENTINEL Ω — Scan Service

Orchestrates scans: creates DB records, runs scanners/auditors,
persists results, and manages job state.
"""
from __future__ import annotations

import json
import threading
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from app.core.logging_config import get_logger
from app.database import SessionLocal
from app.models.scan import Scan, ScanStatus, ScanType
from app.models.network import Network
from app.models.device import Device
from app.models.finding import Finding, FindingSeverity, FindingStatus

logger = get_logger(__name__)

# In-memory registry of active scan threads (for cancellation support)
_active_scans: Dict[str, threading.Event] = {}


def _severity_to_enum(s: str) -> FindingSeverity:
    return FindingSeverity[s] if s in FindingSeverity.__members__ else FindingSeverity.info


def _status_to_enum(s: str) -> FindingStatus:
    return FindingStatus[s] if s in FindingStatus.__members__ else FindingStatus.not_tested


# ─────────────────────────────────────────────────────────────────────────────
# Wi-Fi Discovery Scan
# ─────────────────────────────────────────────────────────────────────────────

def _run_wifi_scan(scan_id: str, cancel_event: threading.Event) -> None:
    from app.scanners.wifi_scanner import scan_wifi
    from app.auditors.wifi_auditor import audit_networks

    db: Session = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return

        scan.status = ScanStatus.running
        db.commit()

        if cancel_event.is_set():
            scan.status = ScanStatus.cancelled
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
            return

        result = scan_wifi()

        if cancel_event.is_set():
            scan.status = ScanStatus.cancelled
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
            return

        if not result.success:
            scan.status = ScanStatus.error
            scan.error_message = result.error
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
            return

        # Persist networks
        for net in result.networks:
            db_net = Network(
                scan_id=scan_id,
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

        # Run audit and persist findings
        audit_results = audit_networks(result.networks)
        for audit in audit_results:
            for finding in audit.findings:
                db_finding = Finding(
                    scan_id=scan_id,
                    title=finding.title,
                    description=finding.description,
                    severity=_severity_to_enum(finding.severity),
                    status=_status_to_enum(finding.status),
                    evidence=json.dumps(finding.evidence),
                    remediation=finding.remediation,
                    references=json.dumps(finding.references),
                )
                db.add(db_finding)

        summary = {
            "networks_found": len(result.networks),
            "method": result.method_used,
            "warning": result.warning,
            "hardware_notes": result.hardware_notes,
        }
        scan.result_summary = json.dumps(summary)
        scan.status = ScanStatus.completed
        scan.completed_at = datetime.now(timezone.utc)
        db.commit()
        logger.info("Wi-Fi scan %s completed: %d networks found", scan_id, len(result.networks))

    except Exception as e:
        logger.exception("Wi-Fi scan %s failed with unexpected error", scan_id)
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.error
                scan.error_message = f"Unexpected error: {type(e).__name__}"
                scan.completed_at = datetime.now(timezone.utc)
                db.commit()
        except Exception:
            pass
    finally:
        db.close()
        _active_scans.pop(scan_id, None)


def start_wifi_scan(db: Session) -> str:
    """Create a Wi-Fi scan record and start the background thread. Returns scan_id."""
    scan_id = str(uuid.uuid4())
    scan = Scan(id=scan_id, scan_type=ScanType.wifi_discovery, status=ScanStatus.pending)
    db.add(scan)
    db.commit()

    cancel_event = threading.Event()
    _active_scans[scan_id] = cancel_event
    t = threading.Thread(target=_run_wifi_scan, args=(scan_id, cancel_event), daemon=True)
    t.start()
    logger.info("Wi-Fi scan started: %s", scan_id)
    return scan_id


# ─────────────────────────────────────────────────────────────────────────────
# Device Discovery Scan
# ─────────────────────────────────────────────────────────────────────────────

def _run_device_scan(
    scan_id: str,
    network_range: str,
    cancel_event: threading.Event,
) -> None:
    from app.scanners.device_scanner import scan_devices

    db: Session = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return

        scan.status = ScanStatus.running
        db.commit()

        if cancel_event.is_set():
            scan.status = ScanStatus.cancelled
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
            return

        result = scan_devices(network_range=network_range, authorized=True)

        if cancel_event.is_set():
            scan.status = ScanStatus.cancelled
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
            return

        if not result.success:
            scan.status = ScanStatus.error
            scan.error_message = result.error
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
            return

        for dev in result.devices:
            db_dev = Device(
                scan_id=scan_id,
                ip_address=dev.ip_address,
                mac_address=dev.mac_address,
                hostname=dev.hostname,
                vendor=dev.vendor,
                open_ports=json.dumps(dev.open_ports),
                services=json.dumps(dev.services),
                is_potential_camera=dev.is_potential_camera,
                camera_evidence=json.dumps(dev.camera_evidence),
            )
            db.add(db_dev)

        summary = {
            "devices_found": len(result.devices),
            "network_range": network_range,
            "method": result.method_used,
            "warning": result.warning,
        }
        scan.result_summary = json.dumps(summary)
        scan.status = ScanStatus.completed
        scan.completed_at = datetime.now(timezone.utc)
        db.commit()
        logger.info("Device scan %s completed: %d devices found", scan_id, len(result.devices))

    except Exception as e:
        logger.exception("Device scan %s failed", scan_id)
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.error
                scan.error_message = f"Unexpected error: {type(e).__name__}"
                scan.completed_at = datetime.now(timezone.utc)
                db.commit()
        except Exception:
            pass
    finally:
        db.close()
        _active_scans.pop(scan_id, None)


def start_device_scan(db: Session, network_range: str) -> str:
    """Create a device discovery scan and start the background thread."""
    scan_id = str(uuid.uuid4())
    scan = Scan(
        id=scan_id,
        scan_type=ScanType.device_discovery,
        status=ScanStatus.pending,
        scope=network_range,
    )
    db.add(scan)
    db.commit()

    cancel_event = threading.Event()
    _active_scans[scan_id] = cancel_event
    t = threading.Thread(
        target=_run_device_scan, args=(scan_id, network_range, cancel_event), daemon=True
    )
    t.start()
    return scan_id


# ─────────────────────────────────────────────────────────────────────────────
# Cancellation
# ─────────────────────────────────────────────────────────────────────────────

def cancel_scan(scan_id: str, db: Session) -> bool:
    """Signal a running scan to cancel. Returns True if signal was sent."""
    event = _active_scans.get(scan_id)
    if event:
        event.set()
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = ScanStatus.cancelled
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
        return True
    return False


def get_scan_status(scan_id: str, db: Session) -> Optional[Dict[str, Any]]:
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return None
    return {
        "id": scan.id,
        "scan_type": scan.scan_type.value,
        "status": scan.status.value,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "error_message": scan.error_message,
        "result_summary": json.loads(scan.result_summary) if scan.result_summary else None,
    }

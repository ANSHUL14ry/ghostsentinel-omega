"""
GHOSTSENTINEL Ω — Report Generation Tests
Verifies HTML, JSON, and PDF report generation against test scan data.
"""
import json
import os
from datetime import datetime, timezone
import pytest
from app.database import SessionLocal
from app.models.scan import Scan, ScanType, ScanStatus
from app.models.network import Network
from app.models.device import Device
from app.models.finding import Finding, FindingSeverity, FindingStatus
from app.reports.generator import save_report, generate_html_report, generate_json_report, generate_pdf_report


import uuid

@pytest.fixture
def sample_scan_id():
    db = SessionLocal()
    scan_id = f"test-report-{uuid.uuid4()}"

    # Create scan
    scan = Scan(
        id=scan_id,
        scan_type=ScanType.wifi_discovery,
        status=ScanStatus.completed,
        scope="Lab Testing Environment",
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
        result_summary=json.dumps({"networks_found": 1}),
    )
    db.add(scan)

    # Add network
    net = Network(
        scan_id=scan_id,
        ssid="TestLab-WPA2",
        bssid="00:11:22:33:44:55",
        channel=6,
        frequency_mhz=2437.0,
        signal_dbm=-55,
        security="WPA2",
        encryption="CCMP",
        authentication="WPA2-PSK",
        wps_detected="unknown",
    )
    db.add(net)

    # Add device
    dev = Device(
        scan_id=scan_id,
        ip_address="192.168.1.50",
        mac_address="00:11:22:AA:BB:CC",
        hostname="lab-camera-test",
        open_ports=json.dumps([80, 554]),
        services=json.dumps({"80": "http", "554": "rtsp"}),
        is_potential_camera=True,
        camera_evidence=json.dumps(["Port 554 RTSP open"]),
    )
    db.add(dev)

    # Add finding
    finding = Finding(
        scan_id=scan_id,
        title="WPA2-PSK Weak Passphrase Susceptibility",
        description="WPA2-PSK is susceptible to offline dictionary attacks if weak passphrases are used.",
        severity=FindingSeverity.medium,
        status=FindingStatus.potential,
        evidence=json.dumps(["WPA2-PSK handshake observable"]),
        remediation="Use a complex passphrase with at least 20 random characters.",
        references=json.dumps(["https://www.wi-fi.org/"]),
    )
    db.add(finding)
    db.commit()
    db.close()

    yield scan_id


def test_generate_html_report(sample_scan_id):
    db = SessionLocal()
    try:
        report_html = generate_html_report(sample_scan_id, db)
        assert "<!DOCTYPE html>" in report_html
        assert "GHOSTSENTINEL Ω" in report_html
        assert "TestLab-WPA2" in report_html
        assert "192.168.1.50" in report_html
        assert "WPA2-PSK Weak Passphrase Susceptibility" in report_html
    finally:
        db.close()


def test_generate_json_report(sample_scan_id):
    db = SessionLocal()
    try:
        data = generate_json_report(sample_scan_id, db)
        assert data["report_metadata"]["scan_id"] == sample_scan_id
        assert len(data["networks"]) == 1
        assert data["networks"][0]["ssid"] == "TestLab-WPA2"
        assert len(data["devices"]) == 1
        assert data["devices"][0]["is_potential_camera"] is True
        assert len(data["findings"]) == 1
        assert "limitations" in data
    finally:
        db.close()


def test_generate_pdf_report(sample_scan_id):
    db = SessionLocal()
    try:
        pdf_bytes = generate_pdf_report(sample_scan_id, db)
        assert isinstance(pdf_bytes, bytes)
        assert pdf_bytes.startswith(b"%PDF")
        assert len(pdf_bytes) > 500
    finally:
        db.close()


def test_save_report_persists_to_db_and_disk(sample_scan_id):
    db = SessionLocal()
    try:
        report = save_report(sample_scan_id, "html", db)
        assert report.id is not None
        assert os.path.exists(report.file_path)
        with open(report.file_path, "r", encoding="utf-8") as f:
            content = f.read()
        assert "TestLab-WPA2" in content
    finally:
        db.close()

"""
GHOSTSENTINEL Ω — Sample Report Generator
Generates sample reports from clearly labelled test fixtures for documentation and verification.
These reports are explicitly marked as [FIXTURE-GENERATED SAMPLE REPORT].
"""
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from app.core.config import settings
from app.database import init_db, SessionLocal
from app.models.scan import Scan, ScanType, ScanStatus
from app.models.network import Network
from app.models.device import Device
from app.models.finding import Finding, FindingSeverity, FindingStatus
from app.reports.generator import save_report


def main():
    init_db()
    db = SessionLocal()
    scan_id = f"sample-lab-{uuid.uuid4().hex[:8]}"

    print(f"Creating sample test fixture scan: {scan_id}")
    scan = Scan(
        id=scan_id,
        scan_type=ScanType.wifi_discovery,
        status=ScanStatus.completed,
        scope="[SAMPLE FIXTURE] Lab Wi-Fi Audit Environment (192.168.1.0/24)",
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
        result_summary=json.dumps({
            "networks_found": 3,
            "method": "SAMPLE FIXTURE",
            "warning": "Sample data generated from controlled test fixture for documentation.",
        }),
    )
    db.add(scan)

    # Networks
    networks = [
        Network(
            scan_id=scan_id,
            ssid="[SAMPLE] Guest-Open",
            bssid="00:11:22:33:44:01",
            channel=1,
            frequency_mhz=2412.0,
            signal_dbm=-72,
            security="Open",
            encryption="None",
            authentication="Open",
            wps_detected="unknown",
        ),
        Network(
            scan_id=scan_id,
            ssid="[SAMPLE] Office-Legacy-WEP",
            bssid="00:11:22:33:44:02",
            channel=6,
            frequency_mhz=2437.0,
            signal_dbm=-65,
            security="WEP",
            encryption="WEP",
            authentication="Open",
            wps_detected="no",
        ),
        Network(
            scan_id=scan_id,
            ssid="[SAMPLE] Corp-WPA2-PSK",
            bssid="00:11:22:33:44:03",
            channel=11,
            frequency_mhz=2462.0,
            signal_dbm=-50,
            security="WPA2",
            encryption="CCMP",
            authentication="WPA2-PSK",
            wps_detected="yes",
        ),
    ]
    for n in networks:
        db.add(n)

    # Devices
    devices = [
        Device(
            scan_id=scan_id,
            ip_address="192.168.1.1",
            mac_address="00:11:22:33:44:00",
            hostname="gateway.lab.local",
            vendor="LabRouter",
            open_ports=json.dumps([80, 443, 53]),
            services=json.dumps({"80": "http", "443": "https", "53": "dns"}),
            is_potential_camera=False,
            camera_evidence=json.dumps([]),
        ),
        Device(
            scan_id=scan_id,
            ip_address="192.168.1.105",
            mac_address="00:11:22:AA:BB:CC",
            hostname="cam-corridor-01.lab.local",
            vendor="LabCamCorp",
            open_ports=json.dumps([80, 554, 8554]),
            services=json.dumps({"80": "http", "554": "rtsp", "8554": "rtsp-alt"}),
            is_potential_camera=True,
            camera_evidence=json.dumps([
                "Port 554 RTSP open (streaming service)",
                "Port 8554 RTSP alternate open",
            ]),
        ),
    ]
    for d in devices:
        db.add(d)

    # Findings
    findings = [
        Finding(
            scan_id=scan_id,
            title="Open Network (No Encryption) Observed",
            description="The network '[SAMPLE] Guest-Open' broadcasts without encryption. All traffic is sent in plaintext.",
            severity=FindingSeverity.critical,
            status=FindingStatus.confirmed,
            evidence=json.dumps(["Security: Open", "Encryption: None"]),
            remediation="Enable WPA2 or WPA3 encryption immediately. If public access is required, deploy an isolated guest VLAN with client isolation.",
            references=json.dumps(["https://www.wi-fi.org/discover-wi-fi/security"]),
        ),
        Finding(
            scan_id=scan_id,
            title="WEP Encryption Detected",
            description="The network '[SAMPLE] Office-Legacy-WEP' uses deprecated WEP encryption, which is cryptographically broken.",
            severity=FindingSeverity.critical,
            status=FindingStatus.confirmed,
            evidence=json.dumps(["Security: WEP"]),
            remediation="Migrate immediately to WPA2-AES or WPA3. Discontinue all WEP usage.",
            references=json.dumps(["https://nvd.nist.gov/vuln/detail/CVE-2001-0952"]),
        ),
        Finding(
            scan_id=scan_id,
            title="WPS Exposure Detected",
            description="The network '[SAMPLE] Corp-WPA2-PSK' broadcasts WPS capability. WPS PIN brute-force may allow credential recovery.",
            severity=FindingSeverity.high,
            status=FindingStatus.potential,
            evidence=json.dumps(["WPS element detected in probe response"]),
            remediation="Disable WPS in the access point configuration. Use standard WPA2/WPA3 passphrase authentication.",
            references=json.dumps(["https://nvd.nist.gov/vuln/detail/CVE-2011-5053"]),
        ),
        Finding(
            scan_id=scan_id,
            title="Potential IP Camera Service Detected",
            description="Host 192.168.1.105 exposes RTSP streaming ports (554, 8554). This indicates a potential networked camera or media server.",
            severity=FindingSeverity.medium,
            status=FindingStatus.potential,
            evidence=json.dumps(["Port 554 RTSP open", "Port 8554 RTSP alternate open"]),
            remediation="Verify host identity physically. Restrict camera streaming interfaces to a dedicated IoT VLAN and require strong authentication.",
            references=json.dumps(["https://csrc.nist.gov/publications/detail/sp/800-213/final"]),
        ),
    ]
    for f in findings:
        db.add(f)

    db.commit()

    # Generate sample reports in all 3 formats
    html_rep = save_report(scan_id, "html", db)
    html_path = html_rep.file_path
    json_rep = save_report(scan_id, "json", db)
    json_path = json_rep.file_path
    pdf_rep = save_report(scan_id, "pdf", db)
    pdf_path = pdf_rep.file_path

    db.close()

    print(f"Sample HTML report: {html_path}")
    print(f"Sample JSON report: {json_path}")
    print(f"Sample PDF report:  {pdf_path}")
    print("Sample reports generated successfully.")


if __name__ == "__main__":
    main()

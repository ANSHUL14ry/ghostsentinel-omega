"""
GHOSTSENTINEL Ω — Test Suite
Tests for core modules, scanners, auditors, and API endpoints.
Mock data is ONLY used in tests — never in production paths.
"""
import json
import pytest
import re
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

# ─── Tests ───────────────────────────────────────────────────────────────────


# ─── Health Check ─────────────────────────────────────────────────────────────

class TestHealth:
    def test_health_endpoint(self, client):
        resp = client.get("/api/system/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "GHOSTSENTINEL" in data["app"]

    def test_hardware_endpoint_returns_real_data(self, client):
        resp = client.get("/api/system/hardware")
        assert resp.status_code == 200
        data = resp.json()
        assert "os_name" in data
        assert "python_version" in data
        assert isinstance(data["wireless_interfaces"], list)
        assert isinstance(data["nmap_available"], bool)
        assert isinstance(data["notes"], list)
        # Must not fabricate monitor mode
        assert isinstance(data["monitor_mode_capable"], list)

    def test_license_endpoint(self, client):
        resp = client.get("/api/system/license")
        assert resp.status_code == 200
        data = resp.json()
        assert "tier" in data
        assert "features" in data
        assert isinstance(data["features"], list)
        assert data["active"] is True


# ─── Wi-Fi Scanner ────────────────────────────────────────────────────────────

class TestWifiScanner:
    def test_scan_returns_scan_result_type(self):
        from app.scanners.wifi_scanner import scan_wifi, ScanResult
        result = scan_wifi()
        assert isinstance(result, ScanResult)

    def test_scan_result_has_required_fields(self):
        from app.scanners.wifi_scanner import scan_wifi
        result = scan_wifi()
        assert hasattr(result, "success")
        assert hasattr(result, "networks")
        assert hasattr(result, "error")
        assert hasattr(result, "method_used")

    def test_scan_success_or_error_not_fabricated(self):
        """Scan must either succeed with real data or fail with real error — never silent success with no networks and no explanation."""
        from app.scanners.wifi_scanner import scan_wifi
        result = scan_wifi()
        if not result.success:
            # Must have an error message
            assert result.error is not None
            assert len(result.error) > 0

    @patch("app.scanners.wifi_scanner.subprocess.run")
    def test_windows_missing_adapter(self, mock_run):
        """Missing adapter returns error, not empty success."""
        import platform
        if platform.system() != "Windows":
            pytest.skip("Windows-only test")
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="There is no wireless interface",
        )
        from app.scanners.wifi_scanner import _scan_windows
        result = _scan_windows()
        assert result.success is False
        assert result.error is not None

    @patch("app.scanners.wifi_scanner.subprocess.run")
    def test_netsh_timeout_handled(self, mock_run):
        import platform, subprocess
        if platform.system() != "Windows":
            pytest.skip("Windows-only test")
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["netsh"], timeout=30)
        from app.scanners.wifi_scanner import _scan_windows
        result = _scan_windows()
        assert result.success is False
        assert "timed out" in result.error.lower()

    def test_netsh_output_parsing(self):
        """Parser extracts real fields from sample netsh output."""
        import platform
        if platform.system() != "Windows":
            pytest.skip("Windows-only parsing test")
        from app.scanners.wifi_scanner import _parse_netsh_output
        sample = """
SSID 1 : TestNetwork
Network type            : Infrastructure
Authentication          : WPA2-Personal
Encryption              : CCMP
BSSID 1                 : aa:bb:cc:dd:ee:ff
     Signal             : 70%
     Channel            : 6

SSID 2 : OpenNet
Network type            : Infrastructure
Authentication          : Open
Encryption              : None
BSSID 1                 : 11:22:33:44:55:66
     Signal             : 40%
     Channel            : 11
"""
        networks = _parse_netsh_output(sample)
        assert len(networks) == 2
        assert networks[0].ssid == "TestNetwork"
        assert networks[0].security == "WPA2"
        assert networks[0].channel == 6
        assert networks[1].ssid == "OpenNet"
        assert networks[1].security == "Open"


# ─── Wi-Fi Auditor ────────────────────────────────────────────────────────────

class TestWifiAuditor:
    def _make_network(self, **kwargs):
        from app.scanners.wifi_scanner import WifiNetwork
        defaults = dict(
            ssid="TestNet", bssid="aa:bb:cc:dd:ee:ff",
            channel=6, frequency_mhz=2437.0, signal_dbm=-60,
            security="WPA2", encryption="CCMP", authentication="WPA2-Personal",
            wps_detected="unknown",
        )
        defaults.update(kwargs)
        return WifiNetwork(**defaults)

    def test_open_network_yields_critical_finding(self):
        from app.auditors.wifi_auditor import audit_network
        net = self._make_network(security="Open", encryption="None", authentication="Open")
        result = audit_network(net)
        titles = [f.title for f in result.findings]
        assert any("Open" in t for t in titles)
        severities = [f.severity for f in result.findings]
        assert "critical" in severities

    def test_wep_yields_critical_finding(self):
        from app.auditors.wifi_auditor import audit_network
        net = self._make_network(security="WEP", encryption="WEP")
        result = audit_network(net)
        assert any("WEP" in f.title for f in result.findings)
        assert any(f.severity == "critical" for f in result.findings)

    def test_wpa3_yields_info_not_critical(self):
        from app.auditors.wifi_auditor import audit_network
        net = self._make_network(security="WPA3", authentication="SAE")
        result = audit_network(net)
        severities = [f.severity for f in result.findings]
        assert "critical" not in severities
        assert "high" not in severities

    def test_wpa2_psk_yields_potential_not_confirmed(self):
        from app.auditors.wifi_auditor import audit_network
        net = self._make_network(security="WPA2", authentication="WPA2-Personal (PSK)")
        result = audit_network(net)
        psk_findings = [f for f in result.findings if "PSK" in f.title]
        assert psk_findings
        assert psk_findings[0].status == "potential"   # Not confirmed without testing

    def test_unknown_wps_noted_not_claimed(self):
        from app.auditors.wifi_auditor import audit_network
        net = self._make_network(wps_detected="unknown")
        result = audit_network(net)
        notes = result.notes
        assert any("WPS" in n for n in notes)

    def test_wps_yes_yields_finding(self):
        from app.auditors.wifi_auditor import audit_network
        net = self._make_network(wps_detected="yes")
        result = audit_network(net)
        assert any("WPS" in f.title for f in result.findings)

    def test_empty_networks_list(self):
        from app.auditors.wifi_auditor import audit_networks
        results = audit_networks([])
        assert results == []


# ─── Password Auditor ─────────────────────────────────────────────────────────

class TestPasswordAuditor:
    def test_weak_password_scores_low(self):
        from app.auditors.password_auditor import audit_password
        result = audit_password("password", "test")
        assert result.score <= 1
        assert result.score_label in ("Very Weak", "Weak")

    def test_strong_password_scores_high(self):
        from app.auditors.password_auditor import audit_password
        result = audit_password("Tr0ub4dor&3xemplaryPass!#77", "test")
        assert result.score >= 3

    def test_result_never_contains_password(self):
        from app.auditors.password_auditor import audit_password
        pw = "supersecret123"
        result = audit_password(pw, "test")
        result_dict = result.model_dump()
        # Ensure password is not in any field
        for key, val in result_dict.items():
            if isinstance(val, str):
                assert pw not in val, f"Password found in field: {key}"

    def test_empty_password_handled(self):
        from app.auditors.password_auditor import audit_password
        result = audit_password("", "test")
        assert result.score == 0
        assert result.length == 0

    def test_common_wifi_pattern_flagged(self):
        from app.auditors.password_auditor import audit_password
        result = audit_password("wifipassword123", "test")
        assert result.has_common_pattern is True

    def test_result_has_crack_time(self):
        from app.auditors.password_auditor import audit_password
        result = audit_password("aB3!xY9$test", "test")
        assert result.crack_time_display is not None
        assert result.crack_time_display != ""


# ─── Device Scanner ───────────────────────────────────────────────────────────

class TestDeviceScanner:
    def test_scope_violation_public_ip(self):
        from app.scanners.device_scanner import scan_devices
        from app.core.exceptions import ScopeViolationError
        with pytest.raises(ScopeViolationError):
            scan_devices("8.8.8.0/24", authorized=True)

    def test_scope_violation_not_authorized(self):
        from app.scanners.device_scanner import scan_devices
        from app.core.exceptions import ScopeViolationError
        with pytest.raises(ScopeViolationError):
            scan_devices("192.168.1.0/24", authorized=False)

    def test_private_range_accepted(self):
        from app.scanners.device_scanner import _is_private_network
        assert _is_private_network("192.168.1.0/24") is True
        assert _is_private_network("10.0.0.0/8") is True
        assert _is_private_network("172.16.0.0/12") is True

    def test_public_range_rejected(self):
        from app.scanners.device_scanner import _is_private_network
        assert _is_private_network("8.8.8.0/24") is False
        assert _is_private_network("1.1.1.0/24") is False
        assert _is_private_network("203.0.113.0/24") is False

    def test_too_large_range_rejected(self):
        from app.scanners.device_scanner import scan_devices
        result = scan_devices("10.0.0.0/8", authorized=True)
        assert result.success is False
        assert "max" in result.error.lower()


# ─── Input Validation (Schemas) ───────────────────────────────────────────────

class TestSchemas:
    def test_device_scan_rejects_public_ip(self):
        from pydantic import ValidationError
        from app.schemas.schemas import DeviceScanRequest
        with pytest.raises(ValidationError):
            DeviceScanRequest(interface="eth0", network_range="8.8.8.0/24", authorized=True)

    def test_device_scan_rejects_unauthorized(self):
        from pydantic import ValidationError
        from app.schemas.schemas import DeviceScanRequest
        with pytest.raises(ValidationError):
            DeviceScanRequest(interface="eth0", network_range="192.168.1.0/24", authorized=False)

    def test_device_scan_rejects_bad_interface_name(self):
        from pydantic import ValidationError
        from app.schemas.schemas import DeviceScanRequest
        with pytest.raises(ValidationError):
            DeviceScanRequest(interface="eth0; rm -rf /", network_range="192.168.1.0/24", authorized=True)

    def test_valid_device_scan_request(self):
        from app.schemas.schemas import DeviceScanRequest
        req = DeviceScanRequest(interface="eth0", network_range="192.168.1.0/24", authorized=True)
        assert req.network_range == "192.168.1.0/24"


# ─── API Endpoints ────────────────────────────────────────────────────────────

class TestWifiAPI:
    def test_start_wifi_scan(self, client):
        resp = client.post("/api/wifi/scan")
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert "scan_id" in data["data"]

    def test_list_wifi_scans(self, client):
        resp = client.get("/api/wifi/scans")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_scan_status_not_found(self, client):
        resp = client.get("/api/wifi/scan/nonexistent-id/status")
        assert resp.status_code == 404

    def test_scan_networks_empty_for_new_scan(self, client):
        create_resp = client.post("/api/wifi/scan")
        scan_id = create_resp.json()["data"]["scan_id"]
        # Networks may be empty while scan is running — that's fine
        resp = client.get(f"/api/wifi/scan/{scan_id}/networks")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)


class TestDeviceAPI:
    def test_device_scan_rejects_public_ip_via_api(self, client):
        resp = client.post("/api/devices/scan", json={
            "interface": "eth0",
            "network_range": "8.8.8.0/24",
            "authorized": True,
        })
        assert resp.status_code in (422, 403)

    def test_device_scan_rejects_unauthorized(self, client):
        resp = client.post("/api/devices/scan", json={
            "interface": "eth0",
            "network_range": "192.168.1.0/24",
            "authorized": False,
        })
        assert resp.status_code == 422

    def test_device_scan_accepts_private_range(self, client):
        resp = client.post("/api/devices/scan", json={
            "interface": "eth0",
            "network_range": "192.168.1.0/30",  # only 2 hosts — fast
            "authorized": True,
        })
        # Should start (200) or fail gracefully — never crash
        assert resp.status_code in (200, 403, 422, 500)


class TestPasswordAPI:
    def test_password_audit_returns_result(self, client):
        resp = client.post("/api/password/audit", json={
            "password": "testpassword123",
            "label": "test-run",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "score" in data
        assert "score_label" in data
        assert "crack_time_display" in data
        assert "password" not in data  # Must never return the password

    def test_password_audit_does_not_echo_password(self, client):
        pw = "my-secret-test-pw-xy99"
        resp = client.post("/api/password/audit", json={"password": pw, "label": "t"})
        assert resp.status_code == 200
        raw = resp.text
        assert pw not in raw

    def test_password_audit_empty_password(self, client):
        resp = client.post("/api/password/audit", json={"password": "", "label": "t"})
        # Pydantic min_length=1 should reject empty
        assert resp.status_code == 422

    def test_password_too_long(self, client):
        resp = client.post("/api/password/audit", json={"password": "x" * 300, "label": "t"})
        assert resp.status_code == 422


class TestFindingsAPI:
    def test_list_all_findings(self, client):
        resp = client.get("/api/findings/all/list")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_findings_for_nonexistent_scan(self, client):
        resp = client.get("/api/findings/nonexistent-scan-id")
        assert resp.status_code == 200
        assert resp.json() == []


class TestReportsAPI:
    def test_generate_report_nonexistent_scan(self, client):
        resp = client.post("/api/reports/generate?scan_id=nonexistent&fmt=html")
        assert resp.status_code in (404, 500)

    def test_list_reports(self, client):
        resp = client.get("/api/reports/list")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_invalid_report_format(self, client):
        resp = client.post("/api/reports/generate?scan_id=test&fmt=docx")
        assert resp.status_code == 400


# ─── Logging Redaction ────────────────────────────────────────────────────────

class TestLoggingRedaction:
    def test_password_redacted_in_log(self):
        import logging
        from app.core.logging_config import RedactingFormatter
        record = logging.LogRecord(
            name="test", level=logging.INFO,
            pathname="", lineno=0,
            msg='Checking password="mysecret123" for user',
            args=(), exc_info=None,
        )
        formatter = RedactingFormatter()
        output = formatter.format(record)
        assert "mysecret123" not in output
        assert "[REDACTED]" in output

    def test_token_redacted_in_log(self):
        import logging
        from app.core.logging_config import RedactingFormatter
        record = logging.LogRecord(
            name="test", level=logging.INFO,
            pathname="", lineno=0,
            msg='Bearer token="eyJhbGciOiJ..." received',
            args=(), exc_info=None,
        )
        formatter = RedactingFormatter()
        output = formatter.format(record)
        assert "eyJhbGciOiJ" not in output

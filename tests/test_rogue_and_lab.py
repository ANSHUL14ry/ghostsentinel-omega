"""
GHOSTSENTINEL Ω — Tests for Rogue AP Detection & Controlled Security Lab
Covers:
- Trusted Baseline CRUD (API & DB)
- Rogue AP & Evil Twin Detection (BSSID mismatch, security downgrade, channel anomaly)
- Multi-AP Mesh Compliance (No false positive on shared SSID with authorized BSSIDs)
- Controlled Wireless Security Lab Assessment (Authorization enforcement, cipher evaluation, PMF, router ports)
"""
import json
import pytest
from app.auditors.rogue_detector import audit_rogue_access_points, _normalize_mac
from app.auditors.lab_auditor import run_lab_assessment
from app.models.baseline import TrustedBaseline
from app.scanners.wifi_scanner import WifiNetwork


class TestRogueDetector:
    def test_normalize_mac(self):
        assert _normalize_mac("aa-bb-cc-dd-ee-ff") == "AA:BB:CC:DD:EE:FF"
        assert _normalize_mac("AA:BB:CC:DD:EE:FF") == "AA:BB:CC:DD:EE:FF"
        assert _normalize_mac(" 00:11:22:33:44:55 ") == "00:11:22:33:44:55"
        assert _normalize_mac(None) == ""

    def test_authorized_ap_yields_zero_rogue_findings(self):
        baseline = TrustedBaseline(
            id="base-1",
            ssid="Corporate-Secure",
            allowed_bssids=json.dumps(["00:11:22:33:44:55"]),
            expected_security="WPA2",
            allowed_channels=json.dumps([1, 6, 11]),
        )
        observed = [
            WifiNetwork(
                ssid="Corporate-Secure",
                bssid="00:11:22:33:44:55",
                channel=6,
                security="WPA2-PSK",
                signal_dbm=-55,
            )
        ]
        summary = audit_rogue_access_points(observed, [baseline])
        assert summary.total_baselines_checked == 1
        assert summary.matched_networks == 1
        assert summary.rogue_aps_detected == 0
        assert summary.downgrades_detected == 0
        assert summary.channel_anomalies == 0
        assert len(summary.findings) == 0

    def test_multi_ap_mesh_same_ssid_not_flagged_malicious(self):
        """
        Master Build Prompt Section 3.D:
        'Do not label a network malicious solely because multiple access points share an SSID.'
        """
        baseline = TrustedBaseline(
            id="base-mesh",
            ssid="Campus-Mesh",
            allowed_bssids=json.dumps(["AA:BB:CC:11:22:33", "AA:BB:CC:44:55:66"]),
            expected_security="WPA2",
            allowed_channels=json.dumps([1, 6, 11]),
        )
        observed = [
            WifiNetwork(ssid="Campus-Mesh", bssid="AA:BB:CC:11:22:33", channel=1, security="WPA2"),
            WifiNetwork(ssid="Campus-Mesh", bssid="AA:BB:CC:44:55:66", channel=6, security="WPA2"),
        ]
        summary = audit_rogue_access_points(observed, [baseline])
        assert summary.matched_networks == 2
        assert summary.rogue_aps_detected == 0
        assert len(summary.findings) == 0

    def test_unauthorized_bssid_flagged_as_evil_twin(self):
        baseline = TrustedBaseline(
            id="base-2",
            ssid="Company-HQ",
            allowed_bssids=json.dumps(["00:11:22:33:44:55"]),
            expected_security="WPA2",
        )
        observed = [
            WifiNetwork(
                ssid="Company-HQ",
                bssid="DE:AD:BE:EF:00:01",
                channel=6,
                security="WPA2",
                signal_dbm=-42,
            )
        ]
        summary = audit_rogue_access_points(observed, [baseline])
        assert summary.rogue_aps_detected == 1
        assert len(summary.findings) == 1
        finding = summary.findings[0]
        assert "Rogue AP / Potential Evil Twin" in finding.title
        assert finding.severity == "high"
        assert finding.status == "confirmed"
        assert any("DE:AD:BE:EF:00:01" in ev for ev in finding.evidence)

    def test_open_evil_twin_is_critical_severity(self):
        baseline = TrustedBaseline(
            id="base-3",
            ssid="SecureCorp",
            allowed_bssids=json.dumps(["00:11:22:33:44:55"]),
            expected_security="WPA2",
        )
        observed = [
            WifiNetwork(
                ssid="SecureCorp",
                bssid="99:88:77:66:55:44",
                channel=1,
                security="OPEN",
                signal_dbm=-30,
            )
        ]
        summary = audit_rogue_access_points(observed, [baseline])
        assert summary.rogue_aps_detected == 1
        assert summary.downgrades_detected == 1  # WPA2 -> OPEN is also a downgrade!
        critical_findings = [f for f in summary.findings if f.severity == "critical"]
        assert len(critical_findings) >= 1

    def test_security_downgrade_detected(self):
        baseline = TrustedBaseline(
            id="base-4",
            ssid="Office-WPA3",
            allowed_bssids=json.dumps(["11:22:33:44:55:66"]),
            expected_security="WPA3",
        )
        observed = [
            WifiNetwork(
                ssid="Office-WPA3",
                bssid="11:22:33:44:55:66",  # Authorized BSSID
                channel=6,
                security="WPA",             # Weak downgrade
            )
        ]
        summary = audit_rogue_access_points(observed, [baseline])
        assert summary.rogue_aps_detected == 0  # BSSID is authorized
        assert summary.downgrades_detected == 1
        finding = summary.findings[0]
        assert "Security Downgrade" in finding.title
        assert finding.severity == "critical"

    def test_channel_anomaly_detected(self):
        baseline = TrustedBaseline(
            id="base-5",
            ssid="Branch-Office",
            allowed_bssids=json.dumps(["00:AA:BB:CC:DD:EE"]),
            expected_security="WPA2",
            allowed_channels=json.dumps([1, 6, 11]),
        )
        observed = [
            WifiNetwork(
                ssid="Branch-Office",
                bssid="00:AA:BB:CC:DD:EE",
                channel=36,  # 5GHz channel not in 1, 6, 11
                security="WPA2",
            )
        ]
        summary = audit_rogue_access_points(observed, [baseline])
        assert summary.channel_anomalies == 1
        assert any("Channel Anomaly" in f.title for f in summary.findings)


class TestSecurityLabAuditor:
    def test_unauthorized_assessment_strictly_rejected(self):
        with pytest.raises(ValueError, match="requires explicit user authorization"):
            run_lab_assessment(
                target_ssid="LabRouter",
                authorized=False,
            )

    def test_open_network_lab_assessment(self):
        res = run_lab_assessment(
            target_ssid="Lab-Open-Test",
            security="OPEN",
            authorized=True,
        )
        assert res.score < 70
        assert res.security_posture in ("NEEDS_REVIEW", "CRITICAL_RISK")
        assert any("Unencrypted Transmission" in f.title for f in res.findings)

    def test_wpa3_lab_assessment_mandates_pmf(self):
        res = run_lab_assessment(
            target_ssid="Lab-WPA3-Test",
            security="WPA3",
            wps_detected="no",
            authorized=True,
        )
        assert res.score >= 90
        assert res.security_posture == "SECURE"
        assert any("802.11w" in f.title and "Mandatory" in f.title for f in res.findings)

    def test_wpa2_psk_lab_assessment_flags_dictionary_risk(self):
        res = run_lab_assessment(
            target_ssid="Lab-WPA2-Test",
            security="WPA2",
            wps_detected="yes",
            authorized=True,
        )
        assert any("Dictionary Exposure" in f.title for f in res.findings)
        assert any("WPS" in f.title for f in res.findings)

    def test_router_ip_public_ip_rejected(self):
        res = run_lab_assessment(
            target_ssid="Lab-Router-Test",
            security="WPA2",
            router_ip="8.8.8.8",  # Public Google DNS — should be rejected/skipped
            authorized=True,
        )
        assert any("not an RFC-1918 private address" in note for note in res.notes)


class TestBaselineAndLabAPI:
    def test_baseline_add_and_list(self, client):
        # 1. Add baseline
        payload = {
            "ssid": "SecureCorp-Internal",
            "allowed_bssids": ["00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF"],
            "expected_security": "WPA3",
            "allowed_channels": [1, 6, 11],
            "notes": "Main internal office Wi-Fi",
        }
        res = client.post("/api/baseline/add", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["success"] is True

        # 2. List baselines
        list_res = client.get("/api/baseline/list")
        assert list_res.status_code == 200
        baselines = list_res.json()
        found = [b for b in baselines if b["ssid"] == "SecureCorp-Internal"]
        assert len(found) == 1
        baseline_id = found[0]["id"]
        assert "00:11:22:33:44:55" in found[0]["allowed_bssids"]

        # 3. Delete baseline
        del_res = client.delete(f"/api/baseline/{baseline_id}")
        assert del_res.status_code == 200
        assert del_res.json()["success"] is True

        # Verify deleted
        list_res2 = client.get("/api/baseline/list")
        assert not any(b["id"] == baseline_id for b in list_res2.json())

    def test_baseline_validation_invalid_bssid(self, client):
        bad_payload = {
            "ssid": "Bad-BSSID-Test",
            "allowed_bssids": ["not-a-valid-mac"],
            "expected_security": "WPA2",
        }
        res = client.post("/api/baseline/add", json=bad_payload)
        assert res.status_code == 422

    def test_lab_api_rejects_unauthorized(self, client):
        payload = {
            "target_ssid": "UnauthorizedAP",
            "authorized": False,
        }
        res = client.post("/api/lab/assess", json=payload)
        assert res.status_code == 422  # Pydantic validator rejects authorized=False

    def test_lab_api_rejects_public_router_ip(self, client):
        payload = {
            "target_ssid": "TestAP",
            "authorized": True,
            "router_ip": "1.1.1.1",  # Cloudflare public IP
        }
        res = client.post("/api/lab/assess", json=payload)
        assert res.status_code == 422

    def test_lab_api_successful_assessment(self, client):
        payload = {
            "target_ssid": "Lab-Approved-AP",
            "target_bssid": "00:11:22:33:44:55",
            "security": "WPA2-PSK",
            "channel": 6,
            "wps_detected": "no",
            "authorized": True,
        }
        res = client.post("/api/lab/assess", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["success"] is True
        assert data["data"]["target_ssid"] == "Lab-Approved-AP"
        assert "score" in data["data"]
        assert "findings" in data["data"]

    def test_audit_rogues_endpoint_empty_baselines(self, client):
        res = client.post("/api/baseline/audit_rogues")
        assert res.status_code == 200
        data = res.json()
        assert data["success"] is True

    def test_audit_rogues_with_configured_baseline(self, client):
        # Register a baseline
        payload = {
            "ssid": "Test-Baseline-Net",
            "allowed_bssids": ["52:66:48:db:f2:c5"],
            "expected_security": "Open",
            "allowed_channels": [13],
        }
        add_res = client.post("/api/baseline/add", json=payload)
        assert add_res.status_code == 200

        # Run rogue audit
        audit_res = client.post("/api/baseline/audit_rogues")
        assert audit_res.status_code == 200
        audit_data = audit_res.json()
        assert audit_data["success"] is True
        assert "total_baselines" in audit_data["data"]

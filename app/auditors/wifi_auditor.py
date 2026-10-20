"""
GHOSTSENTINEL Ω — Wi-Fi Security Auditor (Module B)

Analyses observed network data and produces evidence-based findings.
Never claims a network is vulnerable solely because a protocol exists.
Clearly distinguishes confirmed / potential / unavailable / not-tested.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from app.scanners.wifi_scanner import WifiNetwork


@dataclass
class AuditFinding:
    title: str
    description: str
    severity: str      # critical / high / medium / low / info
    status: str        # confirmed / potential / info_unavailable / not_tested
    evidence: List[str] = field(default_factory=list)
    remediation: str = ""
    references: List[str] = field(default_factory=list)


@dataclass
class NetworkAuditResult:
    ssid: Optional[str]
    bssid: Optional[str]
    findings: List[AuditFinding] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# Individual checks (each returns Optional[AuditFinding])
# ─────────────────────────────────────────────────────────────────────────────

def _check_open_network(net: WifiNetwork) -> Optional[AuditFinding]:
    if net.security and net.security.upper() == "OPEN":
        return AuditFinding(
            title="Open Network (No Encryption)",
            description=(
                f"Network '{net.ssid}' broadcasts without encryption. "
                "All traffic is transmitted in plaintext and can be captured by nearby observers."
            ),
            severity="critical",
            status="confirmed",
            evidence=[f"Security: {net.security}", f"Encryption: {net.encryption}"],
            remediation=(
                "Enable WPA2-Personal or WPA3-Personal on the access point. "
                "If this is a public hotspot, use HTTPS and a VPN for all traffic."
            ),
            references=[
                "https://www.wi-fi.org/discover-wi-fi/security",
                "https://nvd.nist.gov/800-53/Rev4/control/SC-8",
            ],
        )
    return None


def _check_wep(net: WifiNetwork) -> Optional[AuditFinding]:
    if net.security and "WEP" in net.security.upper():
        return AuditFinding(
            title="WEP Encryption Detected",
            description=(
                "WEP (Wired Equivalent Privacy) is a deprecated and cryptographically broken protocol. "
                "It can be cracked in minutes using publicly available tools."
            ),
            severity="critical",
            status="confirmed",
            evidence=[f"Security: {net.security}"],
            remediation=(
                "Replace WEP with WPA2-AES or WPA3 immediately. "
                "Most modern routers support WPA3 or at minimum WPA2."
            ),
            references=[
                "https://www.kb.cert.org/vuls/id/723755",
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2001-0952",
            ],
        )
    return None


def _check_wpa1_only(net: WifiNetwork) -> Optional[AuditFinding]:
    sec = (net.security or "").upper()
    if "WPA" in sec and "WPA2" not in sec and "WPA3" not in sec:
        return AuditFinding(
            title="WPA (TKIP) Without WPA2/WPA3",
            description=(
                "WPA with TKIP is considered weak and deprecated. "
                "TKIP has known vulnerabilities (Beck-Tews, Ohigashi-Morii attacks)."
            ),
            severity="high",
            status="confirmed",
            evidence=[f"Security: {net.security}", f"Authentication: {net.authentication}"],
            remediation="Upgrade to WPA2-AES or WPA3 on the access point.",
            references=["https://www.wi-fi.org/knowledge-center/faq/what-is-wpa3"],
        )
    return None


def _check_wpa2_psk(net: WifiNetwork) -> Optional[AuditFinding]:
    sec = (net.security or "").upper()
    auth = (net.authentication or "").upper()
    if "WPA2" in sec and ("PSK" in auth or "PERSONAL" in auth):
        return AuditFinding(
            title="WPA2-PSK Detected (Pre-Shared Key Mode)",
            description=(
                "WPA2-PSK networks are susceptible to offline dictionary attacks if the handshake "
                "is captured. A weak passphrase can be cracked. "
                "No vulnerability is confirmed without testing the passphrase strength."
            ),
            severity="medium",
            status="potential",
            evidence=[f"Security: {net.security}", f"Authentication: {net.authentication}"],
            remediation=(
                "Use a random passphrase of at least 20 characters. "
                "Consider upgrading to WPA3-SAE which resists offline dictionary attacks."
            ),
            references=["https://www.wi-fi.org/discover-wi-fi/wi-fi-certified-wpa3"],
        )
    return None


def _check_wpa3(net: WifiNetwork) -> Optional[AuditFinding]:
    if net.security and "WPA3" in net.security.upper():
        return AuditFinding(
            title="WPA3 Detected",
            description="WPA3 provides the strongest currently available consumer Wi-Fi security.",
            severity="info",
            status="confirmed",
            evidence=[f"Security: {net.security}"],
            remediation="No action required. Ensure all client devices support WPA3.",
        )
    return None


def _check_hidden_ssid(net: WifiNetwork) -> Optional[AuditFinding]:
    if net.ssid is None or net.ssid == "":
        return AuditFinding(
            title="Hidden SSID Observed",
            description=(
                "The network does not broadcast an SSID. "
                "SSID hiding provides minimal security — the SSID is exposed in probe requests. "
                "This is an observation, not a vulnerability by itself."
            ),
            severity="info",
            status="confirmed",
            evidence=["SSID field is empty in beacon frame."],
            remediation="Do not rely on SSID hiding as a security measure. Use strong WPA2/WPA3.",
        )
    return None


def _check_wps_detected(net: WifiNetwork) -> Optional[AuditFinding]:
    if net.wps_detected == "yes":
        return AuditFinding(
            title="WPS Detected",
            description=(
                "Wi-Fi Protected Setup (WPS) is enabled. WPS PIN mode is vulnerable to brute-force "
                "(Reaver, Pixie-Dust attacks). Push-Button-Connect (PBC) is less risky."
            ),
            severity="high",
            status="potential",
            evidence=["WPS information element present in beacon."],
            remediation=(
                "Disable WPS on the access point unless explicitly required. "
                "If WPS must be enabled, use Push-Button only and disable PIN mode."
            ),
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2011-5053",
                "https://tools.ietf.org/html/rfc6614",
            ],
        )
    return None


def _check_signal_strength(net: WifiNetwork) -> Optional[AuditFinding]:
    if net.signal_dbm is not None and net.signal_dbm > -30:
        return AuditFinding(
            title="Very Strong Signal — Potential Physical Proximity Risk",
            description=(
                f"Signal strength {net.signal_dbm} dBm indicates the AP is very close. "
                "Extremely strong signals may indicate the AP is exposed in a public area."
            ),
            severity="info",
            status="potential",
            evidence=[f"Signal: {net.signal_dbm} dBm"],
            remediation="Consider adjusting transmit power on the AP to minimise signal bleed beyond the premises.",
        )
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Main audit function
# ─────────────────────────────────────────────────────────────────────────────

def audit_network(net: WifiNetwork) -> NetworkAuditResult:
    """
    Run all evidence-based checks against a single observed network.
    Returns a NetworkAuditResult with findings.
    Never invents findings — each check only fires on observed evidence.
    """
    result = NetworkAuditResult(ssid=net.ssid, bssid=net.bssid)

    checks = [
        _check_open_network,
        _check_wep,
        _check_wpa1_only,
        _check_wpa2_psk,
        _check_wpa3,
        _check_hidden_ssid,
        _check_wps_detected,
        _check_signal_strength,
    ]

    for check in checks:
        finding = check(net)
        if finding:
            result.findings.append(finding)

    if not result.findings:
        result.notes.append(
            "No specific findings from observed data. "
            "Checks requiring additional information (WPS, firmware version) were not performed."
        )

    # Note unavailable data
    if net.authentication is None:
        result.notes.append("Authentication mechanism: NOT AVAILABLE from this scan method.")
    if net.wps_detected == "unknown":
        result.notes.append("WPS status: NOT TESTED — requires beacon frame analysis.")

    return result


def audit_networks(networks: List[WifiNetwork]) -> List[NetworkAuditResult]:
    """Run audit_network on every discovered network."""
    return [audit_network(n) for n in networks]

"""
GHOSTSENTINEL Ω — Controlled Wireless Security Lab Auditor (Module C)

Performs authorized, evidence-based security assessments against user-owned
or explicitly permitted test access points and routers in an isolated lab environment.

Strict Rules:
- NEVER runs unless authorized == True.
- Only performs non-destructive configuration and exposure checks.
- Enforces RFC-1918 private IP scope for gateway management probes.
- Never fabricates vulnerabilities; clearly indicates limitations.
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any

from app.auditors.wifi_auditor import AuditFinding


@dataclass
class LabAssessmentResult:
    target_ssid: str
    target_bssid: Optional[str]
    authorized: bool
    score: int
    security_posture: str  # "SECURE", "ACCEPTABLE", "NEEDS_REVIEW", "CRITICAL_RISK"
    checks_run: List[Dict[str, str]] = field(default_factory=list)
    findings: List[AuditFinding] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


def _probe_port(ip: str, port: int, timeout: float = 1.0) -> bool:
    """Non-destructive TCP SYN check with short timeout to detect open administrative ports."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            return result == 0
    except Exception:
        return False


def run_lab_assessment(
    target_ssid: str,
    target_bssid: Optional[str] = None,
    security: Optional[str] = None,
    channel: Optional[int] = None,
    router_ip: Optional[str] = None,
    wps_detected: Optional[str] = None,
    authorized: bool = False,
) -> LabAssessmentResult:
    """
    Execute controlled lab security checks on an authorized target network.
    Raises ValueError if authorized is False.
    """
    if not authorized:
        raise ValueError("Lab assessment requires explicit user authorization confirmation.")

    sec_str = (security or "UNKNOWN").upper()
    checks: List[Dict[str, str]] = []
    findings: List[AuditFinding] = []
    notes: List[str] = []

    # ─────────────────────────────────────────────────────────────────────────
    # 1. Protocol & Encryption Suite Assessment
    # ─────────────────────────────────────────────────────────────────────────
    if sec_str in ("OPEN", "NONE"):
        checks.append({"check": "Encryption Protocol", "status": "CRITICAL", "detail": "No encryption active (Open)"})
        findings.append(AuditFinding(
            title="Unencrypted Transmission (Open Wi-Fi)",
            description=f"Lab target '{target_ssid}' transmits all 802.11 frames in cleartext without link-layer encryption.",
            severity="critical",
            status="confirmed",
            evidence=[f"Configured Security: {security}"],
            remediation="Enable WPA3-SAE or WPA2-AES (CCMP) immediately in the router wireless configuration.",
            references=["https://www.wi-fi.org/discover-wi-fi/security"],
        ))
    elif "WEP" in sec_str:
        checks.append({"check": "Encryption Protocol", "status": "CRITICAL", "detail": "WEP (Deprecated / Broken)"})
        findings.append(AuditFinding(
            title="Cryptographically Deprecated WEP Encryption",
            description="WEP uses 24-bit initialization vectors susceptible to statistical key recovery in minutes.",
            severity="critical",
            status="confirmed",
            evidence=[f"Configured Security: {security}"],
            remediation="Replace with WPA2-AES or WPA3. WEP provides negligible confidentiality.",
            references=["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2001-0952"],
        ))
    elif "WPA3" in sec_str:
        checks.append({"check": "Encryption Protocol", "status": "EXCELLENT", "detail": "WPA3-SAE (Dragonfly handshake)"})
        findings.append(AuditFinding(
            title="Modern WPA3-SAE Security Configured",
            description="The lab network utilizes WPA3-Personal (SAE), offering forward secrecy and offline dictionary resistance.",
            severity="info",
            status="confirmed",
            evidence=[f"Protocol: {security}"],
            remediation="Ensure client roaming compatibility and enforce transition mode disabling if all clients support WPA3.",
            references=["https://www.wi-fi.org/discover-wi-fi/wi-fi-certified-wpa3"],
        ))
    elif "WPA2" in sec_str:
        checks.append({"check": "Encryption Protocol", "status": "ACCEPTABLE", "detail": "WPA2-CCMP / PSK"})
        findings.append(AuditFinding(
            title="WPA2-PSK Offline Dictionary Exposure Risk",
            description=(
                "WPA2-PSK relies on 4-way handshake mutual authentication. If captured, "
                "the Pre-Shared Key can be attacked offline without interacting with the router."
            ),
            severity="medium",
            status="potential",
            evidence=[f"Protocol: {security}", "Authentication: PSK"],
            remediation=(
                "Use high-entropy passphrases (>= 20 characters, mixed charset) or upgrade to WPA3-SAE. "
                "Audit local passphrase entropy using the Password Audit module."
            ),
            references=["https://www.wi-fi.org/discover-wi-fi/security"],
        ))

    # ─────────────────────────────────────────────────────────────────────────
    # 2. 802.11w Protected Management Frames (PMF) Check
    # ─────────────────────────────────────────────────────────────────────────
    if "WPA3" in sec_str:
        checks.append({"check": "802.11w PMF Protection", "status": "PROTECTED", "detail": "Mandatory in WPA3 specification"})
        findings.append(AuditFinding(
            title="Protected Management Frames (802.11w) Mandatory",
            description="WPA3 specification mandates PMF, shielding unicast and broadcast management frames from spoofed disassociation.",
            severity="info",
            status="confirmed",
            evidence=["WPA3-SAE enforces 802.11w PMF"],
            remediation="Keep PMF set to Required in the router administration panel.",
            references=["https://standards.ieee.org/standard/802_11w-2009.html"],
        ))
    else:
        checks.append({"check": "802.11w PMF Protection", "status": "POTENTIAL_RISK", "detail": "Optional or Disabled in legacy WPA2"})
        findings.append(AuditFinding(
            title="Potential Susceptibility to 802.11 Management Frame Spoofing",
            description=(
                "Under standard WPA2 configurations without 802.11w Protected Management Frames, "
                "disassociation and deauthentication frames are unauthenticated and vulnerable to RF spoofing."
            ),
            severity="medium",
            status="potential",
            evidence=[f"Protocol {security} does not strictly mandate 802.11w PMF"],
            remediation="Verify if your access point firmware allows enabling 'Protected Management Frames: Optional / Required'.",
            references=["https://standards.ieee.org/standard/802_11w-2009.html"],
        ))

    # ─────────────────────────────────────────────────────────────────────────
    # 3. WPS (Wi-Fi Protected Setup) Assessment
    # ─────────────────────────────────────────────────────────────────────────
    if wps_detected == "yes":
        checks.append({"check": "WPS Exposure", "status": "HIGH_RISK", "detail": "WPS advertised on beacon"})
        findings.append(AuditFinding(
            title="Wi-Fi Protected Setup (WPS) Enabled",
            description="WPS PIN authentication is mathematically flawed (11,000 max guesses). If PIN mode is active, the AP is exposed to brute-force.",
            severity="high",
            status="potential",
            evidence=["WPS Information Element present"],
            remediation="Disable WPS entirely in the router configuration. If necessary, use Push-Button only.",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2011-5053"],
        ))
    elif wps_detected == "no":
        checks.append({"check": "WPS Exposure", "status": "SECURE", "detail": "WPS disabled / not advertised"})
    else:
        checks.append({"check": "WPS Exposure", "status": "UNAVAILABLE", "detail": "Beacon element not captured"})
        notes.append("WPS status was not available from the current wireless telemetry scan.")

    # ─────────────────────────────────────────────────────────────────────────
    # 4. Router Admin Gateway Surface Check (RFC-1918 safe socket probe)
    # ─────────────────────────────────────────────────────────────────────────
    if router_ip:
        try:
            ip_obj = ipaddress.ip_address(router_ip.strip())
            if not ip_obj.is_private:
                checks.append({"check": "Gateway Administration", "status": "REJECTED", "detail": "Non-private IP address"})
                notes.append(f"Gateway probe skipped: {router_ip} is not an RFC-1918 private address.")
            else:
                target_ip = str(ip_obj)
                port_80_open = _probe_port(target_ip, 80)
                port_443_open = _probe_port(target_ip, 443)
                port_8080_open = _probe_port(target_ip, 8080)
                port_8443_open = _probe_port(target_ip, 8443)

                any_admin_open = port_80_open or port_443_open or port_8080_open or port_8443_open
                ports_detail = []
                if port_80_open: ports_detail.append("80(HTTP)")
                if port_443_open: ports_detail.append("443(HTTPS)")
                if port_8080_open: ports_detail.append("8080(HTTP-Alt)")
                if port_8443_open: ports_detail.append("8443(HTTPS-Alt)")

                if port_80_open and not port_443_open:
                    checks.append({"check": "Router Management Surface", "status": "HIGH_RISK", "detail": "Cleartext HTTP only (Port 80)"})
                    findings.append(AuditFinding(
                        title="Unencrypted Cleartext Router Management Portal (HTTP:80)",
                        description=(
                            f"The gateway at {target_ip} serves an administrative web interface over unencrypted HTTP (Port 80). "
                            "Administrative passwords and session tokens can be sniffed by anyone on the local network."
                        ),
                        severity="high",
                        status="confirmed",
                        evidence=[f"Gateway IP: {target_ip}", "Port 80: OPEN", "Port 443: CLOSED"],
                        remediation="Enable HTTPS management in router settings and disable plain HTTP administration.",
                        references=["https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"],
                    ))
                elif port_80_open and port_443_open:
                    checks.append({"check": "Router Management Surface", "status": "MEDIUM_RISK", "detail": "HTTP & HTTPS both open"})
                    findings.append(AuditFinding(
                        title="Router Management Interface Permits Unencrypted HTTP",
                        description=f"Router management on {target_ip} is accessible via HTTP (80) and HTTPS (443). Plain HTTP traffic may be intercepted.",
                        severity="medium",
                        status="confirmed",
                        evidence=[f"Gateway IP: {target_ip}", "Port 80: OPEN", "Port 443: OPEN"],
                        remediation="Configure automatic HTTP-to-HTTPS redirect or disable HTTP access completely.",
                        references=["https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"],
                    ))
                elif port_443_open or port_8443_open:
                    checks.append({"check": "Router Management Surface", "status": "SECURE", "detail": "Encrypted HTTPS only"})
                    findings.append(AuditFinding(
                        title="Encrypted Router Administration Surface",
                        description=f"The gateway at {target_ip} provides encrypted TLS/HTTPS access for administrative management.",
                        severity="info",
                        status="confirmed",
                        evidence=[f"Gateway IP: {target_ip}", f"Open Ports: {', '.join(ports_detail)}"],
                        remediation="Ensure modern TLS versions (TLS 1.2 / 1.3) are enforced and change default administrative credentials.",
                    ))
                else:
                    checks.append({"check": "Router Management Surface", "status": "CLOSED", "detail": "No standard web admin ports open"})
                    notes.append(f"No standard web ports (80, 443, 8080, 8443) responded on gateway {target_ip}.")
        except ValueError:
            notes.append(f"Invalid IP format provided for gateway probe: {router_ip}")
    else:
        notes.append("No router gateway IP provided; gateway management surface checks were omitted.")

    # ─────────────────────────────────────────────────────────────────────────
    # 5. Score Calculation
    # ─────────────────────────────────────────────────────────────────────────
    score = 100
    for f in findings:
        if f.severity == "critical":
            score -= 35
        elif f.severity == "high":
            score -= 20
        elif f.severity == "medium":
            score -= 10
        elif f.severity == "low":
            score -= 5

    score = max(0, min(100, score))

    if score >= 90:
        posture = "SECURE"
    elif score >= 70:
        posture = "ACCEPTABLE"
    elif score >= 50:
        posture = "NEEDS_REVIEW"
    else:
        posture = "CRITICAL_RISK"

    return LabAssessmentResult(
        target_ssid=target_ssid,
        target_bssid=target_bssid,
        authorized=authorized,
        score=score,
        security_posture=posture,
        checks_run=checks,
        findings=findings,
        notes=notes,
    )

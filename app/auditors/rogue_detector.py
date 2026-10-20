"""
GHOSTSENTINEL Ω — Rogue Access Point & Evil Twin Auditor (Module D)

Compares observed wireless broadcasts against user-maintained trusted baselines.
Identifies unauthorized BSSIDs, security downgrades, and RF channel anomalies.
Follows strict evidence-based rules: never flags multiple APs as malicious
solely because they share an SSID (enterprise/mesh roaming).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import List, Optional, Any, Dict

from app.auditors.wifi_auditor import AuditFinding
from app.models.baseline import TrustedBaseline
from app.scanners.wifi_scanner import WifiNetwork


@dataclass
class RogueDetectionSummary:
    total_baselines_checked: int = 0
    matched_networks: int = 0
    rogue_aps_detected: int = 0
    downgrades_detected: int = 0
    channel_anomalies: int = 0
    findings: List[AuditFinding] = field(default_factory=list)


def _normalize_mac(mac: Optional[str]) -> str:
    """Normalize MAC/BSSID string to uppercase colon-separated format."""
    if not mac:
        return ""
    clean = mac.strip().upper().replace("-", ":")
    return clean


def _parse_json_list(val: Any) -> List[Any]:
    """Parse JSON string list or return list directly."""
    if isinstance(val, list):
        return val
    if isinstance(val, str) and val.strip():
        try:
            parsed = json.loads(val)
            if isinstance(parsed, list):
                return parsed
        except (json.JSONDecodeError, ValueError):
            # Split comma separated if not json
            return [x.strip() for x in val.split(",") if x.strip()]
    return []


def _security_level(sec: Optional[str]) -> int:
    """
    Rough relative ranking of Wi-Fi security strength.
    Higher number = stronger security.
    """
    if not sec:
        return 0
    s = sec.upper()
    if "WPA3" in s:
        return 4
    if "WPA2" in s:
        return 3
    if "WPA" in s:
        return 2
    if "WEP" in s:
        return 1
    if "OPEN" in s or s == "NONE":
        return 0
    return 1


def audit_rogue_access_points(
    observed_networks: List[WifiNetwork],
    baselines: List[TrustedBaseline],
) -> RogueDetectionSummary:
    """
    Compare observed networks against trusted baselines and detect rogue APs/Evil Twins.
    """
    summary = RogueDetectionSummary(
        total_baselines_checked=len(baselines),
    )

    if not baselines or not observed_networks:
        return summary

    for baseline in baselines:
        b_ssid = (baseline.ssid or "").strip()
        if not b_ssid:
            continue

        raw_allowed_bssids = _parse_json_list(baseline.allowed_bssids)
        allowed_bssids = {_normalize_mac(str(m)) for m in raw_allowed_bssids if m}
        expected_sec = (baseline.expected_security or "").strip()
        expected_sec_level = _security_level(expected_sec)

        raw_channels = _parse_json_list(baseline.allowed_channels)
        allowed_channels = {int(c) for c in raw_channels if str(c).isdigit()}

        # Find all observed APs broadcasting this SSID
        matching_observed = [
            n for n in observed_networks
            if (n.ssid or "").strip().lower() == b_ssid.lower()
        ]

        if matching_observed:
            summary.matched_networks += len(matching_observed)

        for obs in matching_observed:
            obs_bssid = _normalize_mac(obs.bssid)

            # Rule 1: BSSID Mismatch (Evil Twin / Unauthorized Rogue AP)
            if allowed_bssids and obs_bssid and obs_bssid not in allowed_bssids:
                summary.rogue_aps_detected += 1
                is_open = (obs.security or "").upper() in ("OPEN", "NONE")
                severity = "critical" if is_open else "high"
                finding = AuditFinding(
                    title=f"Rogue AP / Potential Evil Twin Detected for '{b_ssid}'",
                    description=(
                        f"An access point broadcasting trusted SSID '{b_ssid}' has BSSID {obs.bssid}, "
                        f"which is NOT in the authorized baseline list for this network. "
                        "This may indicate a rogue AP deployment or an Evil Twin honeypot attack."
                    ),
                    severity=severity,
                    status="confirmed",
                    evidence=[
                        f"Target SSID: {b_ssid}",
                        f"Observed BSSID: {obs.bssid}",
                        f"Authorized BSSIDs: {sorted(list(allowed_bssids))}",
                        f"Observed Security: {obs.security or 'Unknown'}",
                        f"Observed Signal: {obs.signal_dbm} dBm" if obs.signal_dbm is not None else "Signal: N/A",
                        f"Observed Channel: {obs.channel}" if obs.channel is not None else "Channel: N/A",
                    ],
                    remediation=(
                        f"1. Physically locate the access point broadcasting BSSID {obs.bssid}.\n"
                        "2. If this is legitimate new hardware or an added mesh node, update the trusted baseline.\n"
                        "3. If this device is unauthorized, investigate immediately and disconnect clients."
                    ),
                    references=[
                        "https://csrc.nist.gov/publications/detail/sp/800-153/final",
                        "https://www.wi-fi.org/discover-wi-fi/security",
                    ],
                )
                summary.findings.append(finding)

            # Rule 2: Security Protocol Downgrade
            if expected_sec and obs.security:
                obs_sec_level = _security_level(obs.security)
                if obs_sec_level < expected_sec_level:
                    summary.downgrades_detected += 1
                    finding = AuditFinding(
                        title=f"Security Downgrade Attack Detected for '{b_ssid}'",
                        description=(
                            f"Network '{b_ssid}' (BSSID {obs.bssid}) is broadcasting {obs.security}, "
                            f"which is weaker than the baseline expected security ({expected_sec}). "
                            "This could be an active Evil Twin downgrade attack attempting to bypass modern WPA encryption."
                        ),
                        severity="critical",
                        status="confirmed",
                        evidence=[
                            f"SSID: {b_ssid}",
                            f"BSSID: {obs.bssid}",
                            f"Expected Security: {expected_sec}",
                            f"Observed Security: {obs.security}",
                        ],
                        remediation=(
                            "1. Inspect the router configuration to ensure legacy encryption modes are disabled.\n"
                            "2. Prevent client devices from automatically connecting to open or downgraded networks."
                        ),
                        references=[
                            "https://csrc.nist.gov/publications/detail/sp/800-153/final",
                        ],
                    )
                    summary.findings.append(finding)

            # Rule 3: Channel Anomaly
            if allowed_channels and obs.channel is not None and obs.channel not in allowed_channels:
                summary.channel_anomalies += 1
                finding = AuditFinding(
                    title=f"Channel Anomaly for '{b_ssid}'",
                    description=(
                        f"Network '{b_ssid}' (BSSID {obs.bssid}) was observed operating on channel {obs.channel}, "
                        f"which is outside the baseline configured channels {sorted(list(allowed_channels))}."
                    ),
                    severity="low",
                    status="potential",
                    evidence=[
                        f"SSID: {b_ssid}",
                        f"BSSID: {obs.bssid}",
                        f"Observed Channel: {obs.channel}",
                        f"Allowed Channels: {sorted(list(allowed_channels))}",
                    ],
                    remediation=(
                        "Verify whether dynamic channel selection (Auto-Channel) changed the router operating channel, "
                        "or whether an unauthorized radio is broadcasting."
                    ),
                    references=[],
                )
                summary.findings.append(finding)

    return summary

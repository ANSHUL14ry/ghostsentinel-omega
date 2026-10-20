"""
GHOSTSENTINEL Ω — Device Scanner (Module D)

Discovers reachable hosts on an explicitly authorised private network.
Uses ping sweep + optional nmap for service detection.
Enforces: private ranges only, explicit authorization required, rate limiting.
"""
from __future__ import annotations

import ipaddress
import json
import platform
import re
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

from app.core.config import settings
from app.core.exceptions import ScopeViolationError
from app.core.logging_config import get_logger

logger = get_logger(__name__)

OS = platform.system()

# Only RFC-1918 private ranges are allowed
PRIVATE_NETWORKS = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
]


@dataclass
class DiscoveredDevice:
    ip_address: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    open_ports: List[int] = field(default_factory=list)
    services: dict = field(default_factory=dict)
    is_potential_camera: bool = False
    camera_evidence: List[str] = field(default_factory=list)
    discovered_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class DeviceScanResult:
    success: bool
    devices: List[DiscoveredDevice] = field(default_factory=list)
    error: Optional[str] = None
    warning: Optional[str] = None
    method_used: Optional[str] = None
    scope: Optional[str] = None


# Camera-related service ports (indicators only, not confirmation)
CAMERA_PORT_INDICATORS = {
    554: "RTSP (potential streaming)",
    8080: "HTTP alternate (potential camera web UI)",
    8554: "RTSP alternate",
    37777: "Dahua DVR",
    34567: "generic DVR",
    9000: "Hikvision ISAPI",
    80: "HTTP (possible camera UI)",
    443: "HTTPS (possible camera UI)",
}


def _is_private_network(network_str: str) -> bool:
    """Validate that the network is within RFC-1918 private ranges."""
    try:
        net = ipaddress.IPv4Network(network_str, strict=False)
    except ValueError:
        return False
    return any(net.subnet_of(priv) for priv in PRIVATE_NETWORKS)


def _ping_host(ip: str, timeout: int = 1) -> bool:
    """Ping a single host; return True if reachable."""
    try:
        if OS == "Windows":
            args = ["ping", "-n", "1", "-w", str(timeout * 1000), ip]
        else:
            args = ["ping", "-c", "1", "-W", str(timeout), ip]
        result = subprocess.run(args, capture_output=True, timeout=timeout + 2)
        return result.returncode == 0
    except Exception:
        return False


def _get_mac_from_arp(ip: str) -> Optional[str]:
    """Try to retrieve MAC address from the ARP cache after pinging."""
    try:
        if OS == "Windows":
            result = subprocess.run(["arp", "-a", ip], capture_output=True, text=True, timeout=5)
            m = re.search(r'([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}', result.stdout)
        else:
            result = subprocess.run(["arp", "-n", ip], capture_output=True, text=True, timeout=5)
            m = re.search(r'([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}', result.stdout)
        return m.group(0).upper() if m else None
    except Exception:
        return None


def _resolve_hostname(ip: str) -> Optional[str]:
    """Attempt reverse DNS resolution."""
    import socket
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def _check_common_ports(ip: str) -> tuple[List[int], dict]:
    """
    Quick port check on common ports.
    Returns (open_ports, services_dict).
    Uses subprocess nmap if available, otherwise socket-based check.
    """
    ports_to_check = [80, 443, 22, 21, 23, 554, 8080, 8554, 37777, 34567, 9000]
    open_ports = []
    services = {}

    # Try nmap first
    nmap_path = _find_nmap()
    if nmap_path:
        ports_str = ",".join(str(p) for p in ports_to_check)
        try:
            result = subprocess.run(
                [nmap_path, "-T3", "--open", "-p", ports_str, "--host-timeout", "10s", ip],
                capture_output=True,
                text=True,
                timeout=20,
            )
            for line in result.stdout.splitlines():
                m = re.match(r'(\d+)/tcp\s+open\s+(\S+)', line)
                if m:
                    port = int(m.group(1))
                    svc = m.group(2)
                    open_ports.append(port)
                    services[str(port)] = svc
            return open_ports, services
        except Exception as e:
            logger.warning("nmap port scan failed for %s: %s", ip, str(e))

    # Fallback: socket connect
    import socket
    for port in ports_to_check:
        try:
            with socket.create_connection((ip, port), timeout=1):
                open_ports.append(port)
                services[str(port)] = "open"
        except Exception:
            pass
        time.sleep(settings.device_scan_rate_limit)

    return open_ports, services


def _find_nmap() -> Optional[str]:
    """Find nmap binary in PATH or standard installation directories (including Zenmap)."""
    from app.services.hardware_service import find_nmap
    return find_nmap()


def _identify_camera_indicators(open_ports: List[int], services: dict) -> tuple[bool, List[str]]:
    """Check whether open ports suggest a camera. Returns (is_potential, evidence_list)."""
    evidence = []
    for port in open_ports:
        if port in CAMERA_PORT_INDICATORS:
            evidence.append(f"Port {port} open — {CAMERA_PORT_INDICATORS[port]}")
    # Strong indicator: RTSP port
    is_potential = any(p in open_ports for p in [554, 8554, 37777, 34567, 9000])
    return is_potential, evidence


def scan_devices(
    network_range: str,
    authorized: bool,
    max_hosts: int = 254,
) -> DeviceScanResult:
    """
    Discover reachable devices on an authorised private network.
    Raises ScopeViolationError for non-private ranges.
    Never scans without explicit authorization=True.
    """
    if not authorized:
        raise ScopeViolationError("Device discovery requires explicit authorization.")

    if not _is_private_network(network_range):
        raise ScopeViolationError(
            f"'{network_range}' is not a private RFC-1918 network. "
            "Only authorised private networks may be scanned."
        )

    logger.info("Starting device scan on %s", network_range)

    try:
        net = ipaddress.IPv4Network(network_range, strict=False)
    except ValueError as e:
        return DeviceScanResult(success=False, error=f"Invalid network range: {e}")

    num_hosts = max(0, net.num_addresses - 2) if net.prefixlen < 31 else net.num_addresses
    if num_hosts > max_hosts:
        return DeviceScanResult(
            success=False,
            error=f"Network range contains {num_hosts} hosts (max {max_hosts}). Use a smaller /CIDR.",
        )

    hosts = list(net.hosts())

    devices: List[DiscoveredDevice] = []
    for host in hosts:
        ip = str(host)
        if _ping_host(ip):
            logger.info("Host reachable: %s", ip)
            mac = _get_mac_from_arp(ip)
            hostname = _resolve_hostname(ip)
            open_ports, services = _check_common_ports(ip)
            is_camera, camera_evidence = _identify_camera_indicators(open_ports, services)
            devices.append(DiscoveredDevice(
                ip_address=ip,
                mac_address=mac,
                hostname=hostname,
                vendor=None,   # OUI lookup not included (no external call)
                open_ports=open_ports,
                services=services,
                is_potential_camera=is_camera,
                camera_evidence=camera_evidence,
            ))

    return DeviceScanResult(
        success=True,
        devices=devices,
        scope=network_range,
        method_used="ping sweep + " + ("nmap" if _find_nmap() else "socket"),
        warning=None if devices else "No reachable hosts found in range.",
    )

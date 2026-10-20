"""
GHOSTSENTINEL Ω — Hardware Diagnostics Service

Reports OS, Python version, wireless adapter presence, nmap availability,
and capability notes. Never fabricates capability claims.
"""
from __future__ import annotations

import platform
import shutil
import subprocess
import sys
from typing import List, Optional

from app.schemas.schemas import HardwareInfo
from app.scanners.wifi_scanner import get_wireless_interfaces
from app.core.logging_config import get_logger

logger = get_logger(__name__)


def find_nmap() -> Optional[str]:
    """
    Locate nmap executable either in PATH or in standard Windows installation paths,
    including Zenmap's bundled installation directory.
    """
    found = shutil.which("nmap")
    if found:
        return found
    
    import os
    candidates = [
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
        r"C:\Program Files (x86)\Zenmap\nmap.exe",
        r"C:\Program Files\Zenmap\nmap.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Programs\Nmap\nmap.exe"),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


def get_hardware_info() -> HardwareInfo:
    os_name = platform.system()
    os_version = platform.version()
    python_version = sys.version

    wireless_interfaces = []
    notes: List[str] = []

    try:
        wireless_interfaces = get_wireless_interfaces()
    except Exception as e:
        notes.append(f"Could not enumerate wireless interfaces: {e}")

    if not wireless_interfaces:
        notes.append(
            "No wireless interfaces detected. "
            "Wi-Fi scanning is NOT SUPPORTED without an active adapter."
        )

    # nmap check (supports system PATH, Nmap installation, and Zenmap bundle)
    nmap_path = find_nmap()
    nmap_available = nmap_path is not None
    nmap_version: Optional[str] = None
    if nmap_available:
        try:
            result = subprocess.run(
                [nmap_path, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            first_line = result.stdout.strip().splitlines()[0] if result.stdout else ""
            nmap_version = first_line
        except Exception as e:
            notes.append(f"nmap found but version check failed: {e}")
    else:
        notes.append(
            "nmap is NOT available. Device port scanning will use socket-based fallback. "
            "Install nmap or Zenmap for more accurate service detection."
        )

    # Monitor mode check
    monitor_mode_capable: List[str] = []
    if os_name == "Linux":
        for iface in wireless_interfaces:
            try:
                result = subprocess.run(
                    ["iw", iface, "info"],
                    capture_output=True, text=True, timeout=5,
                )
                if "monitor" in result.stdout.lower():
                    monitor_mode_capable.append(iface)
            except Exception:
                pass
        if not monitor_mode_capable and wireless_interfaces:
            notes.append(
                "No interfaces with confirmed monitor mode detected. "
                "Passive packet capture is NOT SUPPORTED without monitor mode."
            )
    elif os_name == "Windows":
        import os
        # Check if Npcap driver or WlanHelper exists
        npcap_paths = [
            r"C:\Windows\System32\Npcap\WlanHelper.exe",
            r"C:\Windows\System32\DRIVERS\npcap.sys",
        ]
        has_npcap = any(os.path.exists(p) for p in npcap_paths)
        if has_npcap and wireless_interfaces:
            monitor_mode_capable = [f"{iface} (Npcap Driver)" for iface in wireless_interfaces]
            notes.append(
                f"Npcap packet capture driver active. Monitor mode supported on: {', '.join(wireless_interfaces)}."
            )
        else:
            notes.append(
                "Passive Wi-Fi capture requires specialised drivers (e.g. Npcap in monitor mode)."
            )

    local_ip: Optional[str] = None
    default_subnet: Optional[str] = None
    try:
        import socket
        import ipaddress
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            active_ip = s.getsockname()[0]
            ip_obj = ipaddress.ip_address(active_ip)
            if ip_obj.is_private:
                local_ip = str(ip_obj)
                default_subnet = str(ipaddress.ip_network(f"{active_ip}/24", strict=False))
    except Exception:
        pass

    return HardwareInfo(
        os_name=os_name,
        os_version=os_version,
        python_version=python_version,
        wireless_interfaces=wireless_interfaces,
        nmap_available=nmap_available,
        nmap_version=nmap_version,
        monitor_mode_capable=monitor_mode_capable,
        local_ip=local_ip,
        default_subnet=default_subnet,
        notes=notes,
    )

"""
GHOSTSENTINEL Ω — Wi-Fi Scanner (Module A)

Discovers visible wireless networks using OS-native commands.
Supports: Windows (netsh), Linux (iwlist/nmcli), macOS (airport).
Handles missing adapters, permissions errors, and unsupported hardware
without fabricating results.
"""
from __future__ import annotations

import json
import platform
import re
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import List, Optional

from app.core.logging_config import get_logger

logger = get_logger(__name__)

OS = platform.system()


@dataclass
class WifiNetwork:
    ssid: Optional[str] = None
    bssid: Optional[str] = None
    channel: Optional[int] = None
    frequency_mhz: Optional[float] = None
    signal_dbm: Optional[int] = None
    security: Optional[str] = None
    encryption: Optional[str] = None
    authentication: Optional[str] = None
    wps_detected: str = "unknown"
    observed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    raw_data: Optional[str] = None


@dataclass
class ScanResult:
    success: bool
    networks: List[WifiNetwork] = field(default_factory=list)
    error: Optional[str] = None
    warning: Optional[str] = None
    method_used: Optional[str] = None
    hardware_notes: List[str] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# Windows — netsh wlan show networks with active Native Wi-Fi hardware sweep
# ─────────────────────────────────────────────────────────────────────────────

def _trigger_windows_wlan_scan(dwell_seconds: float = 3.0) -> int:
    """
    Trigger active 802.11 RF channel probe sweeps across all physical Wi-Fi adapters
    using Windows Native Wi-Fi API (wlanapi.dll).

    By default, Windows WLAN AutoConfig (wlansvc) does not send active background probe
    requests once associated to an AP. Invoking WlanScan() forces all physical adapters
    (e.g., USB high-gain antenna and internal Wi-Fi 6E cards) to hop channels across 2.4 GHz,
    5 GHz, and 6 GHz and collect probe responses/beacons from all nearby routers (~100m).
    """
    try:
        import ctypes
        from ctypes import wintypes
        import time

        wlan = ctypes.windll.wlanapi
        handle = wintypes.HANDLE()
        neg_version = wintypes.DWORD()
        res = wlan.WlanOpenHandle(2, None, ctypes.byref(neg_version), ctypes.byref(handle))
        if res != 0:
            logger.debug("WlanOpenHandle failed with code %d", res)
            return 0

        class _GUID(ctypes.Structure):
            _fields_ = [
                ("Data1", wintypes.DWORD),
                ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD),
                ("Data4", ctypes.c_byte * 8),
            ]

        class _WLAN_INTERFACE_INFO(ctypes.Structure):
            _fields_ = [
                ("InterfaceGuid", _GUID),
                ("strInterfaceDescription", wintypes.WCHAR * 256),
                ("isState", wintypes.DWORD),
            ]

        class _WLAN_INTERFACE_INFO_LIST(ctypes.Structure):
            _fields_ = [
                ("dwNumberOfItems", wintypes.DWORD),
                ("dwIndex", wintypes.DWORD),
                ("InterfaceInfo", _WLAN_INTERFACE_INFO * 1),
            ]

        if_list_ptr = ctypes.c_void_p()
        res = wlan.WlanEnumInterfaces(handle, None, ctypes.byref(if_list_ptr))
        scans_triggered = 0

        if res == 0 and if_list_ptr.value:
            base = ctypes.cast(if_list_ptr, ctypes.POINTER(_WLAN_INTERFACE_INFO_LIST))
            count = base.contents.dwNumberOfItems
            if count > 0:
                class _WLAN_INTERFACE_INFO_LIST_DYN(ctypes.Structure):
                    _fields_ = [
                        ("dwNumberOfItems", wintypes.DWORD),
                        ("dwIndex", wintypes.DWORD),
                        ("InterfaceInfo", _WLAN_INTERFACE_INFO * count),
                    ]
                dyn_list = ctypes.cast(if_list_ptr, ctypes.POINTER(_WLAN_INTERFACE_INFO_LIST_DYN)).contents
                for i in range(count):
                    iface = dyn_list.InterfaceInfo[i]
                    scan_rc = wlan.WlanScan(handle, ctypes.byref(iface.InterfaceGuid), None, None, None)
                    if scan_rc == 0:
                        scans_triggered += 1
                        logger.debug("Active hardware scan triggered on interface: %s", iface.strInterfaceDescription)
                    else:
                        logger.debug("WlanScan returned %d on %s", scan_rc, iface.strInterfaceDescription)

            wlan.WlanFreeMemory(if_list_ptr)

        wlan.WlanCloseHandle(handle, None)

        if scans_triggered > 0:
            logger.info("Active RF scan triggered on %d interface(s). Dwelling %gs for probe responses...", scans_triggered, dwell_seconds)
            time.sleep(dwell_seconds)

        return scans_triggered
    except Exception as exc:
        logger.warning("Active hardware scan trigger skipped (fallback to passive netsh cache): %s", exc)
        return 0


def _scan_windows() -> ScanResult:
    # Trigger active RF probe scan via Native Wi-Fi API so all nearby routers respond
    _trigger_windows_wlan_scan(dwell_seconds=3.0)

    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except FileNotFoundError:
        return ScanResult(
            success=False,
            error="netsh not found. This platform does not support Windows Wi-Fi scanning.",
        )
    except subprocess.TimeoutExpired:
        return ScanResult(success=False, error="netsh timed out after 30 seconds.")

    if result.returncode != 0:
        stderr = result.stderr.strip()
        if "not running" in stderr.lower() or "no wireless" in stderr.lower():
            return ScanResult(
                success=False,
                error="No wireless adapter found or WLAN service is not running.",
                hardware_notes=["Install or enable a Wi-Fi adapter.", "Start the WLAN AutoConfig service."],
            )
        return ScanResult(
            success=False,
            error=f"netsh exited with code {result.returncode}: {stderr[:200]}",
        )

    networks = _parse_netsh_output(result.stdout)
    if not networks and result.stdout:
        return ScanResult(
            success=True,
            networks=[],
            warning="Adapter found but no networks were visible. Try moving closer to an AP.",
            method_used="netsh wlan show networks",
        )
    return ScanResult(
        success=True,
        networks=networks,
        method_used="netsh wlan show networks",
    )


def _parse_netsh_output(output: str) -> List[WifiNetwork]:
    """
    Parse Windows netsh wlan show networks mode=bssid output.
    Captures every distinct BSSID (access point / router radio),
    handles hidden SSIDs, multiple interfaces, and dual-band routers.
    """
    networks: List[WifiNetwork] = []
    current_iface = None
    current_ssid = None
    current_auth = "Unknown"
    current_enc = "Unknown"
    current_bssid = None
    
    # Track unique BSSIDs to avoid exact duplicate rows across multiple adapters
    seen_bssids: dict = {}  # bssid -> index in networks

    lines = output.splitlines()
    for line in lines:
        line_clean = line.strip()
        if not line_clean:
            continue

        if line_clean.lower().startswith("interface name"):
            parts = line_clean.split(":", 1)
            current_iface = parts[1].strip() if len(parts) > 1 else None
            continue

        m_ssid = re.match(r'^SSID\s+\d+\s*:\s*(.*)$', line_clean)
        if m_ssid:
            raw_ssid = m_ssid.group(1).strip()
            current_ssid = raw_ssid if raw_ssid else None  # None = hidden SSID
            current_auth = "Unknown"
            current_enc = "Unknown"
            current_bssid = None
            continue

        if ":" in line_clean:
            k, _, v = line_clean.partition(":")
            k = k.strip().lower()
            v = v.strip()

            if k == "authentication":
                current_auth = v
            elif k == "encryption":
                current_enc = v
            elif k.startswith("bssid"):
                current_bssid = v

                # Determine security classification
                if "WPA3" in current_auth:
                    security = "WPA3"
                elif "WPA2" in current_auth:
                    security = "WPA2"
                elif "WPA" in current_auth:
                    security = "WPA"
                elif current_auth.lower() == "open":
                    security = "Open"
                else:
                    security = current_auth if current_auth else "Unknown"

                # Check if this BSSID was already seen (e.g. heard by second adapter)
                if current_bssid in seen_bssids:
                    # Point to existing entry to update with higher signal if available
                    pass
                else:
                    net_obj = WifiNetwork(
                        ssid=current_ssid,
                        bssid=current_bssid,
                        channel=None,
                        frequency_mhz=None,
                        signal_dbm=None,
                        security=security,
                        encryption=current_enc,
                        authentication=current_auth,
                        wps_detected="unknown",
                        raw_data=json.dumps({"interface": current_iface, "auth": current_auth, "enc": current_enc}),
                    )
                    seen_bssids[current_bssid] = len(networks)
                    networks.append(net_obj)

            elif k == "signal" and current_bssid and current_bssid in seen_bssids:
                try:
                    pct = int(v.replace("%", "").strip())
                    sig = int(pct / 2 - 100)
                    target = networks[seen_bssids[current_bssid]]
                    if target.signal_dbm is None or sig > target.signal_dbm:
                        target.signal_dbm = sig
                except ValueError:
                    pass

            elif k == "channel" and current_bssid and current_bssid in seen_bssids:
                try:
                    ch = int(v)
                    target = networks[seen_bssids[current_bssid]]
                    target.channel = ch
                    target.frequency_mhz = _channel_to_mhz(ch)
                except ValueError:
                    pass

    return networks


# ─────────────────────────────────────────────────────────────────────────────
# Linux — nmcli / iwlist
# ─────────────────────────────────────────────────────────────────────────────

def _scan_linux() -> ScanResult:
    # Try nmcli first
    try:
        result = subprocess.run(
            ["nmcli", "-t", "-f",
             "SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY,ACTIVE",
             "device", "wifi", "list", "--rescan", "yes"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            networks = _parse_nmcli(result.stdout)
            return ScanResult(
                success=True,
                networks=networks,
                method_used="nmcli",
                warning=None if networks else "nmcli returned no networks.",
            )
        else:
            logger.warning("nmcli failed: %s", result.stderr[:200])
    except FileNotFoundError:
        logger.info("nmcli not found, trying iwlist.")
    except subprocess.TimeoutExpired:
        return ScanResult(success=False, error="nmcli timed out.")

    # Fallback: iwlist
    interfaces = _get_linux_wireless_interfaces()
    if not interfaces:
        return ScanResult(
            success=False,
            error="No wireless interfaces detected.",
            hardware_notes=["Ensure a Wi-Fi adapter is connected and driver is loaded."],
        )

    iface = interfaces[0]
    try:
        result = subprocess.run(
            ["sudo", "iwlist", iface, "scan"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except FileNotFoundError:
        return ScanResult(
            success=False,
            error="iwlist not found. Install wireless-tools: sudo apt install wireless-tools",
        )
    except subprocess.TimeoutExpired:
        return ScanResult(success=False, error="iwlist timed out.")

    if result.returncode != 0:
        return ScanResult(
            success=False,
            error=f"iwlist scan failed: {result.stderr[:200]}",
            hardware_notes=["Try running with sudo.", "Ensure interface is up: sudo ip link set {iface} up"],
        )

    networks = _parse_iwlist(result.stdout)
    return ScanResult(
        success=True,
        networks=networks,
        method_used=f"iwlist {iface} scan",
    )


def _parse_nmcli(output: str) -> List[WifiNetwork]:
    """Parse nmcli -t tabular output."""
    networks = []
    for line in output.strip().splitlines():
        parts = line.split(":")
        if len(parts) < 6:
            continue
        ssid = parts[0] or None
        bssid = parts[1].replace("\\:", ":") if parts[1] else None
        try:
            channel = int(parts[2]) if parts[2] else None
        except ValueError:
            channel = None
        freq_str = parts[3]
        try:
            freq = float(freq_str.split()[0]) * 1000 if "GHz" in freq_str else float(freq_str.split()[0])
        except (ValueError, IndexError):
            freq = None
        try:
            signal = int(parts[4]) - 110 if parts[4] else None  # nmcli uses 0-100, convert to dBm approx
        except ValueError:
            signal = None
        security = parts[5] if len(parts) > 5 else "Unknown"
        networks.append(WifiNetwork(
            ssid=ssid,
            bssid=bssid,
            channel=channel,
            frequency_mhz=freq,
            signal_dbm=signal,
            security=security or "Open",
            encryption=None,
            authentication=None,
            wps_detected="unknown",
            raw_data=line,
        ))
    return networks


def _parse_iwlist(output: str) -> List[WifiNetwork]:
    """Parse iwlist scan output."""
    networks = []
    cells = re.split(r'Cell \d+ - ', output)
    for cell in cells[1:]:
        net: dict = {}
        m = re.search(r'ESSID:"([^"]*)"', cell)
        net["ssid"] = m.group(1) if m else None
        m = re.search(r'Address: ([0-9A-Fa-f:]{17})', cell)
        net["bssid"] = m.group(1) if m else None
        m = re.search(r'Channel:(\d+)', cell)
        net["channel"] = int(m.group(1)) if m else None
        m = re.search(r'Frequency:([\d.]+) GHz', cell)
        net["frequency_mhz"] = float(m.group(1)) * 1000 if m else _channel_to_mhz(net.get("channel"))
        m = re.search(r'Signal level=(-?\d+)', cell)
        net["signal_dbm"] = int(m.group(1)) if m else None
        m = re.search(r'Encryption key:(on|off)', cell)
        enc_on = m.group(1) == "on" if m else False
        m = re.search(r'IE: (?:WPA |IEEE 802.11i/)([^\n]+)', cell)
        if m:
            ie = m.group(1)
            if "WPA2" in cell or "802.11i" in cell:
                security = "WPA2"
            else:
                security = "WPA"
        else:
            security = "Open" if not enc_on else "WEP"
        networks.append(WifiNetwork(
            ssid=net.get("ssid"),
            bssid=net.get("bssid"),
            channel=net.get("channel"),
            frequency_mhz=net.get("frequency_mhz"),
            signal_dbm=net.get("signal_dbm"),
            security=security,
            encryption=None,
            authentication=None,
            wps_detected="unknown",
            raw_data=cell[:500],
        ))
    return networks


def _get_linux_wireless_interfaces() -> List[str]:
    try:
        import os
        wireless_path = "/proc/net/wireless"
        if os.path.exists(wireless_path):
            with open(wireless_path) as f:
                content = f.read()
            ifaces = re.findall(r'^(\w+):', content, re.MULTILINE)
            return ifaces
    except Exception:
        pass
    try:
        result = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=5)
        return re.findall(r'Interface (\S+)', result.stdout)
    except Exception:
        pass
    return []


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _channel_to_mhz(channel: Optional[int]) -> Optional[float]:
    if channel is None:
        return None
    if 1 <= channel <= 14:
        return 2407.0 + channel * 5
    if 36 <= channel <= 165:
        return 5000.0 + channel * 5
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def scan_wifi() -> ScanResult:
    """
    Dispatch to the appropriate scanner for the current OS.
    Returns a ScanResult — never raises, never fabricates networks.
    """
    logger.info("Starting Wi-Fi scan on %s", OS)
    if OS == "Windows":
        return _scan_windows()
    elif OS == "Linux":
        return _scan_linux()
    elif OS == "Darwin":
        return ScanResult(
            success=False,
            error="macOS scanning is not yet implemented.",
            hardware_notes=["Use airport command manually or contribute a macOS scanner."],
        )
    else:
        return ScanResult(
            success=False,
            error=f"Operating system '{OS}' is not supported for Wi-Fi scanning.",
        )


def get_wireless_interfaces() -> List[str]:
    """Return available wireless interface names for the current OS."""
    if OS == "Windows":
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"],
                capture_output=True, text=True, timeout=10,
            )
            return re.findall(r'Name\s+:\s+(.+)', result.stdout)
        except Exception:
            return []
    elif OS == "Linux":
        return _get_linux_wireless_interfaces()
    return []

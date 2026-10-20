# GHOSTSENTINEL Ω — Troubleshooting Guide

This guide addresses common setup, hardware, operating system, and permission issues on Kali Linux and Windows.

---

## 1. Kali Linux Wi-Fi Adapter Issues

### Issue 1: "No wireless interfaces detected"
**Symptoms**: Dashboard shows `⚠ No Wi-Fi adapter` in sidebar, or `/api/wifi/scan` returns an error.

**Causes & Solutions**:
1. **Running inside a Virtual Machine without USB Passthrough**:
   - VM NAT or Bridged Ethernet adapters appear as wired Ethernet (`eth0`), not Wi-Fi.
   - *Fix*: Connect an external USB Wi-Fi adapter (e.g. Alfa AWUS036NHA). In VirtualBox/VMware, navigate to `Devices` -> `USB` -> check your Wi-Fi adapter to pass it directly to Kali.
2. **Adapter Soft/Hard Blocked**:
   - Check with: `sudo rfkill list all`
   - If blocked, unblock:
     ```bash
     sudo rfkill unblock wifi
     sudo rfkill unblock all
     ```
3. **Interface is Down**:
   - Bring the interface up:
     ```bash
     sudo ip link set wlan0 up
     ```
4. **Missing Driver Firmware**:
   - Identify your chipset: `lsusb` or `lspci -nnk | grep -iA3 net`
   - Install Kali wireless firmware meta-package:
     ```bash
     sudo apt update && sudo apt install -y firmware-linux firmware-atheros firmware-realtek
     ```

---

### Issue 2: "nmcli failed: scanning not allowed while interface is busy"
**Symptoms**: Wi-Fi scan fails or hangs.

**Causes & Solutions**:
- `NetworkManager` and `wpa_supplicant` may be in an active connection attempt or scan conflict.
- *Fix*: Check status:
  ```bash
  sudo systemctl restart NetworkManager
  ```
- Alternatively, test manual scan:
  ```bash
  sudo iwlist wlan0 scan
  ```

---

### Issue 3: Device Scanning (Module D) Finds 0 Hosts
**Symptoms**: Device scan completes, but results list is empty.

**Causes & Solutions**:
1. **Wrong Subnet Specified**:
   - Verify your actual local IP and subnet:
     ```bash
     ip -4 addr show
     ```
   - If your IP is `192.168.1.45/24`, scan `192.168.1.0/24`.
2. **Host Isolation on Wi-Fi AP**:
   - Many guest Wi-Fi networks enable "Client Isolation" or "AP Isolation". Devices on the same Wi-Fi cannot ping or reach each other.
   - Test by pinging your default router gateway (e.g. `ping 192.168.1.1`).
3. **Target Firewall Blocking ICMP Ping**:
   - Windows 10/11 default firewalls drop ICMP echo requests (ping).
   - If `nmap` is installed, GHOSTSENTINEL Ω checks common TCP ports (80, 443, 22) to discover hosts even when ICMP is blocked. Ensure `nmap` is installed:
     ```bash
     sudo apt install -y nmap
     ```

---

## 2. Permission and Port Issues

### Issue 4: "Permission denied" during socket or adapter queries
**Symptoms**: Scan fails with error code 1 or raw socket error.

**Solutions**:
- Option A: Run the server with permissions:
  ```bash
  sudo $(which python3) run.py
  ```
- Option B (Recommended - Least Privilege): Grant Python network raw capabilities without running full root:
  ```bash
  sudo setcap cap_net_raw,cap_net_admin+ep $(which python3)
  ```

### Issue 5: "Address already in use" on Port 8000
**Symptoms**: `Uvicorn failed to bind to 127.0.0.1:8000`.

**Solutions**:
- Another process is using port 8000. Find and terminate it:
  ```bash
  # Linux
  sudo lsof -i :8000
  sudo kill -9 <PID>

  # Or change port in .env:
  PORT=8080
  ```

---

## 3. Windows Specific Issues

### Issue 6: "WLAN AutoConfig service is not running"
**Symptoms**: Windows returns `netsh` error code 1.

**Solutions**:
- Open PowerShell as Administrator and run:
  ```powershell
  Get-Service WlanSvc | Start-Service
  ```

### Issue 7: PowerShell Script Execution Policy
**Symptoms**: Virtualenv activation fails: `Execution of scripts is disabled on this system`.

**Solutions**:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\venv\Scripts\Activate.ps1
```

### Issue 8: Wi-Fi Scan Only Displays 1 Connected Network
**Symptoms**: On Windows, running a scan initially displays only the currently associated SSID and misses other nearby routers.

**Causes & Solutions**:
- Windows OS suppresses periodic background Wi-Fi beacon scanning while actively connected to an Access Point to conserve battery and latency.
- *Fix*: GHOSTSENTINEL Ω automatically issues active `WlanScan` calls via `wlanapi.dll` with a 3-second channel hop dwell. If scanning still returns limited results, disconnect from your current Wi-Fi or trigger a rescan directly from the "Wi-Fi Discovery" workbench tab (`+ Start Spectrum Scan`).

### Issue 9: "Nmap Not Found" on Windows Diagnostics
**Symptoms**: Hardware Diagnostics reports `Nmap: Not installed (using socket fallback)`.

**Causes & Solutions**:
1. Zenmap or Nmap is installed in a non-standard directory or missing from system `PATH`.
2. GHOSTSENTINEL Ω checks:
   - `C:\Program Files (x86)\Nmap\nmap.exe` (Default for Zenmap installer)
   - `C:\Program Files\Nmap\nmap.exe`
   - System `PATH`
3. If installed in a custom location, add the folder containing `nmap.exe` to your Windows System `PATH` environment variable and restart `python run.py`.

### Issue 10: Enabling Monitor Mode with Npcap
**Symptoms**: "Monitor Mode Supported: False" or packet capture unavailable on Windows.

**Causes & Solutions**:
1. Download and install [Npcap](https://npcap.com/) (Free for personal/educational use).
2. During installation, ensure the checkbox **"Support raw 802.11 traffic (and monitor mode) for wireless adapters"** is checked.
3. Test with Npcap's command-line utility:
   ```cmd
   "C:\Windows\System32\Npcap\WlanHelper.exe" "Wi-Fi 3" mode
   ```
4. GHOSTSENTINEL Ω will recognize `(Npcap Driver)` on your interfaces automatically.

---

## 4. Report Generation Issues

### Issue 11: PDF Report Generation Fails
**Symptoms**: "reportlab is not installed" or formatting exception.

**Solutions**:
- Install or reinstall reportlab:
  ```bash
  pip install reportlab>=5.0.1
  ```
- Verify reportlab functions:
  ```bash
  python -c "import reportlab; print('ReportLab version:', reportlab.__version__)"
  ```

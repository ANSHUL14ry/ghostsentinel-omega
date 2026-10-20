# GHOSTSENTINEL Ω (Omega)
### Production-Quality Wi-Fi Security & Privacy Auditing Platform

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111.0-009688.svg)](https://fastapi.tiangolo.com/)
[![SQLite](https://img.shields.io/badge/SQLite-WAL--Mode-003B57.svg)](https://sqlite.org/)
[![Tests](https://img.shields.io/badge/Tests-72%20Passed-brightgreen.svg)]()
[![Target OS](https://img.shields.io/badge/Target%20OS-Kali%20Linux%20%7C%20Windows%2011-555555.svg)]()

---

## 1. Project Overview

**GHOSTSENTINEL Ω** is an evidence-based, modular Wi-Fi security auditing, rogue access-point defense, and privacy inspection platform engineered for cybersecurity students, security researchers, and network defense professionals.

Unlike superficial scanning scripts or mock UI dashboards, **GHOSTSENTINEL Ω strictly adheres to factual verification**:
- **Zero Fabricated Findings**: If an adapter cannot capture WPS elements, it reports `NOT TESTED / UNKNOWN` rather than fabricating vulnerability scores.
- **Zero Plaintext Password Storage**: Audited lab credentials are processed in volatile memory via `zxcvbn` and wiped immediately.
- **Enforced Scope Boundaries**: Active host discovery strictly requires explicit authorization and private RFC-1918 addressing.
- **Native Wi-Fi Active RF Sweeps**: Uses Windows Native Wi-Fi API (`wlanapi.dll` `WlanScan`) and Linux `nmcli` to bypass passive OS cache limitations and discover all physical 2.4 GHz and 5 GHz APs in real time.
- **Rogue AP & Evil Twin Defense**: Automated hardware MAC/BSSID and security cipher baseline comparisons with one-click airwave selection.
- **Controlled Security Lab**: Safe, non-destructive router posture assessment with explicit permission verification and auto-populated network parameters.
- **Commercial Licensing Architecture**: Built-in tiered license verification endpoint (`/api/system/license`) for Community, Professional, and Enterprise editions.
- **Multi-Format Evidence Reports**: Export factual, timestamped audit findings in HTML, JSON, and PDF.

---

## 2. Architecture & Modules

```
ghostsentinel-omega/
├── app/
│   ├── api/             # REST endpoints (wifi, devices, password, findings, reports, system, baseline, lab)
│   ├── auditors/        # Wi-Fi auditor, password auditor, rogue AP detector, lab auditor
│   ├── core/            # Config, logging with redaction, exceptions, licensing framework
│   ├── database/        # SQLite + SQLAlchemy with WAL mode and StaticPool support
│   ├── models/          # ORM models: Scan, Network, Device, Finding, Report, TrustedBaseline
│   ├── reports/         # Report generator: HTML, JSON, and PDF (ReportLab)
│   ├── scanners/        # Wi-Fi scanner (wlanapi/nmcli/iwlist/netsh), Device scanner (RFC-1918 sweeps)
│   ├── schemas/         # Pydantic schemas with typed validation
│   ├── services/        # Hardware diagnostics (Nmap 7.99/Npcap/Zenmap detection), scan orchestration
│   ├── static/          # CSS stylesheet, Vanilla JS SPA client (No external CDN dependencies)
│   ├── templates/       # Main dashboard HTML single-page application
│   └── main.py          # FastAPI application entry point, security middleware, SPA fallback
├── docs/                # Comprehensive documentation
│   ├── HARDWARE_AND_LIMITATIONS.md
│   ├── SECURITY_AND_THREAT_MODEL.md
│   └── TROUBLESHOOTING.md
├── reports_output/      # Generated report files
├── scripts/             # Utility and sample report generators
├── tests/               # 72 automated tests covering core, scanners, auditors, APIs
├── .env.example         # Environment template with documented defaults
├── pytest.ini           # Pytest configuration
├── requirements.txt     # Pinned Python dependencies
└── run.py               # Application startup launcher
```

### Core Modules
- **Module A — Real Wi-Fi Discovery**: Live 802.11 spectrum scanning via Native Wi-Fi API (`ctypes.windll.wlanapi` active channel hopping) on Windows, and `nmcli` / `iwlist` on Linux. Factual SSID, BSSID, channel, signal (dBm), and security parsing.
- **Module B — Defensive Wi-Fi Security Auditor**: Automated rule-based inspection for Open networks, WEP obsolescence, WPA-TKIP deprecation, WPA2-PSK dictionary exposure risks, and WPA3 status.
- **Module C — Authorized Password Security Audit**: Local entropy and dictionary analysis using `zxcvbn`. Immediate memory disposal; never logged or saved to disk.
- **Module D — Authorized Device Discovery**: RFC-1918 subnet ping sweep, ARP MAC resolution, reverse DNS, and port auditing (Nmap 7.99 / Zenmap integration with socket fallback).
- **Module E — Camera & Privacy Inspection**: Heuristic identification of IP camera streaming indicators (RTSP port 554/8554, ONVIF, DVR ports) + local physical inspection logging.
- **Module F — Professional Dark Cybersecurity Dashboard**: 12-page responsive interface (Dark `#06080c`, Cyberpunk Red `#ff304f`, Electric Cyan `#8bdcff`) with real-time network dropdown auto-fill.
- **Module G — Downloadable Reports**: Sanitized HTML, machine-readable JSON, and professional PDF reports via ReportLab.
- **Module H — Rogue Access Point & Evil Twin Defense**: Trusted baseline comparisons, BSSID mismatches, security protocol downgrades, and RF channel anomalies without false positives on multi-AP mesh networks.
- **Module I — Controlled Wireless Security Lab**: Authorized deep-dive assessment on user-owned access points: 802.11w Protected Management Frames (PMF), cipher suite integrity, WPS exposure, and gateway administration portals (HTTP:80 / HTTPS:443).
- **Module J — Hardware & Licensing Engine**: Auto-detection of Npcap packet capture driver, WlanHelper monitor mode state, Nmap/Zenmap binary location, and license entitlement tiers.

---

## 3. Quickstart Guide (Windows 11 & Kali Linux)

### Option A: Windows 11 (PowerShell)

#### Step 1: System Prerequisites
- Python 3.10+ installed and on `PATH`
- (Optional for packet capture & monitor mode) [Npcap](https://npcap.com/) installed with "Support 802.11 traffic" enabled.
- (Optional for full network port auditing) [Nmap](https://nmap.org/download.html) or Zenmap installed.

#### Step 2: Setup Environment & Dependencies
```powershell
cd c:\Users\anshu\OneDrive\Desktop\ghostsentinel-omega

# Create and activate virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# Upgrade pip and install dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt
```

#### Step 3: Configure Environment
```powershell
Copy-Item .env.example .env
```

#### Step 4: Run Automated Tests
```powershell
python -m pytest tests/ -v
```
*(All 72 tests should pass)*

#### Step 5: Start the Server
```powershell
python run.py
```
Open `http://127.0.0.1:8000` in your web browser.

---

### Option B: Kali Linux (Bash)

#### Step 1: System Prerequisites
Update package lists and install standard wireless and scanning utilities:
```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv wireless-tools network-manager nmap
```

#### Step 2: Clone & Setup Virtual Environment
```bash
cd ghostsentinel-omega

# Create a clean virtual environment
python3 -m venv venv

# Activate the virtual environment
source venv/bin/activate

# Upgrade pip and install pinned dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

#### Step 3: Configure Environment
Copy the `.env.example` template:
```bash
cp .env.example .env

# Generate a secure 64-character secret key:
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))"
```
Edit `.env` to update `SECRET_KEY` if desired.

#### Step 4: Run Automated Tests
Verify all components on your system:
```bash
python -m pytest tests/ -v
```
*(All 72 tests should pass)*

#### Step 5: Start the Backend Server
```bash
python run.py
```
*Console output:*
```text
INFO:     Started server process
INFO:     Waiting for application startup.
[INFO] app.database - Database tables initialised at sqlite:////.../ghostsentinel.db
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
```

### Step 6: Open the Dashboard
Open Firefox or Chromium on your Kali machine and navigate to:
```
http://127.0.0.1:8000
```
Interactive Swagger API documentation is available at:
```
http://127.0.0.1:8000/api/docs
```

---

## 4. Stopping the Server
To stop the application at any time, press `CTRL + C` in the terminal where `python run.py` is running. SQLite WAL checkpoints will flush cleanly on shutdown.

---

## 5. Safely Accessing from Another Device on a Trusted Local Network

By default, GHOSTSENTINEL Ω binds **exclusively to `127.0.0.1`** (localhost only) to prevent unauthorized network access.

To allow access from another laptop or workstation on a trusted management network:

1. Open `.env` and configure:
   ```ini
   HOST=0.0.0.0
   PORT=8000
   ALLOW_LAN_ACCESS=true
   ```
2. Identify your Kali machine's local IP address:
   ```bash
   ip -4 addr show
   # Example: 192.168.1.150
   ```
3. Ensure your local firewall (`ufw` or `nftables`) only permits connections from your trusted device IP:
   ```bash
   sudo ufw allow from 192.168.1.50 to any port 8000 proto tcp
   ```
4. Start the server:
   ```bash
   python run.py
   ```
5. From the browser on your trusted machine, open: `http://192.168.1.150:8000`.

> [!WARNING]
> Never expose GHOSTSENTINEL Ω to untrusted or public networks without a reverse proxy (e.g. Nginx with TLS and HTTP Basic / OAuth authentication).

---

## 6. Diagnosing Wi-Fi Adapter Issues

If the dashboard displays `⚠ No Wi-Fi adapter detected`:

1. **Verify USB Passthrough (If running in a VM)**:
   - Ensure your USB Wi-Fi dongle (e.g., Alfa AWUS036NHA) is attached directly to the Kali VM via VirtualBox/VMware settings.
2. **Check Radio State**:
   ```bash
   sudo rfkill list all
   sudo rfkill unblock wifi
   ```
3. **Verify Interface Link**:
   ```bash
   ip link show
   sudo ip link set wlan0 up
   ```
4. **Test Native Scan**:
   ```bash
   nmcli device wifi list --rescan yes
   ```
For in-depth hardware notes, consult [`docs/HARDWARE_AND_LIMITATIONS.md`](file:///c:/Users/anshu/OneDrive/Desktop/ghostsentinel-omega/docs/HARDWARE_AND_LIMITATIONS.md).

---

## 7. Feature Verification Matrix

| Feature | Implemented | Tested | Hardware / Prerequisites | Known Limitations |
| :--- | :---: | :---: | :--- | :--- |
| **Wi-Fi Discovery** | **Yes** | **Yes** (Automated & Manual) | 802.11 wireless adapter | Dependent on OS adapter driver. |
| **Signal Parsing (dBm)** | **Yes** | **Yes** | Native OS reporting | Converted from percentage on Windows. |
| **Open / WEP / WPA Detection** | **Yes** | **Yes** | Standard scan beacon data | Factual observation from beacon IE. |
| **WPA2-PSK Risk Assessment** | **Yes** | **Yes** | Standard scan data | Marks as *potential* risk; does not crack. |
| **WPS Detection** | **Yes** | **Yes** | Monitor mode / Probe parsing | Marked *unknown* when monitor mode is absent. |
| **Password Strength Audit** | **Yes** | **Yes** | None (Local `zxcvbn`) | Offline evaluation; zero plaintext storage. |
| **Authorized Device Sweep** | **Yes** | **Yes** | Private IPv4 interface | Enforces RFC-1918; max 254 hosts per job. |
| **MAC Address Resolution** | **Yes** | **Yes** | Local Layer-2 network | ARP cache only; unavailable across routers. |
| **Camera Indicator Detection** | **Yes** | **Yes** | Local network access | Port indicators only (554, 8554); no offline camera detection. |
| **Physical Inspection Notes** | **Yes** | **Yes** | Browser localStorage | Stored locally in browser; never transmitted. |
| **HTML Report Export** | **Yes** | **Yes** | None | Sanitized HTML; dark cybersecurity styling. |
| **JSON Report Export** | **Yes** | **Yes** | None | Structured, machine-readable export. |
| **PDF Report Export** | **Yes** | **Yes** | `reportlab>=5.0.1` | Formatted evidence table and findings summary. |
| **Structured Log Redaction** | **Yes** | **Yes** | None | Passwords/keys redacted via regex. |
| **Background Job Cancellation**| **Yes** | **Yes** | None | Thread cancellation event propagation. |
| **Rogue AP & Evil Twin Detection** | **Yes** | **Yes** | Trusted Baseline Storage | BSSID mismatch, security downgrade, channel anomalies. Multi-AP mesh compliant. |
| **Controlled Wireless Security Lab** | **Yes** | **Yes** | Authorized target AP + Private IP | Non-destructive checks: 802.11w PMF, WPS exposure, router admin ports 80/443. |
| **Native Wi-Fi Active RF Sweep** | **Yes** | **Yes** | Windows WLAN API (`wlanapi.dll`) | Forces physical probe hopping, breaking OS cache suppression to find all nearby APs. |
| **Npcap Monitor Mode Detection** | **Yes** | **Yes** | Npcap Driver + `WlanHelper.exe` | Factual driver detection; recognizes supported capture interfaces on Windows. |
| **Nmap / Zenmap Resolution** | **Yes** | **Yes** | Nmap 7.99 in Program Files / PATH | Discovers binaries across standard Windows & Linux install directories. |
| **Commercial Licensing System** | **Yes** | **Yes** | `/api/system/license` | Enforces and displays Community, Professional, and Enterprise license entitlements. |

---

## 8. License & Ethical Disclaimer

This software is provided for educational and authorized defensive security auditing only. Unauthorised access, intercepting communications, or scanning networks without written authorization is illegal under computer misuse legislation. The authors accept no liability for damages resulting from misuse.

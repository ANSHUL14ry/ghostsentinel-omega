# GHOSTSENTINEL Ω — Hardware Compatibility & Technical Limitations

## 1. Overview

GHOSTSENTINEL Ω interacts with the physical wireless spectrum through operating system network stacks. It does not fabricate hardware capabilities. If an adapter, driver, or permission is missing, the system reports **NOT SUPPORTED**, **NOT TESTED**, or an actionable error.

---

## 2. Supported Wireless Adapters (Kali Linux)

For general discovery (Module A), any wireless adapter recognized by Linux (`cfg80211` / `mac80211` drivers) is supported via `nmcli` or `iwlist`.

For advanced wireless auditing (packet inspection, monitor mode, frame injection):

| Chipset | Typical USB Adapter | 2.4 GHz | 5 GHz | Monitor Mode | In-Tree Kernel Driver | Reliability Rating |
| :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| **Atheros AR9271** | Alfa AWUS036NHA | Yes | No | Yes | `ath9k_htc` (built-in) | Gold Standard (Lab Recommended) |
| **Ralink RT3070 / RT3572** | Alfa AWUS036NEH, Alfa AWUS051NH | Yes | RT3572 | Yes | `rt2800usb` (built-in) | Very Stable |
| **Realtek RTL8812AU** | Alfa AWUS036ACH, AWUS036AC | Yes | Yes (ac) | Yes | DKMS (`realtek-rtl88xxau-dkms`) | Requires DKMS driver |
| **Realtek RTL8814AU** | Alfa AWUS1900 | Yes | Yes (ac) | Yes | DKMS | High power; requires DKMS |
| **Realtek RTL8188FTV / RTL8188EU** | USB High-Gain Dongles | Yes | No | Yes (via Npcap) | Built-in / Vendor | Excellent 2.4 GHz range with external antenna |
| **Intel / MediaTek Wi-Fi 6E (RZ616/AX210)**| Internal PCIe/M.2 | Yes | Yes (6 GHz) | Yes (via Npcap) | In-tree / Windows OEM | High speed 802.11ax/6E discovery |
| **Intel Wireless (AX200/AC9560)** | Internal Laptop PCIe/M.2 | Yes | Yes (ac/ax) | Partial/Buggy | `iwlwifi` | Scanning only; injection unsupported |
| **Broadcom BCM43xx** | Internal Apple / Dell | Yes | Varies | Poor | `brcmfmac` / `b43` | Not recommended for packet analysis |

---

## 2.1. Windows 11 Hardware Architecture & Native Wi-Fi Engine

On Microsoft Windows 11, the operating system wireless stack behaves differently from Linux:
1. **The Passive Cache Problem**: Standard Windows commands (`netsh wlan show networks mode=bssid`) do not trigger active RF probes if the adapter is already associated with an Access Point or if background scanning is throttled by Windows Power Management. Consequently, vanilla `netsh` queries often report only 1 or 2 cached networks.
2. **The GHOSTSENTINEL Ω Native Wi-Fi Solution**: To solve this, GHOSTSENTINEL Ω interfaces directly with `wlanapi.dll` using Python's `ctypes`:
   - Calls `WlanOpenHandle` to establish an authenticated client session with the WLAN AutoConfig service (`WlanSvc`).
   - Enumerates all physical interface GUIDs (`WlanEnumInterfaces`).
   - Dispatches `WlanScan(..., pDot11Ssid=NULL, ...)` to command all physical radios to execute active 802.11 probe requests across all 2.4 GHz and 5 GHz channels.
   - Enforces an automated dwell delay (3.0 seconds) to allow beacon capture before retrieving the populated BSSID catalog.
3. **Npcap & Monitor Mode Support**:
   - Standard Windows NDIS drivers do not expose raw 802.11 frame capture.
   - When [Npcap](https://npcap.com/) is installed with raw 802.11 capture support, GHOSTSENTINEL Ω automatically detects `C:\Windows\System32\Npcap\WlanHelper.exe` and the `npcap.sys` driver service.
   - Adapters supporting Npcap capture (such as Realtek RTL8188FTV and MediaTek RZ616) are identified as `(Npcap Driver)` in hardware diagnostics.

---

## 3. Hardware Compatibility Checklist

Before conducting a defensive audit, run through this checklist on your Kali machine:

- [ ] **USB Controller Passthrough**: If running Kali Linux in a VM (VirtualBox, VMware, KVM), the USB Wi-Fi adapter must be passed through directly as a USB 3.0/2.0 device. Host-NAT virtual network adapters cannot scan physical 802.11 channels.
- [ ] **Driver Loaded**: Verify `lsusb` lists your adapter chipset and `ip link` shows a wireless interface (e.g., `wlan0`, `wlan1`, `wlp2s0`).
- [ ] **RF-Kill Status**: Ensure the radio is unblocked: `sudo rfkill list all` (should show `Soft blocked: no`, `Hard blocked: no`).
- [ ] **System Tools Installed**: Verify `nmcli` (`network-manager`), `iw` (`iw`), `iwlist` (`wireless-tools`), and `nmap`.
- [ ] **Sufficient Privileges**: Raw network sockets and hardware queries require `sudo` or assigned Linux capabilities (`cap_net_raw`, `cap_net_admin`).

---

## 4. Manual Hardware Validation Procedure

Follow these exact steps in Kali Linux to test your wireless adapter independently before running GHOSTSENTINEL Ω:

### Step 1: Verify Adapter Detection
```bash
lsusb
```
*Expected*: Look for lines referencing `Atheros`, `Ralink`, or `Realtek`.

### Step 2: Check Interface Creation
```bash
ip link show
```
*Expected*: You should see a wireless interface, e.g. `wlan0`. If in state `DOWN`, bring it up:
```bash
sudo ip link set wlan0 up
```

### Step 3: Check Regulatory Domain and Supported Channels
```bash
iw reg get
iw list | grep -E "Frequencies|Band|VHT|HE"
```

### Step 4: Test Real Scanning
```bash
# Using NetworkManager CLI (unprivileged / standard)
nmcli device wifi list --rescan yes

# Using wireless-tools (privileged fallback)
sudo iwlist wlan0 scan
```
If networks appear in the output, your adapter is functional and GHOSTSENTINEL Ω can discover them.

---

## 5. Technical Limitations & Non-Negotiable Boundaries

1. **No Monitor Mode Fabrication**:
   - Standard OS scan APIs (`netsh` on Windows, `nmcli` on Linux) discover networks using managed active/passive probe frames.
   - Deep beacon inspection (such as WPS Vendor Information Elements or PMKID capture) requires an adapter in monitor mode with raw packet capture. When monitor mode is absent, WPS status is explicitly marked **`unknown`** or **`NOT TESTED`**.
2. **Hidden SSIDs**:
   - Access points configured not to broadcast their SSID omit the name in beacon frames.
   - GHOSTSENTINEL Ω displays `(hidden SSID)` with the observable BSSID and frequency rather than pretending to uncloak the SSID without capturing client association frames.
3. **Layer-2 Boundary for Device Inventory**:
   - MAC address discovery relies on ARP cache resolution. ARP only operates within the local Layer-2 broadcast domain.
   - If scanning across a routed subnet or VPN, MAC addresses cannot be resolved via ARP. The tool displays `MAC: N/A` instead of inventing fake addresses.
4. **Camera & Privacy Inspection**:
   - Detection is strictly heuristic based on open ports (RTSP port 554/8554, HTTP video web panels, ONVIF ports).
   - **Offline, battery-powered, SD-card-only, or isolated wireless cameras CANNOT be detected** via IP network scanning.
   - An open RTSP port is a *potential indicator*, never definitive confirmation. Physical inspection remains mandatory.
5. **Password Auditing**:
   - GHOSTSENTINEL Ω performs local offline evaluation with `zxcvbn`.
   - It is not an attack tool; it does not crack external handshakes or perform brute-force against live access points.

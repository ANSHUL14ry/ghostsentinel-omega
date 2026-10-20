# GHOSTSENTINEL Ω — Security Architecture & Threat Model

## 1. System Threat Model

GHOSTSENTINEL Ω is designed for local defensive cybersecurity assessment. Because security tools frequently handle sensitive network telemetry and operate with elevated operating-system interfaces, the application is engineered with strict defensive boundaries.

### Trust Boundaries
```
+-----------------------------------------------------------+
| Untrusted Physical Environment (RF Wireless Spectrum)     |
+-----------------------------------------------------------+
                           |
                           v  (OS Wireless Subsystem / Driver)
+-----------------------------------------------------------+
| Operating System Kernel (Linux cfg80211 / Windows WLAN)   |
+-----------------------------------------------------------+
                           |
                           v  (Structured argument arrays, no shell=True)
+-----------------------------------------------------------+
| GHOSTSENTINEL Ω Python Backend (127.0.0.1:8000)           |
|  - Pydantic typed input validation                        |
|  - RFC-1918 private range enforcement                     |
|  - Redacting log formatter (passwords/tokens stripped)    |
|  - In-memory credential scrubbing (zxcvbn)                |
+-----------------------------------------------------------+
       ^                                             |
       | HTTP / REST (CORS restricted to localhost)  v
+----------------------------------+   +--------------------+
| Local Browser Dashboard          |   | SQLite (WAL Mode)  |
| (Firefox / Chromium on localhost)|   | Local storage only |
+----------------------------------+   +--------------------+
```

---

## 2. Mandatory Security Protections

### 2.1 Default Localhost Binding
- By default, the application binds exclusively to `127.0.0.1:8000`.
- The dashboard is never directly exposed to external network interfaces or the public internet.
- Setting `ALLOW_LAN_ACCESS=true` in `.env` is required to bind to `0.0.0.0` or a LAN IP, and warning messages are emitted to stdout and logs.

### 2.2 Scope Validation & Scope Violation Rejection
- All active host discovery operations (Module D) require:
  1. An explicit boolean `authorized: true` confirmation from the user.
  2. Strict RFC-1918 private network range validation (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
- Public IP ranges (e.g. `8.8.8.8`, `1.1.1.0/24`) and invalid formats are rejected by both Pydantic field validators (HTTP 422) and the underlying scan engine (`ScopeViolationError`, HTTP 403).
- Scans exceeding 254 hosts (e.g. `/16` or `/8` sweeps) are rejected before execution to prevent unintentional network disruption.

### 2.3 Command Injection Prevention
- Shell execution with `shell=True` is strictly prohibited.
- All OS invocations (`netsh`, `nmcli`, `iwlist`, `ping`, `arp`, `nmap`) utilize explicit argument arrays:
  ```python
  # SECURE (GHOSTSENTINEL Ω implementation)
  subprocess.run(["ping", "-c", "1", "-W", str(timeout), ip], capture_output=True)

  # INSECURE (Never used)
  os.system(f"ping -c 1 {ip}")
  ```
- All interface names and network ranges undergo regex filtering (`^[a-zA-Z0-9_\-\.]+$`) before being passed to system utilities.

### 2.4 Sensitive Data Protection & Redaction
- **No Plaintext Passwords in Logs**: The custom `RedactingFormatter` (`app/core/logging_config.py`) strips passwords, keys, tokens, and secrets from all log output matching sensitive patterns.
- **Immediate Credential Disposal**: In Module C (Password Audit), passwords assessed with `zxcvbn` are analyzed locally, overwritten in memory, and immediately garbage collected. The password is never stored in SQLite scan history or returned in API responses.
- **Sanitized Reports**: Report exports (HTML, JSON, PDF) use HTML entity escaping (`html.escape`) to prevent cross-site scripting (XSS) when displaying network SSIDs or hostnames observed over the air.

### 2.5 Path Traversal Protection
- Report download endpoints (`/api/reports/download/{id}`) look up reports by unique UUID primary keys in the database rather than user-supplied filesystem paths.
- Reports are stored in a dedicated, isolated `reports_output/` directory.

### 2.6 Least-Privilege Execution
- The application does not require running the entire web server as root.
- On Kali Linux, specific tools (`iwlist`, `nmap`) can be executed via granular `sudoers` rules or assigned POSIX capabilities:
  ```bash
  sudo setcap cap_net_raw,cap_net_admin+ep $(which python3)
  ```

---

## 3. Ethical and Legal Boundaries

1. **Authorization is Non-Negotiable**: Auditing or scanning networks without explicit, documented permission is illegal under computer misuse laws (e.g., US CFAA 18 U.S.C. § 1030, UK Computer Misuse Act 1990).
2. **Defensive Purpose**: GHOSTSENTINEL Ω is built for network administrators, penetration testers with signed rules of engagement, and cybersecurity students analyzing their own home/lab infrastructure.
3. **No Attack Payload Generation**: This tool does not generate deauthentication packets, perform evil twin attacks, harvest third-party credentials, or automate brute-force against unknown targets.

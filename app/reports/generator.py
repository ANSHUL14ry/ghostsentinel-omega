"""
GHOSTSENTINEL Ω — Report Generator (Module G)

Generates HTML, JSON, and PDF reports from scan evidence.
Never invents findings. Sanitises all output.
"""
from __future__ import annotations

import html
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging_config import get_logger
from app.models.scan import Scan
from app.models.finding import Finding
from app.models.network import Network
from app.models.device import Device
from app.models.report import Report, ReportFormat

logger = get_logger(__name__)

TOOL_VERSION = settings.app_version


def _safe_str(value) -> str:
    """Sanitise a value for HTML output."""
    if value is None:
        return "N/A"
    return html.escape(str(value))


def _load_scan_data(scan_id: str, db: Session) -> dict:
    """Load all scan-related data from the DB."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise ValueError(f"Scan {scan_id} not found.")

    networks = db.query(Network).filter(Network.scan_id == scan_id).all()
    devices = db.query(Device).filter(Device.scan_id == scan_id).all()
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()

    return {
        "scan": scan,
        "networks": networks,
        "devices": devices,
        "findings": findings,
    }


# ─────────────────────────────────────────────────────────────────────────────
# HTML Report
# ─────────────────────────────────────────────────────────────────────────────

def generate_html_report(scan_id: str, db: Session) -> str:
    data = _load_scan_data(scan_id, db)
    scan = data["scan"]
    findings = data["findings"]
    networks = data["networks"]
    devices = data["devices"]

    severity_colours = {
        "critical": "#ff3b3b",
        "high": "#ff8c00",
        "medium": "#ffd700",
        "low": "#4fc3f7",
        "info": "#90a4ae",
    }
    status_labels = {
        "confirmed": "✔ Confirmed",
        "potential": "⚠ Potential",
        "info_unavailable": "ℹ Unavailable",
        "not_tested": "— Not Tested",
    }

    def sev_badge(sev: str) -> str:
        col = severity_colours.get(sev, "#888")
        return f'<span style="background:{col};color:#000;padding:2px 8px;border-radius:4px;font-size:0.8em;font-weight:bold;text-transform:uppercase">{_safe_str(sev)}</span>'

    networks_html = ""
    for n in networks:
        networks_html += f"""
        <tr>
          <td>{_safe_str(n.ssid or '(hidden)')}</td>
          <td>{_safe_str(n.bssid)}</td>
          <td>{_safe_str(n.channel)}</td>
          <td>{_safe_str(n.signal_dbm)} dBm</td>
          <td>{_safe_str(n.security)}</td>
          <td>{_safe_str(n.wps_detected)}</td>
          <td>{_safe_str(n.observed_at)}</td>
        </tr>"""

    devices_html = ""
    for d in devices:
        camera_flag = "⚠ Potential Camera" if d.is_potential_camera else ""
        devices_html += f"""
        <tr>
          <td>{_safe_str(d.ip_address)}</td>
          <td>{_safe_str(d.mac_address)}</td>
          <td>{_safe_str(d.hostname)}</td>
          <td>{_safe_str(d.open_ports)}</td>
          <td style="color:#ffd700">{camera_flag}</td>
        </tr>"""

    findings_html = ""
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        st = f.status.value if hasattr(f.status, "value") else str(f.status)
        label = status_labels.get(st, st)
        evidence = json.loads(f.evidence) if f.evidence else []
        evidence_html = "".join(f"<li>{_safe_str(e)}</li>" for e in evidence)
        refs = json.loads(f.references) if f.references else []
        refs_html = "".join(f'<li><a href="{_safe_str(r)}" target="_blank">{_safe_str(r)}</a></li>' for r in refs)
        findings_html += f"""
        <div style="border:1px solid #333;border-radius:8px;padding:16px;margin:12px 0;background:#1e1e2e">
          <div style="display:flex;align-items:center;gap:12px;margin-bottom:8px">
            {sev_badge(sev)}
            <strong style="color:#e0e0e0">{_safe_str(f.title)}</strong>
            <span style="color:#90a4ae;font-size:0.85em">{label}</span>
          </div>
          <p style="color:#cfd8dc">{_safe_str(f.description)}</p>
          {"<p><strong>Evidence:</strong><ul>" + evidence_html + "</ul></p>" if evidence else ""}
          {"<p><strong>Remediation:</strong><br><em>" + _safe_str(f.remediation) + "</em></p>" if f.remediation else ""}
          {"<p><strong>References:</strong><ul>" + refs_html + "</ul></p>" if refs else ""}
        </div>"""

    scope = _safe_str(scan.scope)
    started = _safe_str(scan.started_at)
    completed = _safe_str(scan.completed_at)

    report_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>GHOSTSENTINEL Ω Report — {_safe_str(scan_id[:8])}</title>
<style>
  body {{font-family:'Segoe UI',sans-serif;background:#121212;color:#e0e0e0;margin:0;padding:24px}}
  h1{{color:#00e676;font-size:2em;margin-bottom:4px}} h2{{color:#40c4ff;border-bottom:1px solid #333;padding-bottom:6px}}
  table{{width:100%;border-collapse:collapse;margin:12px 0}} th{{background:#1a1a2e;color:#40c4ff;padding:8px;text-align:left}}
  td{{padding:8px;border-bottom:1px solid #2a2a3e;color:#cfd8dc}} tr:hover td{{background:#1e1e2e}}
  .meta{{background:#1a1a2e;border-radius:8px;padding:16px;margin-bottom:24px}}
  .disclaimer{{background:#1a0000;border:1px solid #ff3b3b;border-radius:8px;padding:12px;margin-top:32px;color:#ff8a80}}
  a{{color:#40c4ff}}
</style>
</head>
<body>
<h1>🛡 GHOSTSENTINEL Ω — Security Report</h1>
<div class="meta">
  <p><strong>Scan ID:</strong> {_safe_str(scan_id)}</p>
  <p><strong>Scan Type:</strong> {_safe_str(scan.scan_type.value if hasattr(scan.scan_type,'value') else scan.scan_type)}</p>
  <p><strong>Status:</strong> {_safe_str(scan.status.value if hasattr(scan.status,'value') else scan.status)}</p>
  <p><strong>Scope:</strong> {scope}</p>
  <p><strong>Started:</strong> {started} &nbsp;|&nbsp; <strong>Completed:</strong> {completed}</p>
  <p><strong>Tool Version:</strong> {_safe_str(TOOL_VERSION)}</p>
  <p><strong>Generated:</strong> {datetime.now(timezone.utc).isoformat()}</p>
</div>

{"<h2>Wi-Fi Networks Observed</h2><table><tr><th>SSID</th><th>BSSID</th><th>Channel</th><th>Signal</th><th>Security</th><th>WPS</th><th>Observed At</th></tr>" + networks_html + "</table>" if networks else "<h2>Wi-Fi Networks</h2><p>No networks observed.</p>"}
{"<h2>Devices Discovered</h2><table><tr><th>IP</th><th>MAC</th><th>Hostname</th><th>Open Ports</th><th>Camera Flag</th></tr>" + devices_html + "</table>" if devices else ""}
{"<h2>Security Findings (" + str(len(findings)) + ")</h2>" + findings_html if findings else "<h2>Security Findings</h2><p>No findings generated for this scan.</p>"}

<h2>Limitations</h2>
<ul>
  <li>This report reflects observations from a single point-in-time scan.</li>
  <li>WPS status requires beacon frame analysis (monitor mode may be required).</li>
  <li>Device identity cannot be confirmed without additional evidence.</li>
  <li>Camera indicators are based on open ports — not confirmed camera detection.</li>
  <li>Password strength is assessed locally on supplied test passwords only.</li>
</ul>

<div class="disclaimer">
  <strong>⚠ LEGAL NOTICE:</strong> This tool must only be used on networks and devices you are authorised to test.
  Unauthorised network scanning may violate local laws. The tool authors accept no liability for misuse.
</div>
</body>
</html>"""

    return report_html


# ─────────────────────────────────────────────────────────────────────────────
# JSON Export
# ─────────────────────────────────────────────────────────────────────────────

def generate_json_report(scan_id: str, db: Session) -> dict:
    data = _load_scan_data(scan_id, db)
    scan = data["scan"]

    def net_to_dict(n):
        return {
            "id": n.id,
            "ssid": n.ssid,
            "bssid": n.bssid,
            "channel": n.channel,
            "frequency_mhz": n.frequency_mhz,
            "signal_dbm": n.signal_dbm,
            "security": n.security,
            "encryption": n.encryption,
            "authentication": n.authentication,
            "wps_detected": n.wps_detected,
            "observed_at": n.observed_at.isoformat() if n.observed_at else None,
        }

    def dev_to_dict(d):
        return {
            "id": d.id,
            "ip_address": d.ip_address,
            "mac_address": d.mac_address,
            "hostname": d.hostname,
            "vendor": d.vendor,
            "open_ports": json.loads(d.open_ports) if d.open_ports else [],
            "services": json.loads(d.services) if d.services else {},
            "is_potential_camera": d.is_potential_camera,
            "camera_evidence": json.loads(d.camera_evidence) if d.camera_evidence else [],
            "discovered_at": d.discovered_at.isoformat() if d.discovered_at else None,
        }

    def finding_to_dict(f):
        return {
            "id": f.id,
            "title": f.title,
            "description": f.description,
            "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
            "status": f.status.value if hasattr(f.status, "value") else str(f.status),
            "evidence": json.loads(f.evidence) if f.evidence else [],
            "remediation": f.remediation,
            "references": json.loads(f.references) if f.references else [],
            "created_at": f.created_at.isoformat() if f.created_at else None,
        }

    return {
        "report_metadata": {
            "scan_id": scan_id,
            "scan_type": scan.scan_type.value if hasattr(scan.scan_type, "value") else str(scan.scan_type),
            "status": scan.status.value if hasattr(scan.status, "value") else str(scan.status),
            "scope": scan.scope,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "tool_version": TOOL_VERSION,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
        "networks": [net_to_dict(n) for n in data["networks"]],
        "devices": [dev_to_dict(d) for d in data["devices"]],
        "findings": [finding_to_dict(f) for f in data["findings"]],
        "limitations": [
            "Point-in-time scan only.",
            "WPS status requires beacon analysis.",
            "Camera indicators based on open ports, not confirmed detection.",
            "Passwords assessed locally only.",
        ],
    }


# ─────────────────────────────────────────────────────────────────────────────
# PDF Report (reportlab)
# ─────────────────────────────────────────────────────────────────────────────

def generate_pdf_report(scan_id: str, db: Session) -> bytes:
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from io import BytesIO
    except ImportError:
        raise RuntimeError("reportlab is not installed. Run: pip install reportlab")

    data = _load_scan_data(scan_id, db)
    scan = data["scan"]
    findings = data["findings"]

    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=20*mm, bottomMargin=20*mm)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("Title", parent=styles["Title"], textColor=colors.HexColor("#00e676"), fontSize=20)
    h2_style = ParagraphStyle("H2", parent=styles["Heading2"], textColor=colors.HexColor("#40c4ff"))
    body_style = ParagraphStyle("Body", parent=styles["Normal"], textColor=colors.HexColor("#212121"))

    story = []
    story.append(Paragraph("GHOSTSENTINEL Ω — Security Report", title_style))
    story.append(Spacer(1, 6*mm))

    meta = [
        ["Scan ID", scan_id],
        ["Type", str(scan.scan_type.value if hasattr(scan.scan_type, 'value') else scan.scan_type)],
        ["Status", str(scan.status.value if hasattr(scan.status, 'value') else scan.status)],
        ["Scope", str(scan.scope or "N/A")],
        ["Started", str(scan.started_at or "N/A")],
        ["Generated", datetime.now(timezone.utc).isoformat()],
        ["Tool Version", TOOL_VERSION],
    ]
    t = Table(meta, colWidths=[50*mm, 120*mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#1a1a2e")),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#40c4ff")),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (1, 0), (1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
    ]))
    story.append(t)
    story.append(Spacer(1, 8*mm))

    # Networks
    story.append(Paragraph("Wi-Fi Networks Observed", h2_style))
    if data["networks"]:
        net_data = [["SSID", "BSSID", "Channel", "Signal", "Security"]]
        for n in data["networks"]:
            net_data.append([
                str(n.ssid or "(hidden)"), str(n.bssid or "N/A"),
                str(n.channel or "N/A"), f"{n.signal_dbm} dBm" if n.signal_dbm else "N/A",
                str(n.security or "N/A"),
            ])
        nt = Table(net_data, colWidths=[40*mm, 45*mm, 25*mm, 25*mm, 35*mm])
        nt.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        story.append(nt)
    else:
        story.append(Paragraph("No networks observed.", body_style))
    story.append(Spacer(1, 8*mm))

    # Findings
    story.append(Paragraph(f"Security Findings ({len(findings)})", h2_style))
    sev_colors = {
        "critical": "#ff3b3b", "high": "#ff8c00",
        "medium": "#ffd700", "low": "#4fc3f7", "info": "#90a4ae",
    }
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        col = sev_colors.get(sev, "#888")
        story.append(Paragraph(
            f'<font color="{col}">[{sev.upper()}]</font> <b>{f.title}</b>',
            body_style,
        ))
        story.append(Paragraph(f.description or "", body_style))
        if f.remediation:
            story.append(Paragraph(f"<b>Remediation:</b> {f.remediation}", body_style))
        story.append(Spacer(1, 4*mm))

    story.append(Spacer(1, 8*mm))
    story.append(Paragraph(
        "⚠ LEGAL NOTICE: Use only on networks you are authorised to test.",
        ParagraphStyle("disc", parent=styles["Normal"], textColor=colors.red, fontSize=8),
    ))

    doc.build(story)
    return buf.getvalue()


# ─────────────────────────────────────────────────────────────────────────────
# Persist report to disk and DB
# ─────────────────────────────────────────────────────────────────────────────

def save_report(scan_id: str, fmt: str, db: Session) -> Report:
    """Generate and save a report file. Returns the Report ORM record."""
    reports_dir = settings.reports_dir
    reports_dir.mkdir(parents=True, exist_ok=True)

    report_id = str(uuid.uuid4())
    filename = f"ghostsentinel_{scan_id[:8]}_{report_id[:8]}.{fmt}"
    file_path = reports_dir / filename

    if fmt == "html":
        content = generate_html_report(scan_id, db)
        file_path.write_text(content, encoding="utf-8")
        size = file_path.stat().st_size
    elif fmt == "json":
        data = generate_json_report(scan_id, db)
        file_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        size = file_path.stat().st_size
    elif fmt == "pdf":
        content = generate_pdf_report(scan_id, db)
        file_path.write_bytes(content)
        size = file_path.stat().st_size
    else:
        raise ValueError(f"Unsupported format: {fmt}")

    report = Report(
        id=report_id,
        scan_id=scan_id,
        format=ReportFormat(fmt),
        filename=filename,
        file_path=str(file_path),
        size_bytes=str(size),
    )
    db.add(report)
    db.commit()
    logger.info("Report saved: %s (%d bytes)", filename, size)
    return report

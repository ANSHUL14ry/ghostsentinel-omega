"""
GHOSTSENTINEL Ω — Findings & Reports API (Modules B + G)
"""
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy.orm import Session
from typing import List

from app.database import get_db
from app.models.finding import Finding
from app.models.report import Report
from app.reports.generator import save_report
from app.schemas.schemas import FindingOut, ReportOut, APIResponse

router = APIRouter(prefix="/api/findings", tags=["Findings"])
reports_router = APIRouter(prefix="/api/reports", tags=["Reports"])


@router.get("/{scan_id}", response_model=List[FindingOut], summary="Get findings for a scan")
def get_findings(scan_id: str, db: Session = Depends(get_db)):
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    return findings


@router.get("/all/list", response_model=List[FindingOut], summary="List all findings")
def list_all_findings(db: Session = Depends(get_db)):
    findings = db.query(Finding).order_by(Finding.created_at.desc()).limit(500).all()
    return findings


@reports_router.post("/generate", response_model=APIResponse, summary="Generate a report")
def generate_report(
    scan_id: str,
    fmt: str = "html",
    db: Session = Depends(get_db),
):
    """
    Generate a report for the given scan_id.
    fmt: html | json | pdf
    """
    if fmt not in ("html", "json", "pdf"):
        raise HTTPException(status_code=400, detail="Invalid format. Use: html, json, pdf")
    try:
        report = save_report(scan_id, fmt, db)
        return APIResponse(
            success=True,
            message=f"Report generated: {report.filename}",
            data={"report_id": report.id, "filename": report.filename},
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report generation failed: {type(e).__name__}")


@reports_router.get("/list", response_model=List[ReportOut], summary="List generated reports")
def list_reports(db: Session = Depends(get_db)):
    reports = db.query(Report).order_by(Report.generated_at.desc()).all()
    return reports


@reports_router.get("/download/{report_id}", summary="Download a report file")
def download_report(report_id: str, db: Session = Depends(get_db)):
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found.")
    import os
    if not os.path.exists(report.file_path):
        raise HTTPException(status_code=404, detail="Report file not found on disk.")
    media_types = {"html": "text/html", "json": "application/json", "pdf": "application/pdf"}
    media_type = media_types.get(report.format.value if hasattr(report.format, "value") else report.format, "application/octet-stream")
    return FileResponse(
        path=report.file_path,
        filename=report.filename,
        media_type=media_type,
    )

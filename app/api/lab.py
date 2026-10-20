"""
GHOSTSENTINEL Ω — Controlled Wireless Security Lab API (Module C)

Provides authorized, non-destructive security assessment against test access points
and routers in an isolated lab environment.
"""
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.auditors.lab_auditor import run_lab_assessment
from app.schemas.schemas import LabAssessmentRequest, APIResponse

router = APIRouter(prefix="/api/lab", tags=["Controlled Security Lab"])


@router.post("/assess", response_model=APIResponse, summary="Perform controlled lab assessment on authorized network")
def assess_target(payload: LabAssessmentRequest):
    """
    Execute controlled, non-destructive wireless security assessment
    on an authorized target router or access point.
    Requires explicit user authorization.
    """
    if not payload.authorized:
        raise HTTPException(
            status_code=403,
            detail="Forbidden: Lab assessment strictly requires explicit user confirmation of authorized ownership or permission."
        )

    try:
        result = run_lab_assessment(
            target_ssid=payload.target_ssid,
            target_bssid=payload.target_bssid,
            security=payload.security,
            channel=payload.channel,
            router_ip=payload.router_ip,
            wps_detected=payload.wps_detected,
            authorized=payload.authorized,
        )

        serialized_findings = [
            {
                "title": f.title,
                "description": f.description,
                "severity": f.severity,
                "status": f.status,
                "evidence": f.evidence,
                "remediation": f.remediation,
                "references": f.references,
            }
            for f in result.findings
        ]

        return APIResponse(
            success=True,
            message=f"Lab assessment complete for '{result.target_ssid}'. Score: {result.score}/100 ({result.security_posture}).",
            data={
                "target_ssid": result.target_ssid,
                "target_bssid": result.target_bssid,
                "authorized": result.authorized,
                "score": result.score,
                "security_posture": result.security_posture,
                "checks_run": result.checks_run,
                "findings": serialized_findings,
                "notes": result.notes,
                "timestamp": result.timestamp,
            },
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Lab assessment failed: {type(e).__name__}: {str(e)}")

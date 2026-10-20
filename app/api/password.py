"""
GHOSTSENTINEL Ω — Password Audit API (Module C)
"""
from fastapi import APIRouter
from app.auditors.password_auditor import audit_password
from app.schemas.schemas import PasswordAuditRequest, PasswordAuditResult

router = APIRouter(prefix="/api/password", tags=["Password Audit"])


@router.post("/audit", response_model=PasswordAuditResult, summary="Assess password strength locally")
def audit_password_endpoint(request: PasswordAuditRequest):
    """
    Assesses password strength using local zxcvbn analysis.
    The plaintext password is NEVER stored, logged, or transmitted.
    Use only for passwords you own or are authorised to test.
    """
    return audit_password(request.password, request.label)

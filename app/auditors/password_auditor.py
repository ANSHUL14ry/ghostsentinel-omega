"""
GHOSTSENTINEL Ω — Password Strength Auditor (Module C)

Uses zxcvbn for locally-computed, evidence-based password strength assessment.
NEVER stores plaintext passwords.
NEVER transmits passwords to external services.
Safe for controlled lab use only.
"""
from __future__ import annotations

import gc
from typing import List, Optional

import zxcvbn

from app.schemas.schemas import PasswordAuditResult


_SCORE_LABELS = {
    0: "Very Weak",
    1: "Weak",
    2: "Fair",
    3: "Strong",
    4: "Very Strong",
}

# Common Wi-Fi-specific weak patterns
_WIFI_WEAK_PATTERNS = [
    "password", "12345678", "87654321", "admin", "router",
    "internet", "wifi", "wireless", "home", "network",
    "default", "qwerty", "letmein", "welcome",
]


def audit_password(password: str, label: str = "unnamed") -> PasswordAuditResult:
    """
    Assess password strength using zxcvbn.
    The plaintext password is zeroed immediately after analysis.
    Returns PasswordAuditResult — the password field is intentionally absent.
    """
    if not password:
        return PasswordAuditResult(
            label=label,
            score=0,
            score_label="Very Weak",
            crack_time_display="instantly",
            warning="Empty password.",
            suggestions=["Provide a non-empty password."],
            has_common_pattern=True,
            length=0,
        )

    length = len(password)
    pw_lower = password.lower()
    has_common = any(p in pw_lower for p in _WIFI_WEAK_PATTERNS)

    try:
        result = zxcvbn.zxcvbn(password)
    finally:
        # Attempt to scrub the password from local scope
        # Note: Python GC may not guarantee memory zeroing, but this reduces exposure window
        password = "X" * length  # noqa: F841
        del password
        gc.collect()

    score = result.get("score", 0)
    feedback = result.get("feedback", {})
    warning = feedback.get("warning") or None
    suggestions: List[str] = feedback.get("suggestions", [])

    crack_times = result.get("crack_times_display", {})
    crack_time_display = (
        crack_times.get("offline_slow_hashing_1e4_per_second")
        or crack_times.get("offline_fast_hashing_1e10_per_second")
        or "unknown"
    )

    if has_common and score < 3:
        suggestions.insert(0, "Avoid common Wi-Fi password patterns.")

    return PasswordAuditResult(
        label=label,
        score=score,
        score_label=_SCORE_LABELS.get(score, "Unknown"),
        crack_time_display=crack_time_display,
        warning=warning,
        suggestions=suggestions,
        has_common_pattern=has_common,
        length=length,
    )

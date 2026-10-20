"""
GHOSTSENTINEL Ω — Commercial Architecture & Licensing Abstraction

Provides feature tier configuration (Community, Professional, Enterprise Lab),
entitlement checks, and commercial foundation without locking operators out of their data.
"""
from __future__ import annotations

import enum
from typing import Dict, List, Set
from dataclasses import dataclass, field


class LicenseTier(str, enum.Enum):
    community = "community"
    professional = "professional"
    enterprise = "enterprise"


class FeatureEntitlement(str, enum.Enum):
    WIFI_DISCOVERY = "wifi_discovery"
    CONFIG_AUDIT = "config_audit"
    ROGUE_AP_DETECTION = "rogue_ap_detection"
    CONTROLLED_SECURITY_LAB = "controlled_security_lab"
    DEVICE_DISCOVERY = "device_discovery"
    PASSWORD_AUDIT = "password_audit"
    CAMERA_INSPECTION = "camera_inspection"
    JSON_HTML_REPORTS = "json_html_reports"
    EXECUTIVE_PDF_REPORTS = "executive_pdf_reports"
    ADVANCED_NMAP_INTEGRATION = "advanced_nmap_integration"
    MULTI_SITE_BASELINE_SYNC = "multi_site_baseline_sync"
    ENTERPRISE_API_INTEGRATION = "enterprise_api_integration"


TIER_FEATURES: Dict[LicenseTier, Set[FeatureEntitlement]] = {
    LicenseTier.community: {
        FeatureEntitlement.WIFI_DISCOVERY,
        FeatureEntitlement.CONFIG_AUDIT,
        FeatureEntitlement.ROGUE_AP_DETECTION,
        FeatureEntitlement.CONTROLLED_SECURITY_LAB,
        FeatureEntitlement.DEVICE_DISCOVERY,
        FeatureEntitlement.PASSWORD_AUDIT,
        FeatureEntitlement.CAMERA_INSPECTION,
        FeatureEntitlement.JSON_HTML_REPORTS,
        FeatureEntitlement.EXECUTIVE_PDF_REPORTS,
        FeatureEntitlement.ADVANCED_NMAP_INTEGRATION,
    },
    LicenseTier.professional: {
        FeatureEntitlement.WIFI_DISCOVERY,
        FeatureEntitlement.CONFIG_AUDIT,
        FeatureEntitlement.ROGUE_AP_DETECTION,
        FeatureEntitlement.CONTROLLED_SECURITY_LAB,
        FeatureEntitlement.DEVICE_DISCOVERY,
        FeatureEntitlement.PASSWORD_AUDIT,
        FeatureEntitlement.CAMERA_INSPECTION,
        FeatureEntitlement.JSON_HTML_REPORTS,
        FeatureEntitlement.EXECUTIVE_PDF_REPORTS,
        FeatureEntitlement.ADVANCED_NMAP_INTEGRATION,
        FeatureEntitlement.MULTI_SITE_BASELINE_SYNC,
    },
    LicenseTier.enterprise: set(FeatureEntitlement),
}


@dataclass
class LicenseStatus:
    tier: LicenseTier
    tier_name: str
    active: bool
    license_key: str
    features: List[str]
    max_concurrent_scans: int
    data_retention_days: int
    allows_commercial_use: bool


def get_current_license() -> LicenseStatus:
    from app.core.config import settings
    raw_tier = getattr(settings, "license_tier", "community").lower()
    try:
        tier = LicenseTier(raw_tier)
    except ValueError:
        tier = LicenseTier.community

    tier_names = {
        LicenseTier.community: "Community Edition (Defensive)",
        LicenseTier.professional: "Professional Security Assessment Edition",
        LicenseTier.enterprise: "Enterprise Wireless Lab Edition",
    }

    entitlements = [f.value for f in TIER_FEATURES.get(tier, set())]

    return LicenseStatus(
        tier=tier,
        tier_name=tier_names.get(tier, "Community Edition"),
        active=True,
        license_key="LOCAL-OPERATOR-DEPLOYMENT",
        features=sorted(entitlements),
        max_concurrent_scans=5 if tier == LicenseTier.enterprise else (2 if tier == LicenseTier.professional else 1),
        data_retention_days=365 if tier != LicenseTier.community else 90,
        allows_commercial_use=tier != LicenseTier.community,
    )


def is_entitled(feature: FeatureEntitlement) -> bool:
    """Check if the currently active license includes the requested feature."""
    lic = get_current_license()
    allowed = TIER_FEATURES.get(lic.tier, set())
    return feature in allowed

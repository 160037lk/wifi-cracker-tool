"""Authorization and platform policy checks."""
from __future__ import annotations

import platform
from dataclasses import dataclass
from typing import Optional

from models import Authorization


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str


class AuditPolicy:
    """Enforces Windows-only, explicitly authorized read-only audits."""

    def __init__(self, require_windows: bool = True) -> None:
        self.require_windows = require_windows

    def check_platform(self) -> PolicyDecision:
        if self.require_windows and platform.system().lower() != "windows":
            return PolicyDecision(False, "仅支持 Windows 平台。")
        return PolicyDecision(True, "平台检查通过。")

    def validate_authorization(self, authorization: Optional[Authorization]) -> PolicyDecision:
        if authorization is None:
            return PolicyDecision(False, "必须先提供授权记录。")
        required = {
            "operator": authorization.operator,
            "organization": authorization.organization,
            "purpose": authorization.purpose,
            "evidence_reference": authorization.evidence_reference,
        }
        if any(not str(value).strip() for value in required.values()):
            return PolicyDecision(False, "授权人、组织、目的和凭证引用均不能为空。")
        if not authorization.scope.ssids and not authorization.scope.bssids and not authorization.scope.include_saved_profiles:
            return PolicyDecision(False, "授权范围不能为空。")
        return PolicyDecision(True, "授权检查通过。")

    def authorize(self, authorization: Optional[Authorization]) -> PolicyDecision:
        platform_decision = self.check_platform()
        if not platform_decision.allowed:
            return platform_decision
        return self.validate_authorization(authorization)

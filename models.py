"""Domain models for authorized Wi-Fi security audits."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class WifiNetwork:
    ssid: str
    bssid: str = ""
    signal: Optional[int] = None
    channel: Optional[int] = None
    encryption: str = "Unknown"


@dataclass(frozen=True)
class SavedProfile:
    name: str
    authentication: str = "Unknown"
    cipher: str = "Unknown"
    connection_mode: str = "Unknown"


@dataclass(frozen=True)
class AuditScope:
    ssids: List[str] = field(default_factory=list)
    bssids: List[str] = field(default_factory=list)
    include_saved_profiles: bool = True

    def matches(self, network: WifiNetwork) -> bool:
        if not self.ssids and not self.bssids:
            return True
        return (network.ssid in self.ssids) or (network.bssid.lower() in {x.lower() for x in self.bssids})


@dataclass(frozen=True)
class Authorization:
    operator: str
    organization: str
    purpose: str
    evidence_reference: str
    scope: AuditScope
    acknowledged_at: str = field(default_factory=utc_now)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RiskFinding:
    rule_id: str
    severity: str
    title: str
    detail: str
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuditResult:
    started_at: str = field(default_factory=utc_now)
    completed_at: Optional[str] = None
    networks: List[WifiNetwork] = field(default_factory=list)
    saved_profiles: List[SavedProfile] = field(default_factory=list)
    findings: List[RiskFinding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "networks": [asdict(item) for item in self.networks],
            "saved_profiles": [asdict(item) for item in self.saved_profiles],
            "findings": [asdict(item) for item in self.findings],
            "errors": list(self.errors),
        }

    @property
    def highest_severity(self) -> str:
        order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        return max((item.severity for item in self.findings), key=lambda x: order.get(x, 0), default="info")

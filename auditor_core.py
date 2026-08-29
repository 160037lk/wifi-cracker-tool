"""Risk evaluation for Wi-Fi metadata and saved profile posture."""
from __future__ import annotations

from typing import List, Sequence

from models import RiskFinding, SavedProfile, WifiNetwork


def evaluate_risks(networks: Sequence[WifiNetwork], profiles: Sequence[SavedProfile]) -> List[RiskFinding]:
    findings: List[RiskFinding] = []
    for network in networks:
        encryption = network.encryption.lower()
        if "open" in encryption or "开放" in encryption or encryption in {"none", "unknown"}:
            findings.append(RiskFinding("NET-001", "high", "网络未检测到可靠加密", f"SSID {network.ssid or '[隐藏]'} 的加密类型为 {network.encryption}。", {"ssid": network.ssid, "bssid": network.bssid}))
        elif "wep" in encryption:
            findings.append(RiskFinding("NET-002", "critical", "使用已淘汰的 WEP", f"SSID {network.ssid} 使用 WEP。", {"ssid": network.ssid}))
        elif "wpa" in encryption and "wpa2" not in encryption and "wpa3" not in encryption:
            findings.append(RiskFinding("NET-003", "medium", "检测到旧版 WPA", f"SSID {network.ssid} 可能使用旧版 WPA。", {"ssid": network.ssid}))
    for profile in profiles:
        auth = profile.authentication.lower()
        if "wep" in auth:
            findings.append(RiskFinding("PRO-001", "critical", "已保存配置使用 WEP", f"配置 {profile.name} 使用 WEP。", {"profile": profile.name}))
        if profile.authentication == "Unknown":
            findings.append(RiskFinding("PRO-002", "low", "保存配置元数据不完整", f"无法解析配置 {profile.name} 的认证类型。", {"profile": profile.name}))
    return findings

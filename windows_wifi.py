"""Read-only Windows netsh Wi-Fi adapter."""
from __future__ import annotations

import platform
import re
import subprocess
from typing import List, Sequence

from models import SavedProfile, WifiNetwork


class WindowsWifiReader:
    """Collects Wi-Fi metadata without connecting or changing profiles."""

    _ALLOWED_COMMANDS = {"interfaces", "networks", "profiles", "profile"}

    def __init__(self, runner=subprocess.run, timeout_seconds: float = 15.0) -> None:
        self.runner = runner
        self.timeout_seconds = timeout_seconds

    def _run_netsh(self, args: Sequence[str]) -> str:
        if platform.system().lower() != "windows":
            raise RuntimeError("仅支持 Windows 平台。")
        if len(args) < 3 or args[0] != "wlan" or args[1] != "show" or args[2] not in self._ALLOWED_COMMANDS:
            raise ValueError("不允许的 netsh 命令。")
        command = ["netsh", *args]
        completed = self.runner(command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=self.timeout_seconds, shell=False, check=False)
        if completed.returncode != 0:
            raise RuntimeError(completed.stderr.strip() or "netsh 查询失败。")
        return completed.stdout

    def interfaces(self) -> str:
        return self._run_netsh(["wlan", "show", "interfaces"])

    def scan_networks(self) -> List[WifiNetwork]:
        output = self._run_netsh(["wlan", "show", "networks", "mode=bssid"])
        return self._parse_networks(output)

    def saved_profiles(self) -> List[SavedProfile]:
        listing = self._run_netsh(["wlan", "show", "profiles"])
        names = re.findall(r"(?:All User Profile|用户配置文件)\s*:\s*(.+)", listing, flags=re.IGNORECASE)
        profiles: List[SavedProfile] = []
        for name in names:
            profile_output = self._run_netsh(["wlan", "show", "profile", f"name={name.strip()}"])
            profiles.append(self._parse_profile(name.strip(), profile_output))
        return profiles

    @staticmethod
    def _parse_networks(output: str) -> List[WifiNetwork]:
        networks: List[WifiNetwork] = []
        current_ssid = ""
        current_auth = "Unknown"
        current_signal = None
        current_channel = None
        current_bssid = ""
        for raw in output.splitlines():
            line = raw.strip()
            match = re.match(r"SSID\s+\d+\s*:\s*(.*)$", line, flags=re.IGNORECASE)
            if match:
                current_ssid = match.group(1).strip()
                current_auth, current_signal, current_channel, current_bssid = "Unknown", None, None, ""
                continue
            if not current_ssid:
                continue
            match = re.match(r"Authentication\s*:\s*(.*)$", line, flags=re.IGNORECASE)
            if match:
                current_auth = match.group(1).strip()
            match = re.match(r"Signal\s*:\s*(\d+)%", line, flags=re.IGNORECASE)
            if match:
                current_signal = int(match.group(1))
            match = re.match(r"Channel\s*:\s*(\d+)", line, flags=re.IGNORECASE)
            if match:
                current_channel = int(match.group(1))
            match = re.match(r"BSSID\s+\d+\s*:\s*([0-9a-f:.-]+)", line, flags=re.IGNORECASE)
            if match:
                current_bssid = match.group(1).strip()
                networks.append(WifiNetwork(current_ssid, current_bssid, current_signal, current_channel, current_auth))
        return networks

    @staticmethod
    def _parse_profile(name: str, output: str) -> SavedProfile:
        def value(label: str) -> str:
            match = re.search(rf"{label}\s*:\s*(.+)", output, flags=re.IGNORECASE)
            return match.group(1).strip() if match else "Unknown"
        return SavedProfile(name=name, authentication=value("Authentication"), cipher=value("Cipher"), connection_mode=value("Connection mode"))

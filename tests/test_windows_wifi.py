from types import SimpleNamespace

import windows_wifi
from windows_wifi import WindowsWifiReader


NETWORK_OUTPUT = """SSID 1 : LabNet\n    Authentication : WPA2-Personal\n    Signal : 80%\n    Channel : 6\n    BSSID 1 : aa:bb:cc:dd:ee:ff\n"""
PROFILE_LIST = "    All User Profile     : LabNet\n"
PROFILE_OUTPUT = "    Authentication       : WPA2-Personal\n    Cipher                : CCMP\n    Connection mode       : Auto Connect\n"


def test_scan_with_mock_runner(monkeypatch) -> None:
    calls = []

    def runner(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=0, stdout=NETWORK_OUTPUT, stderr="")

    monkeypatch.setattr(windows_wifi.platform, "system", lambda: "Windows")
    networks = WindowsWifiReader(runner=runner).scan_networks()
    assert networks[0].ssid == "LabNet"
    assert networks[0].bssid == "aa:bb:cc:dd:ee:ff"
    assert calls[0][0] == ["netsh", "wlan", "show", "networks", "mode=bssid"]
    assert calls[0][1]["shell"] is False


def test_saved_profiles_do_not_request_keys(monkeypatch) -> None:
    def runner(command, **kwargs):
        output = PROFILE_LIST if command[3] == "profiles" else PROFILE_OUTPUT
        return SimpleNamespace(returncode=0, stdout=output, stderr="")

    monkeypatch.setattr(windows_wifi.platform, "system", lambda: "Windows")
    profiles = WindowsWifiReader(runner=runner).saved_profiles()
    assert profiles[0].name == "LabNet"
    assert profiles[0].authentication == "WPA2-Personal"

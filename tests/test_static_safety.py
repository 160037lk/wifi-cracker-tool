"""Static safety gate tests: forbid attack code and dangerous netsh usage."""
from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

FORBIDDEN_IDENTIFIERS = {
    "try_connect",
    "crack_passwords_batch",
    "password_generator",
    "get_optimal_workers",
    "WiFiCracker",
    "OptimizedGUI",
}

FORBIDDEN_DANGEROUS_CALLS = (
    r"pywifi",
    r"ThreadPoolExecutor",
    r"iface\.connect",
    r"iface\.disconnect",
    r"pywifi\.Profile",
    r"add_network_profile",
    r"remove_all_network_profiles",
    r"IFACE_CONNECTED",
    r"key\s*=\s*clear",
)


def _iter_source_files() -> list[Path]:
    return [path for path in REPO_ROOT.rglob("*.py") if "tests" not in path.parts]


def test_no_attack_apis() -> None:
    sources = []
    for path in _iter_source_files():
        sources.append(path.read_text(encoding="utf-8"))
    combined = "\n".join(sources)
    for identifier in FORBIDDEN_IDENTIFIERS:
        assert identifier not in combined, f"禁用标识符残留: {identifier}"


def test_no_dangerous_calls() -> None:
    for path in _iter_source_files():
        content = path.read_text(encoding="utf-8")
        for pattern in FORBIDDEN_DANGEROUS_CALLS:
            assert not re.search(pattern, content), f"{path.name} 包含危险调用: {pattern}"


def test_netsh_uses_safe_args() -> None:
    netsh_path = REPO_ROOT / "windows_wifi.py"
    content = netsh_path.read_text(encoding="utf-8")
    assert "shell=False" in content
    assert "key=clear" not in content
    assert "mode=bssid" in content

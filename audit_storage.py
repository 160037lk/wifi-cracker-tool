"""Tamper-evident JSONL audit storage using a SHA-256 hash chain."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Optional


class AuditLog:
    """Append-only audit log; each entry commits to its predecessor hash."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _last_hash(self) -> str:
        if not self.path.exists():
            return "0" * 64
        last: Optional[str] = None
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    last = json.loads(line).get("entry_hash")
        return last or "0" * 64

    def append(self, event: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        entry: Dict[str, Any] = {"event": event, "payload": payload, "previous_hash": self._last_hash()}
        canonical = json.dumps(entry, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        entry["entry_hash"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")
        return entry

    def verify(self) -> bool:
        previous = "0" * 64
        if not self.path.exists():
            return True
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                entry = json.loads(line)
                saved = entry.pop("entry_hash", "")
                if entry.get("previous_hash") != previous:
                    return False
                canonical = json.dumps(entry, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                if hashlib.sha256(canonical.encode("utf-8")).hexdigest() != saved:
                    return False
                previous = saved
        return True

from pathlib import Path

from audit_storage import AuditLog


def test_hash_chain(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.jsonl")
    log.append("one", {"x": 1})
    log.append("two", {"x": 2})
    assert log.verify()
    content = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    content[0] = content[0].replace('"x": 1', '"x": 9')
    (tmp_path / "audit.jsonl").write_text("\n".join(content) + "\n", encoding="utf-8")
    assert not log.verify()

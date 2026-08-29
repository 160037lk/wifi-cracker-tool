from pathlib import Path

from audit_policy import AuditPolicy
from models import AuditScope, Authorization


def make_auth(**overrides):
    base = dict(operator="Alice", organization="Self", purpose="self-audit", evidence_reference="ticket-1", scope=AuditScope(include_saved_profiles=True))
    base.update(overrides)
    return Authorization(**base)


def test_platform_required() -> None:
    decision = AuditPolicy(require_windows=True).check_platform()
    if __import__("platform").system().lower() == "windows":
        assert decision.allowed
    else:
        assert not decision.allowed


def test_authorization_missing() -> None:
    policy = AuditPolicy()
    assert not policy.validate_authorization(None).allowed


def test_authorization_blank_rejected() -> None:
    policy = AuditPolicy()
    auth = make_auth(operator="")
    assert not policy.validate_authorization(auth).allowed


def test_authorization_empty_scope_rejected() -> None:
    policy = AuditPolicy()
    auth = make_auth(scope=AuditScope(include_saved_profiles=False))
    assert not policy.validate_authorization(auth).allowed


def test_authorization_accepted() -> None:
    policy = AuditPolicy()
    assert policy.validate_authorization(make_auth()).allowed

from models import SavedProfile, WifiNetwork
from auditor_core import evaluate_risks


def test_risk_rules() -> None:
    findings = evaluate_risks([WifiNetwork("open", encryption="Open"), WifiNetwork("legacy", encryption="WEP")], [SavedProfile("old", authentication="WEP")])
    assert {item.rule_id for item in findings} == {"NET-001", "NET-002", "PRO-001"}

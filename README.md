# Authorized Wi-Fi Security Auditor

Windows-only, read-only Wi-Fi security self-audit tool for networks you own or are explicitly authorized to test. It scans nearby metadata, inspects saved profile metadata via `netsh`, rates common risks, records a tamper-evident JSONL audit trail, and exports CSV reports.

## Safety and scope

- No password dictionaries, password prompts, connection attempts, profile writes, or interface connect/disconnect operations.
- Never reads or stores plaintext Wi-Fi passwords; `key=clear` is not used.
- First use requires an operator, organization, purpose, and authorization/evidence reference. Reconfirm authorization when scope changes.
- Designed for ordinary user privileges where Windows permits read-only `netsh wlan show` queries.

## Run

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python wifi_cracker_optimized.py
```

The application exits with a clear message on non-Windows systems. Optional PDF export is available when `reportlab` is installed; CSV export works with the standard library.

## Tests

```powershell
pytest -q
```

Audit entries are written to `audit_logs/audit.jsonl`. Do not commit this runtime log.

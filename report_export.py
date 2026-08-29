"""CSV and optional PDF export for audit results."""
from __future__ import annotations

import csv
from pathlib import Path
from typing import Optional

from models import AuditResult


def export_csv(result: AuditResult, path: Path) -> Path:
    """Write networks and findings to a portable CSV file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["section", "id", "name", "bssid", "signal", "channel", "encryption", "severity", "detail"])
        for index, network in enumerate(result.networks, 1):
            writer.writerow(["network", index, network.ssid, network.bssid, network.signal, network.channel, network.encryption, "", ""])
        for index, finding in enumerate(result.findings, 1):
            writer.writerow(["finding", index, finding.title, "", "", "", "", finding.severity, finding.detail])
    return path


def export_pdf(result: AuditResult, path: Path) -> Optional[Path]:
    """Export a basic PDF when reportlab is installed; otherwise return None."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas
    except ImportError:
        return None
    path.parent.mkdir(parents=True, exist_ok=True)
    pdf = canvas.Canvas(str(path), pagesize=A4)
    text = pdf.beginText(40, 800)
    text.textLine("Authorized Wi-Fi Security Audit")
    text.textLine(f"Networks: {len(result.networks)}  Findings: {len(result.findings)}")
    for finding in result.findings:
        text.textLine(f"[{finding.severity}] {finding.title}")
    pdf.drawText(text)
    pdf.save()
    return path

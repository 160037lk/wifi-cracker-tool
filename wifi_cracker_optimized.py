"""Windows-only authorized Wi-Fi security self-audit application."""
from __future__ import annotations

import platform
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import List, Optional

from audit_policy import AuditPolicy
from audit_storage import AuditLog
from auditor_core import evaluate_risks
from models import AuditResult, AuditScope, Authorization, WifiNetwork
from report_export import export_csv, export_pdf
from windows_wifi import WindowsWifiReader


class AuditorApp:
    """Tkinter UI for read-only authorized audits."""

    def __init__(self, root: tk.Tk, reader: Optional[WindowsWifiReader] = None) -> None:
        self.root = root
        self.reader = reader or WindowsWifiReader()
        self.policy = AuditPolicy()
        self.networks: List[WifiNetwork] = []
        self.result = AuditResult()
        self.authorization: Optional[Authorization] = None
        self.status = tk.StringVar(value="请填写授权信息后开始。")
        self._build_ui()

    def _build_ui(self) -> None:
        self.root.title("Wi-Fi 安全自检（仅限授权网络）")
        self.root.geometry("900x620")
        auth = ttk.LabelFrame(self.root, text="首次授权（范围变更需重新确认）")
        auth.pack(fill="x", padx=10, pady=8)
        self.operator = tk.StringVar()
        self.organization = tk.StringVar()
        self.purpose = tk.StringVar(value="自有网络安全自检")
        self.evidence = tk.StringVar()
        fields = [("授权人", self.operator), ("组织", self.organization), ("目的", self.purpose), ("凭证/工单引用", self.evidence)]
        for row, (label, variable) in enumerate(fields):
            ttk.Label(auth, text=label).grid(row=row // 2, column=(row % 2) * 2, padx=5, pady=4, sticky="e")
            ttk.Entry(auth, textvariable=variable, width=35).grid(row=row // 2, column=(row % 2) * 2 + 1, padx=5, pady=4, sticky="w")
        ttk.Button(auth, text="确认授权", command=self.confirm_authorization).grid(row=2, column=0, padx=5, pady=4, sticky="w")
        ttk.Button(auth, text="只读扫描", command=self.scan).grid(row=2, column=1, padx=5, pady=4, sticky="w")
        ttk.Button(auth, text="检查已保存配置", command=self.check_profiles).grid(row=2, column=2, padx=5, pady=4, sticky="w")
        ttk.Button(auth, text="导出 CSV", command=self.save_csv).grid(row=2, column=3, padx=5, pady=4, sticky="w")
        self.tree = ttk.Treeview(self.root, columns=("ssid", "bssid", "signal", "channel", "encryption"), show="headings")
        for column, title in zip(self.tree["columns"], ("SSID", "BSSID", "信号", "信道", "加密类型")):
            self.tree.heading(column, text=title)
            self.tree.column(column, width=160)
        self.tree.pack(fill="both", expand=True, padx=10, pady=5)
        ttk.Label(self.root, textvariable=self.status).pack(fill="x", padx=10, pady=4)

    def confirm_authorization(self) -> None:
        scope = AuditScope(include_saved_profiles=True)
        self.authorization = Authorization(self.operator.get(), self.organization.get(), self.purpose.get(), self.evidence.get(), scope)
        decision = self.policy.authorize(self.authorization)
        self.status.set(decision.reason)
        if decision.allowed:
            AuditLog(Path("audit_logs/audit.jsonl")).append("authorization_confirmed", self.authorization.to_dict())
        else:
            messagebox.showwarning("授权信息不完整", decision.reason)

    def _authorized(self) -> bool:
        decision = self.policy.authorize(self.authorization)
        if not decision.allowed:
            messagebox.showwarning("无法执行", decision.reason)
            self.status.set(decision.reason)
            return False
        return True

    def scan(self) -> None:
        if not self._authorized():
            return
        try:
            self.networks = self.reader.scan_networks()
            self.result = AuditResult(networks=self.networks, findings=evaluate_risks(self.networks, []))
            for item in self.tree.get_children():
                self.tree.delete(item)
            for network in self.networks:
                self.tree.insert("", "end", values=(network.ssid or "[隐藏]", network.bssid, network.signal, network.channel, network.encryption))
            self.status.set(f"扫描完成：{len(self.networks)} 个网络；最高风险：{self.result.highest_severity}")
            AuditLog(Path("audit_logs/audit.jsonl")).append("scan_completed", self.result.to_dict())
        except (RuntimeError, OSError, ValueError) as error:
            self.status.set(f"扫描失败：{error}")
            messagebox.showerror("扫描失败", str(error))

    def check_profiles(self) -> None:
        if not self._authorized():
            return
        try:
            profiles = self.reader.saved_profiles()
            self.result.saved_profiles = profiles
            self.result.findings.extend(evaluate_risks([], profiles))
            self.status.set(f"已检查 {len(profiles)} 个保存配置；未读取明文密码。")
            AuditLog(Path("audit_logs/audit.jsonl")).append("profiles_checked", {"count": len(profiles), "findings": [finding.__dict__ for finding in self.result.findings]})
        except (RuntimeError, OSError, ValueError) as error:
            self.status.set(f"配置检查失败：{error}")
            messagebox.showerror("配置检查失败", str(error))

    def save_csv(self) -> None:
        if not self.result.networks and not self.result.findings:
            messagebox.showinfo("无数据", "请先执行扫描或配置检查。")
            return
        destination = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if destination:
            export_csv(self.result, Path(destination))
            self.status.set(f"已导出：{destination}")


def main() -> None:
    if platform.system().lower() != "windows":
        print("此工具仅支持 Windows。")
        return
    root = tk.Tk()
    AuditorApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()

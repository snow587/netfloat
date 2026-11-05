import sys
import os
import time
import psutil
import configparser
from pathlib import Path
from PySide6.QtWidgets import (
    QApplication, QWidget, QLabel, QMenu, QDialog, QVBoxLayout,
    QListWidget, QDialogButtonBox, QMessageBox, QSystemTrayIcon, QStyle,
    QTableWidget, QTableWidgetItem, QHeaderView
)
from PySide6.QtCore import QTimer, Qt
from PySide6.QtGui import QFont, QAction, QIcon
import pythoncom
import win32com.client

from win_packet_monitor import PacketStatsMonitor

# ===================== 路径 =====================
if hasattr(sys, 'frozen'):
    base_dir = Path(os.path.dirname(sys.executable))
    exe_path = Path(sys.executable)
else:
    base_dir = Path(__file__).parent
    exe_path = base_dir / sys.argv[0]
cfg_path = base_dir / "config.ini"
icon_path = base_dir / "icon.ico"


def get_startup_lnk():
    startup = Path(os.environ["USERPROFILE"]) / r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
    return startup / "NetFloat.lnk"


def set_shortcut(target, shortcut_file, workdir):
    pythoncom.CoInitialize()
    try:
        shell = win32com.client.Dispatch("WScript.Shell")
        sc = shell.CreateShortCut(str(shortcut_file))
        sc.TargetPath = str(target)
        sc.WorkingDirectory = str(workdir)
        sc.Save()
    finally:
        pythoncom.CoUninitialize()


class NicSelectDialog(QDialog):
    def __init__(self, nic_list, selected_name, parent=None):
        super().__init__(parent)
        self.setWindowTitle("选择网卡")
        # 弹窗也顺便加上图标
        if icon_path.exists():
            self.setWindowIcon(QIcon(str(icon_path)))
            
        layout = QVBoxLayout()
        self.list_widget = QListWidget()
        for name in nic_list:
            self.list_widget.addItem(name)
            if name == selected_name:
                self.list_widget.setCurrentRow(self.list_widget.count() - 1)
        layout.addWidget(self.list_widget)
        btn_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btn_box.accepted.connect(self.accept)
        btn_box.rejected.connect(self.reject)
        layout.addWidget(btn_box)
        self.setLayout(layout)

    def get_selected(self):
        item = self.list_widget.currentItem()
        return item.text() if item else None


class NumericTableItem(QTableWidgetItem):
    def __init__(self, text, value):
        super().__init__(text)
        self._value = value

    def __lt__(self, other):
        if isinstance(other, NumericTableItem):
            return self._value < other._value
        return super().__lt__(other)


class ProcessMonitorWindow(QWidget):
    """TCP + UDP 按进程实时统计（抓包方案）。"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("进程网络用量（TCP + UDP 抓包统计）")
        self.resize(900, 580)
        self.setAttribute(Qt.WA_DeleteOnClose, False)

        # 1. 设置窗口图标
        if icon_path.exists():
            self.setWindowIcon(QIcon(str(icon_path)))

        # 2. 注入暗色主题 QSS
        self.setStyleSheet("""
            QWidget {
                background-color: #1e1e1e;
                color: #eeeeee;
                font-family: "Microsoft YaHei", sans-serif;
            }
            QTableWidget {
                background-color: #252526;
                alternate-background-color: #2d2d30;
                border: 1px solid #3e3e42;
                gridline-color: #3e3e42;
                selection-background-color: #005a9e;
                selection-color: #ffffff;
                outline: none;
                border-radius: 6px;
            }
            QHeaderView::section {
                background-color: #333337;
                color: #cccccc;
                border: none;
                border-right: 1px solid #3e3e42;
                border-bottom: 1px solid #3e3e42;
                padding: 6px;
                font-weight: bold;
            }
            QTableCornerButton::section {
                background-color: #333337;
                border: none;
                border-bottom: 1px solid #3e3e42;
            }
            QScrollBar:vertical {
                border: none;
                background: #1e1e1e;
                width: 10px;
                margin: 0px;
            }
            QScrollBar::handle:vertical {
                background: #424242;
                min-height: 20px;
                border-radius: 5px;
            }
            QScrollBar::handle:vertical:hover {
                background: #4f4f4f;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                border: none;
                background: none;
            }
            QScrollBar:horizontal {
                border: none;
                background: #1e1e1e;
                height: 10px;
                margin: 0px;
            }
            QScrollBar::handle:horizontal {
                background: #424242;
                min-width: 20px;
                border-radius: 5px;
            }
            QScrollBar::handle:horizontal:hover {
                background: #4f4f4f;
            }
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
                border: none;
                background: none;
            }
        """)

        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(
            ["进程", "实时下载", "实时上传", "总下载", "总上传"]
        )
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        for i in range(1, 5):
            header.setSectionResizeMode(i, QHeaderView.ResizeToContents)
        self.table.setSortingEnabled(True)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False) # 隐藏左侧行号

        self.status_label = QLabel("正在初始化抓包…")
        self.status_label.setFont(QFont("Microsoft YaHei", 9))
        self.status_label.setStyleSheet("color: #888888; padding: 4px; background: transparent;")

        layout = QVBoxLayout()
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)
        layout.addWidget(self.table)
        layout.addWidget(self.status_label)
        self.setLayout(layout)

        self.monitor = PacketStatsMonitor()

        self._last_nic = None
        self._nic_down = 0.0
        self._nic_up = 0.0

        self._pid_names = {}
        self._warned = False

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh)
        self.timer.start(800)

        if not self.monitor.running:
            self._show_start_error()

    def _show_start_error(self):
        if self._warned:
            return
        self._warned = True
        QMessageBox.warning(
            self, "抓包未启动",
            self.monitor.last_error or "抓包初始化失败。",
        )

    def showEvent(self, event):
        self.refresh()
        super().showEvent(event)

    def closeEvent(self, event):
        event.ignore()
        self.hide()

    def refresh(self):
        if not self.monitor.running:
            self.status_label.setText(
                f"❌ 抓包未运行：{self.monitor.last_error or '未知错误'}"
            )
            return

        self.monitor.sample()
        totals, speeds = self.monitor.get_snapshot()

        now = time.monotonic()
        nic = psutil.net_io_counters(pernic=False)
        if self._last_nic is not None:
            lr, ls, lts = self._last_nic
            dt = now - lts
            if 0.05 < dt < 5.0:
                self._nic_down = max(nic.bytes_recv - lr, 0) / dt
                self._nic_up = max(nic.bytes_sent - ls, 0) / dt
        self._last_nic = (nic.bytes_recv, nic.bytes_sent, now)

        rows = []
        for pid in set(totals) | set(speeds):
            d, u = speeds.get(pid, (0.0, 0.0))
            td, tu = totals.get(pid, (0, 0))
            rows.append((self._get_proc_name(pid), pid, d, u, td, tu))

        self._update_table(rows)

        self.status_label.setText(
            f"网卡：↓ {self._fmt_speed(self._nic_down)}  "
            f"↑ {self._fmt_speed(self._nic_up)}    |    "
            f"抓包活跃进程：{len(rows)}    "
            f"（当前仅 IPv4，含 TCP + UDP）"
        )

    def _get_proc_name(self, pid):
        name = self._pid_names.get(pid)
        if name is not None:
            return name
        try:
            name = psutil.Process(pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            name = f"PID {pid}"
        self._pid_names[pid] = name
        return name

    def _update_table(self, rows):
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(rows))
        for i, (name, pid, d, u, td, tu) in enumerate(rows):
            self.table.setItem(i, 0, QTableWidgetItem(f"{name} ({pid})"))
            self.table.setItem(i, 1, NumericTableItem(self._fmt_speed(d), d))
            self.table.setItem(i, 2, NumericTableItem(self._fmt_speed(u), u))
            self.table.setItem(i, 3, NumericTableItem(self._fmt_bytes(td), td))
            self.table.setItem(i, 4, NumericTableItem(self._fmt_bytes(tu), tu))
        self.table.setSortingEnabled(True)

    @staticmethod
    def _fmt_speed(bps):
        if bps < 1024:
            return f"{bps:.0f} B/s"
        elif bps < 1024 * 1024:
            return f"{bps / 1024:.1f} KB/s"
        return f"{bps / 1024 / 1024:.2f} MB/s"

    @staticmethod
    def _fmt_bytes(b):
        if b < 1024:
            return f"{b:.0f} B"
        elif b < 1024 * 1024:
            return f"{b / 1024:.1f} KB"
        elif b < 1024 * 1024 * 1024:
            return f"{b / (1024 * 1024):.1f} MB"
        return f"{b / (1024 * 1024 * 1024):.2f} GB"


class FloatWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint | Qt.Tool)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setAttribute(Qt.WA_NoSystemBackground)

        self.is_vertical = True
        self.alpha_index = 1
        self.alpha_list = [0.45, 0.75, 0.92]
        self.is_on_top = True
        self.autostart = False

        self.pos_x = 200
        self.pos_y = 200
        self.nic_name = ""
        self.base_recv = 0
        self.base_sent = 0
        self.saved_total_down = 0
        self.saved_total_up = 0
        self._last_recv = None
        self._last_sent = None
        self._last_ts = None
        self._proc_window = None

        self.label = QLabel(self)
        self.label.setAlignment(Qt.AlignCenter)
        self.label.setFont(QFont("Microsoft YaHei", 10, QFont.Bold))

        # ===== 托盘 =====
        self.tray_icon = QSystemTrayIcon(self)
        if icon_path.exists():
            self.tray_icon.setIcon(QIcon(str(icon_path)))
        else:
            self.tray_icon.setIcon(
                self.style().standardIcon(QStyle.StandardPixmap.SP_ComputerIcon)
            )
        self.tray_icon.setToolTip("NetFloat 流量悬浮窗")

        tray_menu = QMenu()
        self.action_show = QAction("显示窗口", self)
        self.action_hide = QAction("隐藏窗口", self)
        self.action_proc_tray = QAction("进程网络用量", self)
        self.action_quit = QAction("彻底退出", self)
        self.action_show.triggered.connect(self.show_window)
        self.action_hide.triggered.connect(self.hide)
        self.action_proc_tray.triggered.connect(self.open_process_monitor)
        self.action_quit.triggered.connect(self.force_quit)
        tray_menu.addAction(self.action_show)
        tray_menu.addAction(self.action_hide)
        tray_menu.addAction(self.action_proc_tray)
        tray_menu.addSeparator()
        tray_menu.addAction(self.action_quit)
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.activated.connect(self.on_tray_click)
        self.tray_icon.show()

        # ===== 右键菜单 =====
        self.menu = QMenu(self)
        self.action_topmost = QAction("总在最前", self)
        self.action_topmost.setCheckable(True)
        self.action_topmost.setChecked(True)
        self.action_autostart = QAction("开机自启", self)
        self.action_autostart.setCheckable(True)
        self.action_alpha = QAction("切换透明度", self)
        self.action_layout = QAction("切换横/竖布局", self)
        self.action_nic = QAction("选择网卡", self)
        self.action_reset = QAction("重置流量统计", self)
        self.action_process_monitor = QAction("进程网络用量", self)
        self.action_exit = QAction("隐藏到托盘", self)

        self.action_topmost.triggered.connect(self.toggle_topmost)
        self.action_autostart.triggered.connect(self.toggle_autostart)
        self.action_alpha.triggered.connect(self.switch_alpha)
        self.action_layout.triggered.connect(self.switch_layout)
        self.action_nic.triggered.connect(self.select_nic)
        self.action_reset.triggered.connect(self.reset_traffic)
        self.action_process_monitor.triggered.connect(self.open_process_monitor)
        self.action_exit.triggered.connect(self.hide)

        self.menu.addAction(self.action_topmost)
        self.menu.addAction(self.action_autostart)
        self.menu.addAction(self.action_alpha)
        self.menu.addAction(self.action_layout)
        self.menu.addAction(self.action_nic)
        self.menu.addAction(self.action_reset)
        self.menu.addAction(self.action_process_monitor)
        self.menu.addSeparator()
        self.menu.addAction(self.action_exit)

        self.load_config()
        self.refresh_nic_list()
        self.move(self.pos_x, self.pos_y)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_speed)
        self.timer.start(500)
        self.update_speed()
        self.refresh_style()

        self.persist_timer = QTimer(self)
        self.persist_timer.timeout.connect(self.flush_totals)
        self.persist_timer.start(60_000)

    def open_process_monitor(self):
        if self._proc_window is None:
            self._proc_window = ProcessMonitorWindow()
        self._proc_window.show()
        self._proc_window.raise_()
        self._proc_window.activateWindow()

    def on_tray_click(self, reason):
        if reason == QSystemTrayIcon.Trigger:
            self.hide() if self.isVisible() else self.show_window()

    def show_window(self):
        self.show()
        self.raise_()
        self.activateWindow()

    def force_quit(self):
        self.flush_totals()
        if self._proc_window is not None:
            self._proc_window.timer.stop()
            self._proc_window.monitor.stop()
            self._proc_window.close()
        self.tray_icon.hide()
        self.close()
        QApplication.quit()

    def closeEvent(self, event):
        self.flush_totals()
        event.ignore()
        self.hide()

    def load_config(self):
        cfg = configparser.ConfigParser()
        if cfg_path.exists():
            cfg.read(cfg_path, encoding="utf-8")
            if "main" in cfg:
                self.nic_name = cfg["main"].get("nic", "")
                self.is_vertical = cfg["main"].getboolean("vertical", True)
                self.alpha_index = cfg["main"].getint("alpha", 1)
                self.is_on_top = cfg["main"].getboolean("ontop", True)
                self.autostart = cfg["main"].getboolean("autostart", False)
                self.pos_x = cfg["main"].getint("pos_x", 200)
                self.pos_y = cfg["main"].getint("pos_y", 200)
                self.saved_total_down = cfg["main"].getint("saved_total_down", 0)
                self.saved_total_up = cfg["main"].getint("saved_total_up", 0)
        if not (0 <= self.alpha_index < len(self.alpha_list)):
            self.alpha_index = 1
        self.action_topmost.setChecked(self.is_on_top)
        self.action_autostart.setChecked(self.autostart)

    def save_config(self):
        cfg = configparser.ConfigParser()
        cfg["main"] = {
            "nic": self.nic_name,
            "vertical": str(self.is_vertical),
            "alpha": str(self.alpha_index),
            "ontop": str(self.is_on_top),
            "autostart": str(self.autostart),
            "pos_x": str(self.x()),
            "pos_y": str(self.y()),
            "saved_total_down": str(self.saved_total_down),
            "saved_total_up": str(self.saved_total_up),
        }
        try:
            with open(cfg_path, "w", encoding="utf-8") as f:
                cfg.write(f)
        except Exception as e:
            print(f"[NetFloat] 保存配置失败: {e}")

    def flush_totals(self):
        counters = psutil.net_io_counters(pernic=True)
        if self.nic_name in counters:
            net = counters[self.nic_name]
            self.saved_total_down += net.bytes_recv - self.base_recv
            self.saved_total_up += net.bytes_sent - self.base_sent
            self.base_recv = net.bytes_recv
            self.base_sent = net.bytes_sent
            self.save_config()

    def toggle_autostart(self, checked):
        lnk = get_startup_lnk()
        try:
            if checked:
                set_shortcut(exe_path, lnk, base_dir)
            elif lnk.exists():
                lnk.unlink()
        except Exception as e:
            QMessageBox.warning(self, "失败", f"设置开机自启失败：{e}")
            self.action_autostart.blockSignals(True)
            self.action_autostart.setChecked(not checked)
            self.action_autostart.blockSignals(False)
            return
        self.autostart = checked
        self.save_config()

    def refresh_nic_list(self):
        counters = psutil.net_io_counters(pernic=True)
        nic_list = list(counters.keys())
        if not self.nic_name or self.nic_name not in nic_list:
            self.nic_name = nic_list[0] if nic_list else ""
        if self.nic_name in counters:
            self.base_recv = counters[self.nic_name].bytes_recv
            self.base_sent = counters[self.nic_name].bytes_sent
        self._last_recv = None
        self._last_sent = None
        self._last_ts = None

    def reset_traffic(self):
        counters = psutil.net_io_counters(pernic=True)
        if self.nic_name in counters:
            net = counters[self.nic_name]
            self.saved_total_down = 0
            self.saved_total_up = 0
            self.base_recv = net.bytes_recv
            self.base_sent = net.bytes_sent
            self._last_recv = None
            self._last_sent = None
            self._last_ts = None
            self.save_config()

    def select_nic(self):
        counters = psutil.net_io_counters(pernic=True)
        dlg = NicSelectDialog(list(counters.keys()), self.nic_name, self)
        if dlg.exec():
            new = dlg.get_selected()
            if new and new != self.nic_name:
                self.saved_total_down = 0
                self.saved_total_up = 0
                self.nic_name = new
                self.refresh_nic_list()
                self.save_config()

    def toggle_topmost(self):
        pos = self.pos()
        self.is_on_top = not self.is_on_top
        flags = Qt.FramelessWindowHint | Qt.Tool
        if self.is_on_top:
            flags |= Qt.WindowStaysOnTopHint
        self.setWindowFlags(flags)
        self.show()
        self.move(pos)
        self.save_config()

    def refresh_style(self):
        a = self.alpha_list[self.alpha_index]
        self.label.setStyleSheet(f"""
            QLabel {{
                background-color: rgba(20, 20, 20, {a});
                color: #eeeeee;
                padding: 8px 12px;
                border-radius: 10px;
            }}
        """)

    def switch_alpha(self):
        self.alpha_index = (self.alpha_index + 1) % len(self.alpha_list)
        self.refresh_style()
        self.save_config()

    def switch_layout(self):
        self.is_vertical = not self.is_vertical
        self.update_speed()
        self.save_config()

    def format_speed(self, bps):
        if bps < 1024:
            return f"{bps:.1f} B/s"
        elif bps < 1024 * 1024:
            return f"{bps / 1024:.1f} KB/s"
        return f"{bps / 1024 / 1024:.2f} MB/s"

    def format_total(self, byte):
        if byte < 1024:
            return f"{byte:.1f} B"
        elif byte < 1024 * 1024:
            return f"{byte / 1024:.1f} KB"
        elif byte < 1024 * 1024 * 1024:
            return f"{byte / (1024 * 1024):.2f} MB"
        return f"{byte / (1024 * 1024 * 1024):.2f} GB"

    def update_speed(self):
        counters = psutil.net_io_counters(pernic=True)
        if self.nic_name not in counters:
            self.label.setText("网卡异常")
            self.label.adjustSize()
            self.resize(self.label.size())
            self._last_recv = self._last_sent = self._last_ts = None
            return

        net = counters[self.nic_name]
        now = time.monotonic()
        session_down = net.bytes_recv - self.base_recv
        session_up = net.bytes_sent - self.base_sent
        total_down = self.saved_total_down + session_down
        total_up = self.saved_total_up + session_up

        if self._last_recv is None or self._last_ts is None:
            speed_down = speed_up = 0.0
        else:
            dt = max(now - self._last_ts, 1e-6)
            speed_down = max(net.bytes_recv - self._last_recv, 0) / dt
            speed_up = max(net.bytes_sent - self._last_sent, 0) / dt

        self._last_recv = net.bytes_recv
        self._last_sent = net.bytes_sent
        self._last_ts = now

        t1 = f'<span style="color:#4cc9f0">↓ {self.format_speed(speed_down)}</span>'
        t2 = f'<span style="color:#f77f00">↑ {self.format_speed(speed_up)}</span>'
        t3 = f'<span style="color:#73d2de">总下：{self.format_total(total_down)}</span>'
        t4 = f'<span style="color:#ffb703">总上：{self.format_total(total_up)}</span>'

        self.label.setText(
            f"{t1}<br>{t2}<br>{t3}<br>{t4}" if self.is_vertical
            else f"{t1} {t2}<br>{t3} {t4}"
        )
        self.label.adjustSize()
        self.resize(self.label.size())

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.windowHandle().startSystemMove()
            event.accept()
        elif event.button() == Qt.RightButton:
            self.action_topmost.setChecked(self.is_on_top)
            self.action_autostart.setChecked(self.autostart)
            self.menu.exec(event.globalPosition().toPoint())
            event.accept()

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.LeftButton:
            QTimer.singleShot(60, self.save_config)

    def enterEvent(self, event):
        self.label.setStyleSheet("""
            QLabel {
                background-color: rgba(20, 20, 20, 0.88);
                color: #ffffff;
                padding: 8px 12px;
                border-radius: 10px;
            }
        """)

    def leaveEvent(self, event):
        self.refresh_style()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    # 【重要】设置全局应用图标，统一任务栏图标
    if icon_path.exists():
        app.setWindowIcon(QIcon(str(icon_path)))

    if not QSystemTrayIcon.isSystemTrayAvailable():
        QMessageBox.critical(None, "错误", "当前系统不支持托盘图标！")
        sys.exit(1)
        
    QApplication.setQuitOnLastWindowClosed(False)
    w = FloatWindow()
    w.show()
    sys.exit(app.exec())
# win_packet_monitor.py
"""
基于 Npcap + scapy 的按进程网络统计。

覆盖 TCP 和 UDP。
依赖：
  1. 安装 Npcap（https://npcap.com/），安装时勾选 "WinPcap API-compatible Mode"
  2. 以管理员身份运行

原理：
  - 从 Npcap 抓 IPv4 包
  - 定期用 GetExtendedTcpTable / GetExtendedUdpTable 构建 (本地端点) -> PID 映射
  - 每个包按方向 & PID 累计，速度由 sample() 差分得到
"""

import socket
import struct
import threading
import time
import ctypes
from ctypes import wintypes, byref, sizeof, create_string_buffer, POINTER

import psutil

try:
    from scapy.all import AsyncSniffer, IP, TCP, UDP, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# ============================================================
# IP Helper API（反查 PID）
# ============================================================
iphlpapi = ctypes.WinDLL("iphlpapi.dll", use_last_error=True)

AF_INET = 2
TCP_TABLE_OWNER_PID_ALL = 5
UDP_TABLE_OWNER_PID = 1
ERROR_INSUFFICIENT_BUFFER = 122
MIB_TCP_STATE_LISTEN = 2


class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwState", wintypes.DWORD),
        ("dwLocalAddr", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("dwRemoteAddr", wintypes.DWORD),
        ("dwRemotePort", wintypes.DWORD),
        ("dwOwningPid", wintypes.DWORD),
    ]


class MIB_UDPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwLocalAddr", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("dwOwningPid", wintypes.DWORD),
    ]


iphlpapi.GetExtendedTcpTable.argtypes = [
    ctypes.c_void_p, POINTER(wintypes.DWORD), wintypes.BOOL,
    wintypes.ULONG, ctypes.c_int, wintypes.ULONG,
]
iphlpapi.GetExtendedTcpTable.restype = wintypes.ULONG

iphlpapi.GetExtendedUdpTable.argtypes = [
    ctypes.c_void_p, POINTER(wintypes.DWORD), wintypes.BOOL,
    wintypes.ULONG, ctypes.c_int, wintypes.ULONG,
]
iphlpapi.GetExtendedUdpTable.restype = wintypes.ULONG


def _ip_str(dw):
    return socket.inet_ntoa(struct.pack("<I", dw))


def _port_val(dw):
    return socket.ntohs(dw & 0xFFFF)


def _enum_tcp():
    size = wintypes.DWORD(0)
    ret = iphlpapi.GetExtendedTcpTable(
        None, byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0
    )
    if ret != ERROR_INSUFFICIENT_BUFFER:
        return []
    buf = create_string_buffer(size.value)
    ret = iphlpapi.GetExtendedTcpTable(
        buf, byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0
    )
    if ret != 0:
        return []
    n = ctypes.cast(buf, POINTER(wintypes.DWORD))[0]
    if n == 0:
        return []
    return list((MIB_TCPROW_OWNER_PID * n).from_address(ctypes.addressof(buf) + 4))


def _enum_udp():
    size = wintypes.DWORD(0)
    ret = iphlpapi.GetExtendedUdpTable(
        None, byref(size), False, AF_INET, UDP_TABLE_OWNER_PID, 0
    )
    if ret != ERROR_INSUFFICIENT_BUFFER:
        return []
    buf = create_string_buffer(size.value)
    ret = iphlpapi.GetExtendedUdpTable(
        buf, byref(size), False, AF_INET, UDP_TABLE_OWNER_PID, 0
    )
    if ret != 0:
        return []
    n = ctypes.cast(buf, POINTER(wintypes.DWORD))[0]
    if n == 0:
        return []
    return list((MIB_UDPROW_OWNER_PID * n).from_address(ctypes.addressof(buf) + 4))


class PidResolver:
    """定期刷新 (本地端点) -> PID 映射。"""

    def __init__(self, interval=1.0):
        self._interval = interval
        self._lock = threading.Lock()
        self._tcp = {}  # (l_ip, l_port, r_ip, r_port) -> pid
        self._udp = {}  # (l_ip, l_port) -> pid
        self._last = 0.0

    def refresh(self, force=False):
        now = time.monotonic()
        if not force and now - self._last < self._interval:
            return
        self._last = now

        tcp = {}
        for row in _enum_tcp():
            if row.dwState == MIB_TCP_STATE_LISTEN:
                continue
            pid = row.dwOwningPid
            if pid == 0:
                continue
            key = (
                _ip_str(row.dwLocalAddr), _port_val(row.dwLocalPort),
                _ip_str(row.dwRemoteAddr), _port_val(row.dwRemotePort),
            )
            tcp[key] = pid

        udp = {}
        for row in _enum_udp():
            pid = row.dwOwningPid
            if pid == 0:
                continue
            key = (_ip_str(row.dwLocalAddr), _port_val(row.dwLocalPort))
            udp.setdefault(key, pid)

        with self._lock:
            self._tcp = tcp
            self._udp = udp

    def lookup_tcp(self, l_ip, l_port, r_ip, r_port):
        with self._lock:
            return self._tcp.get((l_ip, l_port, r_ip, r_port))

    def lookup_udp(self, l_ip, l_port):
        with self._lock:
            pid = self._udp.get((l_ip, l_port))
            if pid is not None:
                return pid
            # UDP 常绑 0.0.0.0，回退查通配
            return self._udp.get(("0.0.0.0", l_port))


def _get_local_ips():
    ips = set()
    try:
        for addrs in psutil.net_if_addrs().values():
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    ips.add(addr.address)
    except Exception:
        pass
    return ips


# ============================================================
# 抓包统计
# ============================================================
class PacketStatsMonitor:
    def __init__(self):
        self._lock = threading.Lock()
        self._totals = {}            # pid -> [in_bytes, out_bytes]
        self._speeds = {}            # pid -> (speed_in, speed_out)
        self._last_sample = {}       # pid -> (in, out)
        self._last_ts = None

        self._local_ips = _get_local_ips()
        self._local_ips_ts = time.monotonic()
        self._resolver = PidResolver(interval=1.0)

        self._sniffer = None
        self._running = False
        self.last_error = None

        self.start()

    # ---------- 生命周期 ----------
    def start(self):
        if self._running:
            return
        if not SCAPY_AVAILABLE:
            self.last_error = "未安装 scapy（pip install scapy）"
            return

        # 优先使用 Npcap 后端；失败则退回 raw socket
        try:
            conf.use_pcap = True
        except Exception:
            pass

        try:
            self._sniffer = AsyncSniffer(
                filter="ip and not net 127.0.0.0/8",
                prn=self._on_packet,
                store=False,
                promisc=False,
            )
            self._sniffer.start()
            self._running = True
            self.last_error = None
        except Exception as e:
            self._running = False
            self._sniffer = None
            self.last_error = (
                f"抓包启动失败: {e}\n"
                "请确认：1) 已安装 Npcap（勾选 WinPcap API-compatible Mode）"
                " 2) 以管理员身份运行程序"
            )

    def stop(self):
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None
        self._running = False

    @property
    def running(self):
        return self._running

    # ---------- 包处理 ----------
    def _on_packet(self, pkt):
        try:
            self._process(pkt)
        except Exception:
            pass

    def _process(self, pkt):
        if IP not in pkt:
            return
        ip = pkt[IP]
        src, dst = ip.src, ip.dst
        length = len(ip)  # 整个 IPv4 包长（含 IP 头）

        # 30s 刷一次本机 IP 列表（DHCP 变化）
        now = time.monotonic()
        if now - self._local_ips_ts > 30:
            self._local_ips = _get_local_ips()
            self._local_ips_ts = now

        if src in self._local_ips:
            direction = "out"
            local_ip, remote_ip = src, dst
        elif dst in self._local_ips:
            direction = "in"
            local_ip, remote_ip = dst, src
        else:
            return  # 混杂模式看到的第三方流量，丢弃

        if TCP in pkt:
            t = pkt[TCP]
            if direction == "out":
                l_port, r_port = t.sport, t.dport
            else:
                l_port, r_port = t.dport, t.sport
            pid = self._resolver.lookup_tcp(local_ip, l_port, remote_ip, r_port)
        elif UDP in pkt:
            u = pkt[UDP]
            l_port = u.sport if direction == "out" else u.dport
            pid = self._resolver.lookup_udp(local_ip, l_port)
        else:
            return

        if not pid:
            return

        with self._lock:
            entry = self._totals.setdefault(pid, [0, 0])
            if direction == "in":
                entry[0] += length
            else:
                entry[1] += length

    # ---------- 采样 / 快照 ----------
    def sample(self):
        self._resolver.refresh()
        now = time.monotonic()
        with self._lock:
            snap = {pid: (v[0], v[1]) for pid, v in self._totals.items()}

        dt = (now - self._last_ts) if self._last_ts else 0.0
        speeds = {}
        if dt > 0.05:
            for pid, (i, o) in snap.items():
                if pid in self._last_sample:
                    pi, po = self._last_sample[pid]
                    di, do = i - pi, o - po
                    if di >= 0 and do >= 0:
                        speeds[pid] = (di / dt, do / dt)
        self._last_sample = snap
        self._last_ts = now

        with self._lock:
            self._speeds = speeds

    def get_snapshot(self):
        with self._lock:
            return dict(self._totals), dict(self._speeds)
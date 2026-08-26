# -*- coding: utf-8 -*-
"""
固定数据流模拟器（MVP 演示版）
--------------------------------
按预置剧本（时间线）模拟"安全日志事件流"的实时产生，
其中穿插了 4 段攻击剧情，用于演示检测引擎在特定时刻触发报警。

剧本时间线（模拟时间，秒）：
  t=0    ~ t=8    : 正常业务流量（SSH 登录 / HTTP 请求 / DNS 查询）
  t=8    ~ t=26   : 攻击一：SSH 暴力破解（203.0.113.9 -> 192.168.5.11）
  t=26   ~ t=40   : 攻击二：端口扫描（198.51.100.77 -> 192.168.5.11）
  t=40   ~ t=56   : 攻击三：爆破成功后上传 Webshell
  t=56   ~ t=68   : 攻击四：已知恶意 IP 漏洞利用 + 疑似数据外传
  t=68   ~ t=75   : 恢复正常，演示收尾

说明：
  - 所有数据均为固定/确定性生成（随机数使用固定种子），保证演示可复现。
  - speed 参数用于控制播放速度（模拟时间 / 真实时间）。
"""
import itertools
import random
import threading
import time

# ------------------------- 剧本中使用的关键 IP -------------------------
BRUTE_IP   = "203.0.113.9"    # 暴力破解攻击者（TEST-NET-3 保留地址）
SCAN_IP    = "198.51.100.77"  # 端口扫描攻击者（TEST-NET-2 保留地址）
MAL_IP     = "45.155.205.233"  # 已知恶意 IP（情报库命中）
TARGET     = "192.168.5.11"    # 受攻击的靶机
WEB_HOST   = "192.168.5.11"
SERVER     = "192.168.5.10"
CLIENT     = "192.168.5.13"

FINISH_AT = 75.0  # 演示总时长（模拟时间）

# ------------------------- 事件构造工具 -------------------------
def _fmt_time(t):
    m, s = divmod(int(t), 60)
    return "%02d:%02d" % (m, s)


class EventSimulator(threading.Thread):
    """在后台线程中按剧本节奏产生事件，并逐条回调 on_event(event)。"""

    def __init__(self, speed=1.0, on_event=None):
        super().__init__(daemon=True)
        self.speed = max(0.1, float(speed))
        self.on_event = on_event
        self._rng = random.Random(20260826)          # 固定种子 -> 固定数据
        self._sid = itertools.count(1)
        self._t = 0.0                                 # 当前模拟时间
        self._lock = threading.Lock()

    # ---------------- 事件基础字段 ----------------
    def _finalize(self, evt):
        evt["id"] = next(self._sid)
        evt["t"] = round(self._t, 2)
        evt["time"] = _fmt_time(self._t)
        return evt

    # ---------------- 正常流量生成 ----------------
    def _gen_background(self):
        r = self._rng
        i = r.randint(0, 2)
        if i == 0:
            return {
                "event_type": "ssh_login", "severity": "info",
                "source_ip": "10.0.0.%d" % r.randint(2, 30),
                "target_ip": SERVER, "target_port": 22,
                "message": "SSH 登录成功 user=secuser",
            }
        if i == 1:
            return {
                "event_type": "http_request", "severity": "info",
                "source_ip": "8.%d.%d.%d" % (r.randint(1, 200), r.randint(1, 255), r.randint(1, 255)),
                "target_ip": WEB_HOST, "target_port": 80,
                "message": "GET /api/status -> 200",
            }
        return {
            "event_type": "dns_query", "severity": "info",
            "source_ip": SERVER,
            "target_ip": "192.168.5.1", "target_port": 53,
            "message": "DNS 查询 %s" % r.choice(["update.example.com", "cdn.example.com", "log.example.com"]),
        }

    # ---------------- 攻击事件生成 ----------------
    def _attack_events(self):
        """返回 [(模拟时间, event_factory), ...] 的有序剧本事件。"""
        evs = []
        usernames = ["root", "admin", "oracle", "postgres", "ubuntu"]
        ports = [22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433,
                 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 9200, 9300,
                 11211, 27017, 28017, 389, 636, 161, 512, 513, 514, 2049,
                 49152, 49153, 49154, 49155, 49156, 49157]

        # 攻击一：SSH 暴力破解（t=8~26，间隔约 1.6s）
        t = 8.0
        for i in range(11):
            u = usernames[i % len(usernames)]
            evs.append((t, lambda u=u: {
                "event_type": "auth_failure", "severity": "low",
                "source_ip": BRUTE_IP, "target_ip": TARGET, "target_port": 22,
                "message": "SSH 认证失败 user=%s 密码错误" % u,
            }))
            t += 1.6

        # 攻击二：端口扫描（t=26~40，间隔 0.25s，按固定端口序列）
        t = 26.0
        for i in range(56):
            p = ports[i % len(ports)]
            evs.append((t, lambda p=p: {
                "event_type": "port_probe", "severity": "medium",
                "source_ip": SCAN_IP, "target_ip": TARGET, "target_port": p,
                "message": "TCP 探测端口 %d 无响应" % p,
            }))
            t += 0.25

        # 攻击三：爆破成功后上传 Webshell（t=40~56）
        evs.append((40.0, lambda: {
            "event_type": "ssh_login", "severity": "high",
            "source_ip": BRUTE_IP, "target_ip": TARGET, "target_port": 22,
            "message": "SSH 登录成功 user=admin（来源为暴力破解攻击者）",
        }))
        t = 41.0
        for i in range(3):
            evs.append((t, lambda: {
                "event_type": "web_upload", "severity": "high",
                "source_ip": BRUTE_IP, "target_ip": WEB_HOST, "target_port": 80,
                "message": "上传文件 uploads/shell.php 大小 2468B",
            }))
            t += 1.2
        evs.append((45.0, lambda: {
            "event_type": "web_shell", "severity": "critical",
            "source_ip": BRUTE_IP, "target_ip": WEB_HOST, "target_port": 80,
            "message": "Webshell 命令执行 cmd=whoami",
        }))

        # 攻击四：已知恶意 IP + 数据外传（t=56~68）
        t = 56.0
        for i in range(14):
            evs.append((t, lambda: {
                "event_type": "web_exploit", "severity": "critical",
                "source_ip": MAL_IP, "target_ip": CLIENT, "target_port": 8080,
                "message": "尝试利用 /manager/html 漏洞（CVE-2017-12615 特征命中）",
            }))
            t += 0.8
        t = 56.0
        for i in range(12):
            evs.append((t, lambda: {
                "event_type": "data_exfil", "severity": "high",
                "source_ip": WEB_HOST, "target_ip": BRUTE_IP, "target_port": 443,
                "message": "外联数据包 %dKB 目标:%s" % (self._rng.randint(80, 500), BRUTE_IP),
            }))
            t += 0.5

        evs.sort(key=lambda x: x[0])
        return evs

    # ---------------- 主循环 ----------------
    def run(self):
        attack_q = self._attack_events()
        bg_next = self._rng.uniform(0.5, 1.3)   # 首个正常事件时间

        while self._t < FINISH_AT:
            next_attack = attack_q[0][0] if attack_q else float("inf")
            use_attack = next_attack <= bg_next
            t_next = next_attack if use_attack else bg_next

            wait = max(0.0, t_next - self._t)
            if wait > 0:
                time.sleep(wait / self.speed)
            self._t = t_next

            if use_attack:
                _, factory = attack_q.pop(0)
                evt = factory()
            else:
                evt = self._gen_background()
                bg_next = self._t + self._rng.uniform(0.5, 1.3)

            if self.on_event:
                self.on_event(self._finalize(evt))
            else:
                break

# -*- coding: utf-8 -*-
"""
规则检测引擎（MVP 演示版）
---------------------------
对模拟器产生的每条事件做实时规则匹配（滑动时间窗口统计），
命中规则后生成安全告警 Alert。当前内置 5 条规则：

  1. SSH 暴力破解      : 同一来源 15s 内认证失败 >= 5 次
  2. 端口扫描          : 同一来源 15s 内探测的不同端口 >= 12 个
  3. 暴力破解成功      : 来源此前 30s 内失败 >= 5 次后又登录成功
  4. 已知恶意 IP       : 来源 IP 命中情报黑名单
  5. 疑似数据外传      : 同一主机 15s 内高频外联数据包 >= 6 次

每条规则带冷却时间（cooldown），避免同一攻击持续刷屏告警。
"""
from dataclasses import dataclass, field

# 情报库：已知恶意 IP 黑名单（演示用固定数据）
BLACKLIST_IPS = {"45.155.205.233"}

WINDOW = 15.0       # 统计滑动窗口（秒）
COOLDOWN = 30.0     # 规则冷却（秒）


@dataclass
class Alert:
    seq: int
    t: float
    time: str
    rule: str
    title: str
    severity: str            # low / medium / high / critical
    source_ip: str
    target_ip: str
    detail: str
    suggestion: str


@dataclass
class DetectionEngine:
    _seq: int = 0
    _events: list = field(default_factory=list)          # 窗口内事件
    _fail_history: dict = field(default_factory=dict)    # src -> [(t,), ...] 近 60s 认证失败
    _cooldown: dict = field(default_factory=dict)        # (rule, key) -> 冷却截止时间

    # ---------------- 工具方法 ----------------
    def _prune(self, t):
        cutoff = t - WINDOW
        self._events = [e for e in self._events if e["t"] >= cutoff]
        for src in list(self._fail_history):
            self._fail_history[src] = [x for x in self._fail_history[src] if x > t - 60]
            if not self._fail_history[src]:
                del self._fail_history[src]

    def _window_events(self, src=None, evtype=None):
        out = self._events
        if src is not None:
            out = [e for e in out if e["source_ip"] == src]
        if evtype is not None:
            out = [e for e in out if e["event_type"] == evtype]
        return out

    def _can_fire(self, rule, key, t):
        k = (rule, key)
        if self._cooldown.get(k, -1.0) > t:
            return False
        self._cooldown[k] = t + COOLDOWN
        return True

    def _new_alert(self, t, rule, title, severity, src, dst, detail, suggestion):
        self._seq += 1
        m, s = divmod(int(t), 60)
        return Alert(
            seq=self._seq, t=t, time="%02d:%02d" % (m, s), rule=rule,
            title=title, severity=severity,
            source_ip=src, target_ip=dst, detail=detail, suggestion=suggestion,
        )

    # ---------------- 规则实现 ----------------
    def _rule_bruteforce(self, evt, t):
        if evt["event_type"] != "auth_failure":
            return None
        src = evt["source_ip"]
        self._fail_history.setdefault(src, []).append(t)
        if len(self._window_events(src=src, evtype="auth_failure")) >= 5 and \
                self._can_fire("bruteforce", src, t):
            return self._new_alert(
                t, "bruteforce", "SSH 暴力破解攻击", "critical", src, evt["target_ip"],
                "来源 %s 在 15 秒内认证失败达到 %d 次" % (src, len(self._window_events(src=src, evtype="auth_failure"))),
                "立即封禁来源 IP，开启 fail2ban/访问限流，改用密钥登录并强化口令策略。")
        return None

    def _rule_portscan(self, evt, t):
        if evt["event_type"] != "port_probe":
            return None
        src = evt["source_ip"]
        probed = {e["target_port"] for e in self._window_events(src=src, evtype="port_probe")}
        if len(probed) >= 12 and self._can_fire("portscan", src, t):
            return self._new_alert(
                t, "portscan", "端口扫描探测", "high", src, evt["target_ip"],
                "来源 %s 在 15 秒内扫描了 %d 个不同端口" % (src, len(probed)),
                "在边界防火墙封禁扫描来源，关闭未开放端口，启用入侵检测防护规则。")
        return None

    def _rule_brute_success(self, evt, t):
        if evt["event_type"] != "ssh_login":
            return None
        src = evt["source_ip"]
        fails = [x for x in self._fail_history.get(src, []) if x > t - 30]
        if len(fails) >= 5 and self._can_fire("brute_success", src, t):
            return self._new_alert(
                t, "brute_success", "暴力破解成功-可疑登录", "critical", src, evt["target_ip"],
                "来源 %s 在 30 秒内失败 %d 次后登录成功，疑似爆破得手" % (src, len(fails)),
                "强制下线该会话，重置相关账号口令，排查后门、挖矿木马与持久化行为。")
        return None

    def _rule_blacklist(self, evt, t):
        src = evt["source_ip"]
        if src in BLACKLIST_IPS and self._can_fire("blacklist", src, t):
            return self._new_alert(
                t, "blacklist", "命中已知恶意 IP 情报", "critical", src, evt["target_ip"],
                "来源 %s 命中威胁情报黑名单，正在发起漏洞利用" % src,
                "边界防火墙立即封禁该 IP，追溯内网横向移动与受害范围。")
        return None

    def _rule_data_exfil(self, evt, t):
        if evt["event_type"] != "data_exfil":
            return None
        src = evt["source_ip"]
        n = len(self._window_events(src=src, evtype="data_exfil"))
        if n >= 6 and self._can_fire("data_exfil", src, t):
            return self._new_alert(
                t, "data_exfil", "疑似数据外传", "high", src, evt["target_ip"],
                "主机 %s 在 15 秒内向外部发送了 %d 次大流量数据包" % (src, n),
                "阻断异常外联地址，核查泄露数据范围，升级为安全事件进入处置流程。")
        return None

    # ---------------- 对外入口 ----------------
    def feed(self, evt):
        """输入一条事件，返回命中的告警列表。"""
        t = evt["t"]
        self._events.append(evt)
        self._prune(t)
        alerts = []
        for fn in (self._rule_bruteforce, self._rule_portscan,
                   self._rule_brute_success, self._rule_blacklist,
                   self._rule_data_exfil):
            a = fn(evt, t)
            if a:
                alerts.append(a)
        return alerts

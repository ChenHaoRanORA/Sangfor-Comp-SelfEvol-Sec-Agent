# -*- coding: utf-8 -*-
"""
MVP 演示入口：自进化网络安全智能体 · 实时监测演示
====================================================
流程：固定数据流模拟器 -> 规则检测引擎 -> 实时报警（控制台 + 网页看板）

运行方式：
    python src/demo/main.py                 # 默认 2x 速度，端口 8000
    python src/demo/main.py --speed 1       # 1x 真实节奏（约 75 秒）
    python src/demo/main.py --speed 4       # 4x 加速（约 19 秒）
    python src/demo/main.py --port 8080     # 自定义端口
    python src/demo/main.py --no-browser    # 不自动打开浏览器

浏览器访问：http://127.0.0.1:8000
"""
import argparse
import os
import sys
import time
import webbrowser

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from data_simulator import EventSimulator   # noqa: E402
from detection import DetectionEngine       # noqa: E402
from server import start_server             # noqa: E402

# ------------------------- 控制台彩色输出 -------------------------
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

if os.name == "nt":
    try:
        import ctypes
        ctypes.windll.kernel32.SetConsoleMode(ctypes.windll.kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass

SEV_COLOR = {
    "info": "\033[36m", "low": "\033[32m", "medium": "\033[33m",
    "high": "\033[95m", "critical": "\033[91m", "cyan": "\033[36m",
}
RESET = "\033[0m"
BOLD = "\033[1m"


def cprint(text, color=None, bold=False):
    s = (BOLD if bold else "") + (SEV_COLOR.get(color, "") if color else "") + text + RESET
    print(s)


def banner():
    cprint("=" * 68, "info", True)
    cprint("  自进化网络安全智能体 · 实时监测演示（MVP）", "cyan", True)
    cprint("  剧本: 正常流量 -> SSH爆破 -> 端口扫描 -> Webshell -> 恶意IP/数据外传", "info")
    cprint("  浏览器打开 http://127.0.0.1:%d 观看实时看板" % PORT, "info")
    cprint("=" * 68, "info", True)


def main():
    global PORT
    parser = argparse.ArgumentParser(description="自进化安全智能体 MVP 演示")
    parser.add_argument("--speed", type=float, default=2.0, help="播放速度倍率（默认 2.0）")
    parser.add_argument("--port", type=int, default=8000, help="看板端口（默认 8000）")
    parser.add_argument("--host", type=str, default="127.0.0.1")
    parser.add_argument("--no-browser", action="store_true", help="不自动打开浏览器")
    args = parser.parse_args()
    PORT = args.port

    banner()

    # 启动服务器 + 发布中心
    httpd, broadcaster = start_server(args.host, args.port)

    if not args.no_browser:
        webbrowser.open("http://%s:%d" % (args.host, args.port))

    # 检测引擎 + 数据模拟器
    engine = DetectionEngine()
    alerts = []
    event_count = {"n": 0}

    def _on_event(evt):
        event_count["n"] += 1
        # 控制台：仅高亮可疑事件
        if evt["severity"] in ("high", "critical"):
            cprint("[%s] %s %s -> %s  %s" % (evt["time"], evt["event_type"],
                                             evt["source_ip"], evt["target_ip"], evt["message"]),
                   evt["severity"])
        broadcaster.publish({"kind": "event", "data": evt})
        # 规则检测 -> 报警
        for a in engine.feed(evt):
            alerts.append(a)
            broadcaster.publish({"kind": "alert", "data": a.__dict__})
            cprint("=" * 68, "critical", True)
            cprint("  \u26A0 [%s] %s" % (a.severity.upper(), a.title), "critical", True)
            cprint("    时间: %s | 来源: %s | 目标: %s | 规则: %s" % (a.time, a.source_ip, a.target_ip, a.rule), "critical")
            cprint("    详情: %s" % a.detail, "critical")
            cprint("    建议: %s" % a.suggestion, "critical")
            cprint("=" * 68, "critical", True)

    simulator = EventSimulator(speed=args.speed, on_event=_on_event)

    simulator.start()

    try:
        simulator.join()
    except KeyboardInterrupt:
        cprint("\n\033[33m已手动中断\033[0m")
        httpd.shutdown()
        return

    # 演示结束
    broadcaster.publish({"kind": "finish"})
    cprint("\n" + "=" * 68, "info", True)
    cprint("  演示结束：共监测事件 %d 条，产生告警 %d 条" % (event_count["n"], len(alerts)), "info", True)
    for a in alerts:
        cprint("    - [%s] %s（%s -> %s）" % (a.time, a.title, a.source_ip, a.target_ip), a.severity)
    cprint("=" * 68, "info", True)
    cprint("  看板已暂停推流，按 Ctrl+C 退出。", "info")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        httpd.shutdown()


if __name__ == "__main__":
    main()

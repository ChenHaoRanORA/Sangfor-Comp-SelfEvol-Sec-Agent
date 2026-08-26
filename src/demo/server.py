# -*- coding: utf-8 -*-
"""
轻量实时推送服务器（MVP 演示版）
---------------------------------
基于 Python 标准库 http.server 实现：
  - GET /        返回监测看板页面 static/index.html
  - GET /events  以 SSE(Server-Sent Events) 推送实时事件与告警

Broadcaster 作为简单的发布/订阅中心，事件与告警统一以 JSON 推送，
前端通过 EventSource 订阅即可。
"""
import json
import os
import queue
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")


class Broadcaster:
    """线程安全的发布/订阅中心。"""

    def __init__(self, maxsize=2000):
        self._subs = set()
        self._lock = threading.Lock()
        self._maxsize = maxsize

    def subscribe(self):
        q = queue.Queue(maxsize=self._maxsize)
        with self._lock:
            self._subs.add(q)
        return q

    def unsubscribe(self, q):
        with self._lock:
            self._subs.discard(q)

    def publish(self, obj):
        payload = json.dumps(obj, ensure_ascii=False)
        with self._lock:
            dead = []
            for q in self._subs:
                try:
                    q.put_nowait(payload)
                except queue.Full:
                    dead.append(q)
            for q in dead:
                self._subs.discard(q)


def make_handler(broadcaster):
    """生成请求处理器（闭包注入 broadcaster）。"""

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):  # 静默默认访问日志
            pass

        def _send(self, code, ctype, body, extra=None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = self.path.split("?")[0]
            if path in ("/", "/index.html"):
                f = os.path.join(STATIC_DIR, "index.html")
                with open(f, "rb") as fp:
                    self._send(200, "text/html; charset=utf-8", fp.read())
            elif path == "/favicon.ico":
                self._send(204, "image/x-icon", b"")
            elif path == "/events":
                self._serve_sse()
            else:
                self._send(404, "text/plain; charset=utf-8", b"not found")

        def _serve_sse(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            q = broadcaster.subscribe()
            try:
                while True:
                    try:
                        payload = q.get(timeout=15)
                    except queue.Empty:
                        self.wfile.write(b": keepalive\n\n")
                        self.wfile.flush()
                        continue
                    self.wfile.write(("data: " + payload + "\n\n").encode("utf-8"))
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                pass
            finally:
                broadcaster.unsubscribe(q)

    return Handler


def start_server(host="127.0.0.1", port=8000):
    """启动 HTTP 服务器（后台线程），返回 server 对象。"""
    broadcaster = Broadcaster()
    httpd = ThreadingHTTPServer((host, port), make_handler(broadcaster))
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, broadcaster

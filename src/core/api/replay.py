# -*- coding: utf-8 -*-
"""演示回放中心：把 Agent 事件按时间压缩节奏广播给所有 WebSocket 客户端。

- 数据源按 ts 升序排队，每个事件之间固定间隔（events/sec 可配，默认按总量压到 ~90 秒）；
- 推送给前端的消息与 REST 一致：{kind:'alert', alert:<前端告警>}；
- 播完发 {kind:'done', stats}，可选 --loop 循环播放便于展示。
"""
from __future__ import annotations

import asyncio
import json
import math
from typing import Optional

from .demo import DemoSource

MSG = "text"


class ReplayHub:
    def __init__(self, source: DemoSource, eps: float = 0, loop: bool = False):
        self.ds = source
        self.queue = source.rows_asc
        self.total = len(self.queue)
        self.eps = eps or float(max(2, math.ceil(self.total / 90)))
        self.interval = 1.0 / self.eps
        self.loop = loop
        self.idx = 0
        self.done = False
        self._clients: set = set()
        self._task: Optional[asyncio.Task] = None

    # ---------- 客户端管理 ----------
    def attach(self, ws) -> None:
        self._clients.add(ws)

    def detach(self, ws) -> None:
        self._clients.discard(ws)

    async def _broadcast(self, msg: dict) -> None:
        text = json.dumps(msg, ensure_ascii=False, default=str)
        for ws in list(self._clients):
            try:
                await ws.send_text(text)
            except Exception:  # noqa: BLE001 连接断开则剔除
                self._clients.discard(ws)

    @property
    def stats(self) -> dict:
        sl = self.queue[:self.idx]
        tp = sum(1 for r in sl if (r.get("verdict") or {}).get("classification") == "TP")
        fp = sum(1 for r in sl if (r.get("verdict") or {}).get("classification") == "FP")
        llm_used = sum(1 for r in sl if (r.get("verdict") or {}).get("method") == "llm")
        llm_err = sum(1 for r in sl if (r.get("verdict") or {}).get("llm_error"))
        return {
            "source": self.ds.name, "total": self.total, "cursor": self.idx,
            "tp": tp, "fp": fp, "llm_used": llm_used, "llm_error": llm_err,
            "eps": round(self.eps, 2), "interval_ms": int(self.interval * 1000),
        }

    # ---------- 主循环 ----------
    def start(self) -> None:
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._run())

    async def _run(self) -> None:
        """观众驱动：无人在线时空转；首个观众接入即从头完整回放，随时演示/刷新都是全量时间线。"""
        while True:
            # 等观众上线（有连接才播，避免无人查看时空转）
            while not self._clients:
                await asyncio.sleep(0.2)
            self.idx = 0
            self.done = False
            await self._broadcast({"kind": "start", "stats": self.stats})
            while self.idx < self.total:
                row = self.queue[self.idx]
                self.idx += 1
                alert = self.ds.to_front_alert(row)
                await self._broadcast({"kind": "alert", "alert": alert})
                if self.idx < self.total:
                    await asyncio.sleep(self.interval)
                # 非循环模式下观众全走光则中断本轮回放，回到等待
                if not self._clients and not self.loop:
                    self.idx = self.total
            self.done = True
            await self._broadcast({"kind": "done", "stats": self.stats})
            if self.loop:
                # 循环展示：留白 5 秒再重播
                await asyncio.sleep(5.0)
            else:
                # 等现有观众离开，下一位接入时从头开始
                while self._clients:
                    await asyncio.sleep(0.5)

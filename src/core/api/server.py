# -*- coding: utf-8 -*-
"""Agent ↔ 前端演示后端（FastAPI）。

能力：
- REST：dashboard / alerts(筛选分页) / alert 详情 / 人工复核 / rules(含内存编辑)；
- WebSocket /ws/feed：Agent 事件时间压缩回放广播（大屏实时告警流）；
- 若 web/dist 已构建则一并托管前端（同一 8000 端口）。

用法（conda scssa 内，仓库根）：
    python -m src.core.api.server --source llm-soc           # 178 条 DeepSeek 实判回放
    python -m src.core.api.server --source linux --eps 60    # 9357 条规则回退快放
    python -m src.core.api.server --loop                     # 播完循环重放（展会演示）
前端构建后访问 http://127.0.0.1:8000/ （监控大屏 /screen、后台 /admin/alerts）。
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Optional

from fastapi import Body, FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .demo import SOURCES, DemoSource, store
from .memory_api import (  # noqa: F401
    candidate_explain as mem_candidate_explain,
    delete_rule as mem_delete_rule,
    derived_rules as mem_derived_rules,
    evolution,
    patch_rule as mem_patch_rule,
    promote_candidates as mem_promote_candidates,
    promote_rule as mem_promote_rule,
    promoted_manual_items,
    record_review_feedback,
    reject_rule as mem_reject_rule,
    rule_trace,
)
from .replay import ReplayHub


def _dist_dir() -> str:
    """前端构建产物目录：打包态取 exe 内解包目录（PyInstaller _MEIPASS），开发态取仓库 web/dist。"""
    if getattr(sys, "frozen", False):
        base = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
        return os.path.join(base, "web", "dist")
    return os.path.join("web", "dist")


DIST = _dist_dir()


def _techs(mitre) -> list:
    """从合并行 mitre（两种键位）提 techniques，供图谱多跳。"""
    if not mitre:
        return []
    t = mitre.get("technique", mitre.get("techniques"))
    if isinstance(t, list):
        return [x for x in t if x]
    if t:
        return [t]
    return [mitre["id"]] if "id" in mitre else []


def create_app(source_name: str, eps: float = 0, loop: bool = False) -> FastAPI:
    if source_name not in SOURCES:
        raise ValueError(f"未知数据源 {source_name}，可选 {list(SOURCES)}")
    ds: DemoSource = store.get(source_name)
    hub = ReplayHub(ds, eps=eps, loop=loop)

    app = FastAPI(title="SCSSA Agent 演示后端", version="0.1")
    app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
    app.state.ds = ds
    app.state.hub = hub

    @app.on_event("startup")
    async def _boot() -> None:
        hub.start()
        # 记忆库已人工升格的规则 → 登记进当前演示源的人工规则池（跨进程续显）
        try:
            for fe in promoted_manual_items():
                ds.rule_promote_register(fe)
        except Exception as exc:  # noqa: BLE001  记忆库缺库等不应阻断回放
            print(f"[demo] 升格规则登记跳过: {type(exc).__name__}: {exc}")

    # ---------- 健康 / 数据源 ----------
    @app.get("/api/health")
    def health():
        return {"ok": True, "source": source_name,
                "available": store.available(), "replay": hub.stats, "dist": os.path.isdir(DIST)}

    # ---------- dashboard ----------
    @app.get("/api/dashboard")
    def dashboard():
        return ds.dashboard()

    # ---------- alerts ----------
    @app.get("/api/alerts")
    def alerts(
        keyword: str = Query(""), severity: str = Query(""),
        verdict: str = Query(""), source: str = Query(""), status: str = Query(""),
        page: int = Query(1, ge=1), size: int = Query(20, ge=1, le=200),
    ):
        return ds.query_alerts(keyword=keyword, severity=severity, verdict=verdict,
                               source=source, status=status, page=page, size=size)

    @app.get("/api/alerts/{alert_id}")
    def alert_detail(alert_id: str):
        a = ds.alert_detail(alert_id)
        if a is None:
            raise HTTPException(404, f"无此告警 {alert_id}")
        return a

    @app.post("/api/alerts/{alert_id}/review")
    def alert_review(alert_id: str, body: dict = Body(...)):
        """人工复核：更新前端 verdict；同时以 feedback 片段写回多层记忆（规格 B）。"""
        cls = str(body.get("cls", "TP")).upper()
        by = str(body.get("by") or "analyst")
        reason = str(body.get("reason") or "")
        priority = str(body.get("priority") or "")
        a = ds.review(alert_id, cls, by=by, reason=reason, priority=priority)
        if a is None:
            raise HTTPException(404, f"无此告警 {alert_id}")
        row = ds.alert_row(alert_id)
        feedback = None
        if row is not None:
            try:
                feedback = record_review_feedback(source_name, row, cls, by,
                                                  reason=reason, priority=priority)
            except Exception as exc:  # noqa: BLE001  记忆写回失败不阻断复核本身
                feedback = {"error": f"{type(exc).__name__}: {exc}"}
        a["feedback"] = feedback
        return a

    @app.get("/api/alerts/{alert_id}/evidence")
    def alert_evidence(alert_id: str):
        """实时证据面板：相似记忆片段 + 命中可疑模式 + ATT&CK 图谱多跳（流式防泄漏）。"""
        row = ds.alert_row(alert_id)
        if row is None:
            raise HTTPException(404, f"无此告警 {alert_id}")
        b = getattr(app.state, "evidence_builder", None)
        if b is None:
            from src.core.memory.evidence import EvidenceBuilder
            kb = None
            try:
                from src.core.knowledge.graph import KnowledgeKB
                kb = KnowledgeKB()
            except Exception as exc:  # noqa: BLE001  图谱缺库 → 仅记忆证据
                print(f"[demo] 知识图谱不可用，仅记忆证据: {type(exc).__name__}: {exc}")
            from src.core.api.memory_api import get_store as mem_get_store
            b = EvidenceBuilder(mem_get_store(), kb)
            app.state.evidence_builder = b
        text = (row.get("text") or "") + " " + (row.get("rule_desc") or "")
        res = b.collect(source_name, query=(text or "")[:800],
                        techniques=_techs(row.get("mitre")),
                        seq_now=int(row.get("seq") or 0),
                        with_memory=True, with_kb=True)
        return {
            "alertId": alert_id,
            "dataset": source_name,
            "seq": row.get("seq"),
            "leakageGuard": f"仅引用 seq < {row.get('seq')} 的历史记忆（流式切分，防未来泄漏）",
            "counts": res["counts"],
            "evidenceText": res["evidence_text"],
        }

    # ---------- rules ----------
    @app.get("/api/rules")
    def rules(type: str = Query("manual")):
        # 衍生规则来自多层记忆库（MemoryStore），人工规则为演示 overlay
        if type == "derived":
            return mem_derived_rules()
        return ds.rule_items()

    @app.patch("/api/rules/{rule_id}")
    def rule_patch(rule_id: str, body: dict = Body(...)):
        # 人工规则池（演示 overlay：含数据集规则 + 新建/升格人工规则）优先就地编辑；
        # 其余回退多层记忆库衍生规则（人工冻结/停用/改字段均审计）
        overlay = ds.rule_overlay.get(ds.name, {})
        if rule_id in overlay:
            out = ds.rule_set(rule_id, **body)
            if out is None:
                raise HTTPException(404, f"无此规则 {rule_id}")
            return out
        m = mem_patch_rule(rule_id, body)
        if m is not None:
            return m
        out = ds.rule_set(rule_id, **body)
        if out is None:
            raise HTTPException(404, f"无此规则 {rule_id}")
        return out

    @app.post("/api/rules")
    def rule_create(body: dict = Body(...)):
        return ds.rule_create(body)

    @app.delete("/api/rules/{rule_id}")
    def rule_delete(rule_id: str):
        # 人工规则池条目（含已升格）删除即从人工池移除；其余为记忆库衍生规则停用
        if rule_id in ds.rule_overlay.get(ds.name, {}):
            ds.rule_delete(rule_id)
            return {"ok": True, "kind": "manual"}
        if mem_delete_rule(rule_id):
            return {"ok": True, "kind": "derived"}
        ds.rule_delete(rule_id)
        return {"ok": True, "kind": "manual"}

    # ---------- 多层记忆：演化总开关 / 溯源 ----------
    @app.get("/api/evolution")
    def evolution_get():
        return evolution(None)

    @app.post("/api/evolution")
    def evolution_post(body: dict = Body(default={})):
        on = body.get("on")
        return evolution(bool(on) if on is not None else None)

    # ---------- 升格审批（自进化 → 人工权威，规格 D） ----------
    @app.get("/api/evolution/promote-candidates")
    def promote_candidates_ep():
        """待升格人工规则候选：经验证有含金量的衍生规则（含来源模式/命中/支撑统计）。"""
        return mem_promote_candidates()

    @app.post("/api/evolution/promote")
    def promote_ep(body: dict = Body(...)):
        """人工拍板（同意）：衍生规则 → 人工规则。落库(记忆) + 审计 + 登记当前演示人工规则池。"""
        rule_id = str(body.get("ruleId") or body.get("patternId") or "")
        by = str(body.get("by") or "analyst")
        note = str(body.get("note") or "")
        fe = mem_promote_rule(rule_id, by=by, note=note)
        if fe is None:
            raise HTTPException(404, f"无可升格的衍生规则 {rule_id}")
        item = ds.rule_promote_register(fe)
        return {"ok": True, "rule": item, "kind": "promoted"}

    @app.post("/api/evolution/reject")
    def reject_ep(body: dict = Body(...)):
        """人工拒绝：仅退出『建议新增规则』推荐，衍生规则保持 active 继续演化（含审计）。"""
        rule_id = str(body.get("ruleId") or "")
        by = str(body.get("by") or "analyst")
        note = str(body.get("note") or "")
        fe = mem_reject_rule(rule_id, by=by, note=note)
        if fe is None:
            raise HTTPException(404, f"无此衍生规则 {rule_id}")
        return {"ok": True, "rule": fe, "kind": "rejected"}

    @app.post("/api/evolution/promote-candidates/{rule_id}/explain")
    def candidate_explain_ep(rule_id: str, body: dict = Body(default={})):
        """生成/获取候选规则的大模型自然语言解释（evo 缓存；LLM 不可用自动降级模板）。"""
        res = mem_candidate_explain(rule_id, force=bool(body.get("force") or False))
        if res is None:
            raise HTTPException(404, f"无此候选规则 {rule_id}")
        return {"ok": True, **res}

    @app.get("/api/rules/{rule_id}/trace")
    def rule_trace_ep(rule_id: str):
        """衍生规则溯源：规则 → 来源模式 → 支撑片段（证据链）。"""
        t = rule_trace(rule_id)
        if t is not None:
            return t
        d = ds.rule_get(rule_id)
        if d is not None:
            return {"rule": d, "pattern": None, "fragments": [],
                    "note": "人工规则无自进化溯源链"}
        raise HTTPException(404, f"无此规则 {rule_id}")

    # ---------- WebSocket 回放流 ----------
    @app.websocket("/ws/feed")
    async def ws_feed(ws: WebSocket):
        await ws.accept()
        hub.attach(ws)
        # 先推送当前回放进度快照，随后持续收广播
        try:
            await ws.send_text(json.dumps({"kind": "hello", "stats": hub.stats}, ensure_ascii=False))
            while True:
                await ws.receive_text()  # 保持连接（前端不主动发数据）
        except WebSocketDisconnect:
            pass
        finally:
            hub.detach(ws)

    # ---------- 前端静态托管 ----------
    if os.path.isdir(DIST):
        assets = os.path.join(DIST, "assets")
        if os.path.isdir(assets):
            app.mount("/assets", StaticFiles(directory=assets), name="assets")

        @app.get("/{full_path:path}")
        def spa(full_path: str):
            # 单页应用：真实文件直出，否则回退 index.html
            candidate = os.path.normpath(os.path.join(DIST, full_path))
            if full_path and candidate.startswith(DIST) and os.path.isfile(candidate):
                return FileResponse(candidate)
            return FileResponse(os.path.join(DIST, "index.html"))
    else:
        @app.get("/")
        def no_dist():
            return JSONResponse({
                "msg": "前端未构建（web/dist 不存在）。开发调试请 `cd web && npm run dev`（Vite 代理到本服务）；"
                       "或先 `npm run build` 再访问本端口。",
                "docs": "/docs", "health": "/api/health", "dashboard": "/api/dashboard",
            })

    return app


def main() -> None:
    ap = argparse.ArgumentParser(description="SCSSA Agent 演示后端")
    ap.add_argument("--source", choices=list(SOURCES), default="llm-soc", help="回放数据源")
    ap.add_argument("--eps", type=float, default=0, help="每秒事件数（0=按总量自动压到 ~90s）")
    ap.add_argument("--loop", action="store_true", help="播完自动循环重放")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    args = ap.parse_args()

    import uvicorn
    app = create_app(args.source, eps=args.eps, loop=args.loop)
    print(f"[demo] 数据源: {args.source}（{store.get(args.source).label}），事件流将推送至 /ws/feed")
    print(f"[demo] 前端: http://{args.host}:{args.port}/   API: /api/health   WS: /ws/feed")
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()

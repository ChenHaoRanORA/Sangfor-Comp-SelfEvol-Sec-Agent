# -*- coding: utf-8 -*-
"""多层记忆 API：衍生规则(CRUD/审计) + 演化总开关 + 溯源（规则→模式→片段）。
    独立于演示数据源 overlay，直接读写 MemoryStore(SQLite)；
    数据结构对齐 web/src/api/types.ts 的 RuleItem / AuditEntry。
"""
from __future__ import annotations

import json
from typing import Optional

from src.core.llm.client import LLMClient, LLMError
from src.core.memory.store import MemoryStore
from src.core.memory.models import Fragment, now_ms

_store: Optional[MemoryStore] = None


def get_store() -> MemoryStore:
    global _store
    if _store is None:
        _store = MemoryStore()
    return _store


# ============================================================ 转换
def _rule_to_fe(r: dict) -> dict:
    """DB 衍生规则 → 前端 RuleItem（对齐 types.ts）。"""
    ap = r.get("action_policy") or {}
    audit = r.get("audit") or []
    for a in audit:
        a.setdefault("by", "system")
    return {
        "ruleId": r["rule_id"],
        "ruleType": "derived",
        "name": r.get("name") or r["rule_id"],
        "description": r.get("description") or "",
        "enabled": bool(r.get("enabled")),
        "state": r.get("state") or "active",
        "severity": r.get("severity") or "Medium",
        "expression": json.dumps(r.get("expression") or [], ensure_ascii=False),
        "actionPolicy": {"maxTier": ap.get("max_tier") or "A0",
                         "allow": ap.get("allow") or []},
        "firedTimes": int(r.get("fired_times") or 0),
        "series": [0] * 24,
        "lastTriggeredAt": r.get("last_triggered_at"),
        "owner": r.get("owner") or "system",
        "createdAt": r.get("created_at"),
        "updatedAt": r.get("updated_at"),
        "revision": int(r.get("revision") or 1),
        "audit": audit,
        "auto": bool(r.get("auto")),
        # 衍生规则特有（溯源展示）
        "sourcePatternId": r.get("source_pattern_id"),
        "confidence": _pattern_conf(r.get("source_pattern_id")),
    }


def _pattern_conf(pattern_id: Optional[str]) -> Optional[float]:
    if not pattern_id:
        return None
    p = get_store().pattern_by_id(pattern_id)
    return p.get("confidence") if p else None


def _pattern_to_fe(p: dict, store: MemoryStore) -> dict:
    """DB 模式 → 前端溯源视图（Pattern → 支撑片段摘要）。"""
    frags = store.fragment_by_ids(p.get("supporting_fragment_ids") or [])
    return {
        "patternId": p["pattern_id"],
        "dataset": p.get("dataset"),
        "title": p.get("title"),
        "description": p.get("description"),
        "kind": p.get("kind"),
        "state": p.get("state"),
        "confidence": p.get("confidence"),
        "hits": p.get("hits"),
        "ruleIds": p.get("rule_ids") or [],
        "mitreTechniques": p.get("mitre_techniques") or [],
        "mitreTactics": p.get("mitre_tactics") or [],
        "derivedRuleId": p.get("derived_rule_id"),
        "meta": p.get("meta") or {},
        "supportingFragments": [{
            "fragmentId": f["fragment_id"],
            "summary": (f.get("summary") or "")[:200],
            "host": f.get("host"),
            "ts": f.get("ts_ms"),
            "classification": f.get("classification"),
        } for f in frags[:50]],
    }


# ============================================================ 查询 / CRUD
def derived_rules(dataset: Optional[str] = None) -> list[dict]:
    """衍生规则列表（可选按数据集过滤，经 source_pattern 关联）。

    已由人工拍板升格为人工规则（evo promoted.manual）的不再以『衍生』名义列出，
    避免与人工规则池重复展示；其审计/溯源仍可在规则页完整查看。
    """
    st = get_store()
    promoted = set(st.promoted_rule_ids())
    rules = [r for r in st.rules() if r["rule_id"] not in promoted]
    if dataset:
        ds_pids = {p["pattern_id"] for p in st.patterns(dataset=dataset)}
        rules = [r for r in rules if r.get("source_pattern_id") in ds_pids]
    return [_rule_to_fe(r) for r in rules]


def get_rule(rule_id: str) -> Optional[dict]:
    r = get_store().rule_by_id(rule_id)
    return _rule_to_fe(r) if r else None


def patch_rule(rule_id: str, body: dict, by: str = "analyst") -> Optional[dict]:
    st = get_store()
    cur = st.rule_by_id(rule_id)
    if cur is None:
        return None
    prev_rev = cur["revision"]
    state = body.get("state")
    enabled = body.get("enabled")
    fields = {k: body[k] for k in ("name", "description", "severity") if body.get(k) is not None}
    if body.get("expr") is not None:
        fields["expr"] = body["expr"]
    if body.get("tier") is not None:
        fields["tier"] = body["tier"]
    if body.get("allow") is not None:
        fields["allow"] = body["allow"]
    r = st.rule_patch(rule_id, by=by, state=state, enabled=enabled, **fields)
    if r is not None and r["revision"] != prev_rev:
        # 审计表行（列里同时由 _patch_rule 记全量 JSON，供前端抽屉展示）
        parts = []
        if state is not None and state != cur["state"]:
            parts.append(f"状态 {cur['state']} → {state}")
        if enabled is not None and enabled != cur["enabled"]:
            parts.append(f"启用 → {enabled}")
        parts += [f"{k} 更新" for k in ("name", "description", "severity", "expr", "tier", "allow") if k in fields]
        st.audit("rule", rule_id, "manual", by, f"人工修改: {'；'.join(parts) or '规则字段'}")
    return _rule_to_fe(r) if r else None


def delete_rule(rule_id: str, by: str = "analyst", note: str = "人工停用") -> bool:
    return get_store().rule_delete(rule_id, by=by, note=note)


def evolution(on: Optional[bool] = None) -> dict:
    st = get_store()
    return {"on": st.auto_evolve(on)}


# ============================================================ 溯源（多跳）
def rule_trace(rule_id: str) -> Optional[dict]:
    """衍生规则溯源：规则 → 来源模式 → 支撑片段（Episodic 证据链）。"""
    st = get_store()
    r = st.rule_by_id(rule_id)
    if r is None:
        return None
    rule = _rule_to_fe(r)
    pid = r.get("source_pattern_id")
    out: dict = {"rule": rule, "pattern": None, "fragments": []}
    if pid:
        p = st.pattern_by_id(pid)
        if p:
            out["pattern"] = _pattern_to_fe(p, st)
            out["fragments"] = [f for f in
                                st.fragment_by_ids(p.get("supporting_fragment_ids") or [])][:100]
    return out


def pattern_trace(pattern_id: str) -> Optional[dict]:
    """模式溯源：模式 → 支撑片段 + 其衍生的规则。"""
    st = get_store()
    p = st.pattern_by_id(pattern_id)
    if p is None:
        return None
    out = _pattern_to_fe(p, st)
    if p.get("derived_rule_id"):
        out["derivedRule"] = _rule_to_fe(st.rule_by_id(p["derived_rule_id"]))
    return out


# ============================================================ 复核反馈回流（规格 B）
def record_review_feedback(source_name: str, row: dict, cls: str, by: str,
                           reason: str = "", priority: str = "") -> dict:
    """人工复核告警 → 以 feedback 片段沉淀进多层记忆（低风险可写）。

    - fragment_id = fb-{dataset}-{alert_id}：同告警重复复核整行覆盖更新（幂等）；
    - method='feedback'，source 内含复核人/理由/原处置归属（rule_hits + 原 LLM verdict）；
    - 审计 scope=fragment。
    """
    st = get_store()
    alert_id = str(row.get("alert_id"))
    fid = f"fb-{source_name}-{alert_id}"
    hits = row.get("rule_hits") or []
    rule_id = row.get("rule_id")
    rule_level = row.get("rule_level")
    if not rule_id and hits:
        rule_id = hits[0].get("rule_id")
    if rule_level is None and hits:
        rule_level = hits[0].get("level")
    groups = row.get("rule_groups") or (hits[0].get("groups") if hits else []) or []
    ov = row.get("verdict") or {}
    reason = reason or ""
    priority = priority or ""
    summary = (f"[人工复核] {source_name}#{row.get('seq')} 告警 {alert_id} "
               f"源规则 {rule_id or '-'}(lvl {rule_level}) 原判 "
               f"{ov.get('classification') or '未判'}({ov.get('method') or 'none'}) "
               f"→ 人工复核 {cls} 优先级 {priority or 'low'} by {by}，理由：{reason or '（未填）'}")
    frag = Fragment(
        fragment_id=fid, dataset=source_name, alert_id=alert_id,
        seq=int(row.get("seq") or 0), host=str(row.get("agent_name") or "-"),
        ts_ms=row.get("ts"), rule_id=str(rule_id) if rule_id else None,
        rule_level=rule_level, groups=groups, mitre=row.get("mitre"),
        classification=cls, verdict_priority=priority or "low",
        method="feedback", llm_error=False, summary=summary,
        source={"alert": {
            "seq": row.get("seq"), "dataset": source_name,
            "text": (row.get("text") or "")[:2000],
            "rule_hits": hits,
            "orig_verdict": {
                "classification": ov.get("classification"),
                "priority": ov.get("priority"),
                "method": ov.get("method"),
                "justification": (ov.get("justification") or "")[:600],
            }},
            "review": {"by": by, "reason": reason, "prio": priority,
                       "ts": now_ms()}},
        created_at=now_ms())
    st.upsert_fragments([frag])
    st.audit("fragment", fid, "manual.review", by, f"复核写回 feedback 片段：{summary[:200]}")
    return {"fragmentId": fid, "updated": 1, "cls": cls, "by": by,
            "summary": summary, "ts": frag.created_at}


# ============================================================ 升格审批（规格 D）
def promote_candidates() -> list[dict]:
    """建议新增规则候选：active + enabled + auto 的衍生规则（含来源模式验证统计 + 已缓存 LLM 解释）。

    供前端『规则建议』列表呈现；验证统计 = 命中次数/支撑片段数/其中 feedback 占比。
    已升格(promoted.manual)或已拒绝(promote.rejected)的规则不再出现。
    """
    st = get_store()
    promoted = set(st.promoted_rule_ids())
    rejected = set(st.rejected_rule_ids())
    out: list[dict] = []
    for r in st.rules():
        rid = r["rule_id"]
        if rid in promoted or rid in rejected:
            continue
        if not r.get("auto") or not r.get("enabled") or r["state"] != "active":
            continue
        pid = r.get("source_pattern_id")
        if not pid:
            continue
        p = st.pattern_by_id(pid)
        if p is None or p.get("state") != "active":
            continue
        fe = _rule_to_fe(r)
        sids = p.get("supporting_fragment_ids") or []
        fe["promoteFromPatternId"] = pid
        fe["promoteFromPatternTitle"] = p.get("title")
        fe["validation"] = {
            "firedTimes": r.get("fired_times") or 0,
            "patternHits": p.get("hits") or 0,
            "confidence": p.get("confidence"),
            "supportFragments": len(sids),
            "feedbackFragments": sum(1 for s in sids if str(s).startswith("fb-")),
        }
        cache = st.evo_get(f"promote.explain.{rid}")
        if cache and isinstance(cache, dict) and cache.get("text"):
            fe["explain"] = cache["text"]
            fe["explainSource"] = cache.get("source") or "template"
        out.append(fe)
    out.sort(key=lambda x: -(x["validation"]["firedTimes"] or 0))
    return out


def _candidate_context(st: MemoryStore, r: dict, p: Optional[dict]) -> dict:
    """LLM 解释所需的候选上下文：规则/覆盖规则 id/模式/MITRE/验证统计。"""
    expr = r.get("expression") or []
    covered: list[str] = []
    for pred in expr:
        if pred.get("field") == "rule.id" and pred.get("op") in ("in", "eq", "=="):
            vals = pred.get("value")
            if isinstance(vals, list):
                covered += [str(x) for x in vals]
            elif pred.get("op") in ("eq", "==") and vals is not None:
                covered.append(str(vals))
    sids = (p or {}).get("supporting_fragment_ids") or []
    return {
        "name": r.get("name") or r["rule_id"],
        "ruleId": r["rule_id"],
        "description": r.get("description") or "",
        "severity": r.get("severity") or "Medium",
        "ruleIds": sorted(set(covered)) or (p or {}).get("rule_ids") or [],
        "patternId": (p or {}).get("pattern_id"),
        "patternTitle": (p or {}).get("title") or "",
        "patternDesc": (p or {}).get("description") or "",
        "patternKind": (p or {}).get("kind") or "behavior",
        "mitreTechniques": (p or {}).get("mitre_techniques") or [],
        "mitreTactics": (p or {}).get("mitre_tactics") or [],
        "firedTimes": r.get("fired_times") or 0,
        "confidence": (p or {}).get("confidence"),
        "supportFragments": len(sids),
        "feedbackFragments": sum(1 for s in sids if str(s).startswith("fb-")),
    }


_llm: Optional[LLMClient] = None


def _llm_client() -> Optional[LLMClient]:
    global _llm
    if _llm is None:
        try:
            _llm = LLMClient()
        except Exception:  # noqa: BLE001  环境异常时按无 LLM 处理
            _llm = None
    return _llm


def _llm_explain(ctx: dict) -> str:
    """用 LLM 生成『为什么建议新增这条人工规则』的自然语言解释；不可用/失败返回 ""。"""
    llm = _llm_client()
    if llm is None or not llm.available:
        return ""
    system = (
        "你是一名资深安全运营分析师。系统从历史处置经验中提炼出一条『建议新增为人工规则』"
        "的候选。请用简体中文给安全运营人员写一段自然语言解释（不超过 220 字），要点：\n"
        "1) 这条规则捕获什么行为；\n"
        "2) 为什么值得固化为确定性规则（重复命中 / 人工复核修正等证据）；\n"
        "3) 固化为人工规则后带来什么改变（命中即按规则直发、不消耗大模型推理）；\n"
        "4) 需要注意的风险或误报可能。\n"
        "只输出 JSON 对象：{\"reason\": \"...\"}，reason 为纯文本、不换行。"
    )
    user = (
        f"[规则] {ctx['name']}（{ctx['ruleId']}，级别 {ctx['severity']}）\n"
        f"[规则说明] {ctx['description'] or '-'}\n"
        f"[覆盖原始告警规则] {', '.join(map(str, ctx['ruleIds'])) or '-'}\n"
        f"[来源可疑模式] {ctx['patternId']} · {ctx['patternTitle']}（kind={ctx['patternKind']}）\n"
        f"[模式说明] {ctx['patternDesc'] or '-'}\n"
        f"[MITRE] 战术: {', '.join(ctx['mitreTactics']) or '-'}；"
        f"技术: {', '.join(ctx['mitreTechniques']) or '-'}\n"
        f"[验证统计] 命中 {ctx['firedTimes']} 次 / 支撑历史片段 {ctx['supportFragments']} 条"
        f"（其中人工复核修正 {ctx['feedbackFragments']} 条）"
        f" / 模式置信度 {('%.0f%%' % (ctx['confidence'] * 100)) if ctx['confidence'] is not None else '-'}"
    )
    try:
        obj = llm.complete(system, user)
        reason = str(obj.get("reason") or "").strip()
        return reason[:600]
    except LLMError:  # 网络/解析失败：不阻断建议页
        return ""


def _template_explain(ctx: dict) -> str:
    """LLM 不可用时，用规则证据拼装一段自然语言摘要（明确标注非 LLM）。"""
    covered = "、".join(map(str, ctx["ruleIds"])) or "-"
    tacs = "、".join(ctx["mitreTactics"]) or "-"
    conf = ("%.0f%%" % (ctx["confidence"] * 100)) if ctx["confidence"] is not None else "-"
    fb = f"，其中 {ctx['feedbackFragments']} 条来自人工复核修正" if ctx["feedbackFragments"] else ""
    return (
        f"系统从历史处置经验中建议把「{ctx['name']}」固化为人工规则（级别 {ctx['severity']}）："
        f"它覆盖原始告警规则 {covered}，归纳自可疑模式 {ctx['patternId']}"
        f"（{ctx['patternDesc'] or ctx['patternTitle'] or '经验证的高频行为'}），"
        f"关联 MITRE 战术 {tacs}。该规则已重复命中 {ctx['firedTimes']} 次，"
        f"由 {ctx['supportFragments']} 条历史片段支撑{fb}，模式置信度 {conf}。"
        f"升格后命中即按规则定级直接告警，不再消耗大模型推理。"
        f"（说明：大模型解释暂不可用，本段由规则证据自动拼装）"
    )


def candidate_explain(rule_id: str, force: bool = False) -> Optional[dict]:
    """获取/生成（并缓存）某条候选规则的 LLM 自然语言解释。

    - 有缓存且未 force → 直接返回缓存；
    - LLM 可用 → 实时生成（模型总结）并写 evo 缓存 `promote.explain.{rule_id}`；
    - LLM 不可用/失败 → 自动降级为『证据拼装摘要』（source=template）兜底并缓存。
    均返回 {"ruleId","text","source": llm|template, "cached": bool}。
    """
    st = get_store()
    r = st.rule_by_id(rule_id)
    if r is None:
        return None
    key = f"promote.explain.{rule_id}"
    cached = st.evo_get(key)
    if cached and isinstance(cached, dict) and cached.get("text") and not force:
        return {"ruleId": rule_id, "text": cached["text"],
                "source": cached.get("source") or "template", "cached": True}
    p = st.pattern_by_id(r.get("source_pattern_id")) if r.get("source_pattern_id") else None
    ctx = _candidate_context(st, r, p)
    text = _llm_explain(ctx)
    source = "llm"
    if not text:
        text = _template_explain(ctx)
        source = "template"
    st.evo_set(key, {"text": text, "source": source, "ts": now_ms()})
    return {"ruleId": rule_id, "text": text, "source": source, "cached": False}


def reject_rule(rule_id: str, by: str = "analyst", note: str = "") -> Optional[dict]:
    """人工拒绝候选：仅退出『建议新增规则』推荐，衍生规则保持 active 继续演化（含审计）。"""
    st = get_store()
    r = st.reject_candidate(rule_id, by=by, note=note)
    return _rule_to_fe(r) if r else None


def promote_rule(rule_id: str, by: str = "analyst", note: str = "") -> Optional[dict]:
    """人工拍板升格：衍生规则 → 人工权威规则（记忆落库 + 审计 + 来源模式登记）。"""
    st = get_store()
    r = st.promote_rule(rule_id, by=by, note=note)
    return _rule_to_fe(r) if r else None


def promoted_manual_items() -> list[dict]:
    """已升格为人工规则的规则 FE 列表（供演示人工规则池启动时登记/续显）。"""
    st = get_store()
    promoted = set(st.promoted_rule_ids())
    return [_rule_to_fe(r) for r in st.rules() if r["rule_id"] in promoted]

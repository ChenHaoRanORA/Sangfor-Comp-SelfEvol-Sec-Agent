# -*- coding: utf-8 -*-
"""LangGraph v1/v2 处置流：告警 → 双向匹配 → (证据增强 LLM 研判?) → 仅告警通知。

v1 能力边界：**Agent 只告警（notify），不执行任何自主动作**（不封禁/不停服/不修改
系统）。动作分级 A0–A3、HITL、自进化留待后续版本。

v2（自进化规格 A · 处置分流）在 v1 之上增加可选的 `gather_evidence` 节点：
- 命中**人工规则**且 `need_llm=False` → 潜意识直发 `alert_only`（不耗 LLM）；
- 命中可疑模式/有相似记忆（即需要 LLM）→ `gather_evidence` 检索"多层记忆相似片段
  + 可疑模式 + ATT&CK 图谱多跳"证据（仅 seq<当前，防泄漏）注入 triage 后再研判；
- 未提供 evidence_builder 时行为与 v1 完全一致（无证据注入）。

节点：
    match_rules    : 规则引擎命中（双池 v1=人工规则种子），并计算是否需要 LLM 研判
    gather_evidence: (v2 可选) 记忆+图谱证据检索（EvidenceBuilder.collect → evidence 文本）
    resolve        : 需要时调用 LLM（带缓存/失败回退，可注入证据），否则直接规则回退结论
    alert_only     : 组装 AlertEvent 事件（action=notify），不触发其他动作

用 add_conditional_edges 在 match_rules 后分流（alert_only / gather / resolve），
体现"LLM 成本可控 + 模式命中走显意识"。
"""
from __future__ import annotations

import hashlib
import json
from typing import Callable, Optional, TypedDict

from langgraph.graph import END, START, StateGraph

from src.core.llm.client import LLMClient, LLMError
from src.core.memory.evidence import EvidenceBuilder
from src.core.memory.models import Fragment, now_ms
from src.core.memory.store import MemoryStore
from src.core.models import Alert, AlertEvent, RuleHit, Verdict
from src.core.rules.engine import RuleEngine
from src.core.rules.pools import load_manual_rules, match_manual


class AgentState(TypedDict, total=False):
    """LangGraph 处置流状态。逐键 last-write-wins，节点只返回自己更新的键。

    注：所有跨节点传递的键**必须**声明在此（LangGraph 按 TypedDict 建通道，
    未声明的键会被静默丢弃），否则 v3 的 manual_hits/channel 等无法在节点间流通。
    """
    seq: int
    alert: Alert
    rule_hits: list
    manual_hits: list             # v3：命中记忆库人工权威规则(auto=0)的列表
    need_llm: bool
    channel: str = ""             # v3 分流通路: manual|memory|policy
    cover_patterns: list          # v3：命中『过去可疑模式』(防泄漏)的 active 模式列表
    evidence: Optional[str]       # v2：gather_evidence 产出的证据文本（供 LLM 研判注入）
    evidence_counts: Optional[dict]  # v2：证据统计（片段/模式/图谱条数），供审计观测
    verdict: Optional[Verdict]
    event: Optional[AlertEvent]


def fingerprint(alert: Alert) -> str:
    raw = json.dumps({
        "dataset": alert.dataset, "id": alert.alert_id, "text": alert.text,
        "rule": alert.rule.model_dump() if alert.rule else None,
    }, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


def fallback_verdict(alert: Alert, hits: list[RuleHit]) -> Verdict:
    """LLM 不可用/失败/无需语义判断时，直接用规则结论回退。"""
    if hits:
        desc = hits[0].description or f"规则 {hits[0].rule_id}"
        just = f"命中规则 {hits[0].rule_id}（{desc}，level={hits[0].level}）；按规则定级告警。"
        ev = [h.rule_id for h in hits]
    else:
        just = "未命中人工规则，按告警自带等级定级并通知。"
        ev = []
    mitre = alert.mitre or {}
    if mitre.get("id") or mitre.get("technique"):
        just += f" 关联 MITRE {mitre.get('id') or mitre.get('technique')}。"
        ev.append(str(mitre.get("id") or mitre.get("technique")))
    return Verdict(
        classification=None,
        priority=alert.priority,
        method="rule_fallback",
        justification=just,
        evidence=ev,
    )


def make_triage_resolver(llm: Optional[LLMClient], cache: Optional[dict] = None):
    """返回 (alert, hits, evidence=None) -> Verdict 的研判函数：优先缓存/调用 LLM，失败自动回退。"""
    memo: dict[str, Verdict] = cache if cache is not None else {}

    def resolve(alert: Alert, hits: list[RuleHit], evidence: Optional[str] = None) -> Verdict:
        fp = fingerprint(alert)
        if fp in memo:
            return memo[fp]
        verdict: Optional[Verdict] = None
        if llm is not None and llm.available:
            try:
                obj = llm.triage(
                    dataset=alert.dataset, text=alert.text,
                    rule_desc=hits[0].description if hits else None,
                    rule_level=hits[0].level if hits else None,
                    mitre=alert.mitre,
                    fingerprint=fp,
                    evidence=evidence,
                )
                classification = obj.get("classification")
                if classification not in ("TP", "FP", "UNKNOWN", None):
                    classification = None
                priority = obj.get("priority")
                if priority not in ("low", "medium", "high", "critical"):
                    priority = alert.priority
                verdict = Verdict(
                    classification=classification,
                    priority=priority,
                    method="llm",
                    justification=str(obj.get("justification") or "")[:2000],
                    evidence=[h.rule_id for h in hits] + ([str(alert.mitre.get("id"))] if (alert.mitre or {}).get("id") else []),
                )
            except LLMError as exc:
                verdict = fallback_verdict(alert, hits)
                verdict.llm_error = True
                verdict.justification = f"[LLM 失败已回退] {exc} | " + verdict.justification
        else:
            verdict = fallback_verdict(alert, hits)
        memo[fp] = verdict
        return verdict

    return resolve


def _default_state(seq: int, alert: Alert) -> dict:
    return {
        "seq": seq,
        "alert": alert,
        "rule_hits": [],
        "need_llm": False,
        "evidence": None,
        "evidence_counts": None,
        "verdict": None,
        "event": None,
    }


def _mitre_techniques(alert: Alert) -> list[str]:
    """统一告警 MITRE technique 字段 → 名称/ID 列表（供图谱多跳检索）。"""
    m = alert.mitre or {}
    raw = m.get("technique", m.get("techniques"))
    if isinstance(raw, str):
        return [raw] if raw else []
    if not isinstance(raw, list):
        return []
    out = []
    for x in raw:
        if isinstance(x, str):
            out.append(x)
        elif isinstance(x, dict):
            out.append(str(x.get("id") or x.get("name") or ""))
    return [x for x in out if x]


def make_v2_graph(
    engine: RuleEngine,
    need_llm: Callable[[Alert, list[RuleHit]], bool],
    triage_resolver: Callable[[Alert, list[RuleHit], Optional[str]], Verdict],
    evidence_builder: Optional[EvidenceBuilder] = None,
    use_memory: bool = True,
    use_kb: bool = True,
):
    """构造编译好的 LangGraph 处置图 v2（v1 的超集）。

    - `evidence_builder=None`：不检索证据，行为与 v1 完全一致；
    - 提供 `EvidenceBuilder`：need_llm 的告警经 `gather_evidence` 注入记忆+图谱证据再研判；
    - 命中人工规则且 `need_llm=False` 始终潜意识直发（不耗 LLM、不进 gather）。
    graph.invoke(_default_state(seq, alert)) 使用；seq 须与记忆库该数据集片段序号对齐
    （流式防泄漏：只引用 seq<当前 的经验）。
    """

    def _node_match(s: dict) -> dict:
        alert: Alert = s["alert"]
        hits = engine.match(alert)
        return {"rule_hits": hits, "need_llm": need_llm(alert, hits)}

    def _node_gather(s: dict) -> dict:
        alert: Alert = s["alert"]
        if evidence_builder is None:
            return {"evidence": None, "evidence_counts": None}
        query = ((alert.text or "") + " " + (s["rule_hits"][0].description or "" if s["rule_hits"] else ""))[:3000]
        evd = evidence_builder.collect(
            dataset=alert.dataset,
            query=query,
            techniques=_mitre_techniques(alert),
            seq_now=s["seq"],
            with_memory=use_memory,
            with_kb=use_kb,
        )
        return {"evidence": evd["evidence_text"] or None, "evidence_counts": evd["counts"]}

    def _node_resolve(s: dict) -> dict:
        alert: Alert = s["alert"]
        return {"verdict": triage_resolver(alert, s["rule_hits"], evidence=s.get("evidence"))}

    def _node_alert_only(s: dict) -> dict:
        alert: Alert = s["alert"]
        # 未走 resolve（need_llm=False）时无 verdict，按规则结论兜底
        verdict: Verdict = s["verdict"] or fallback_verdict(alert, s["rule_hits"])
        agent = alert.agent or {}
        event = AlertEvent(
            seq=s["seq"],
            ts_ms=alert.ts_ms,
            ts_iso=(alert.time or {}).get("iso"),
            dataset=alert.dataset,
            alert_id=alert.alert_id,
            index=alert.index,
            agent_name=agent.get("name"),
            rule_hits=s["rule_hits"],
            need_llm=s["need_llm"],
            llm_used=verdict.method == "llm",
            verdict=verdict,
            action="notify",
            notified=True,
        )
        return {"event": event}

    def _route(s: dict) -> str:
        if not s["need_llm"]:
            return "alert_only"
        return "gather" if evidence_builder is not None else "resolve"

    g = StateGraph(AgentState)
    g.add_node("match_rules", _node_match)
    if evidence_builder is not None:
        g.add_node("gather_evidence", _node_gather)
    g.add_node("resolve", _node_resolve)
    g.add_node("alert_only", _node_alert_only)
    g.add_edge(START, "match_rules")
    if evidence_builder is not None:
        g.add_conditional_edges(
            "match_rules", _route, {"resolve": "resolve", "gather": "gather_evidence", "alert_only": "alert_only"})
        g.add_edge("gather_evidence", "resolve")
    else:
        g.add_conditional_edges(
            "match_rules", _route, {"resolve": "resolve", "alert_only": "alert_only"})
    g.add_edge("resolve", "alert_only")
    g.add_edge("alert_only", END)
    return g.compile()


def make_v1_graph(
    engine: RuleEngine,
    need_llm: Callable[[Alert, list[RuleHit]], bool],
    triage_resolver: Callable[[Alert, list[RuleHit]], Verdict],
):
    """v1 处置图（无证据注入，等价 make_v2_graph(evidence_builder=None)），保留兼容。"""
    return make_v2_graph(engine, need_llm, triage_resolver, evidence_builder=None)


# ============================================================ v3 处置分流（自进化规格 A · 命中源裁决）

_SEV_PRIO = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}


def _manual_fallback_verdict(alert: Alert, manual: list[dict], hits: list[RuleHit]) -> Verdict:
    """命中人工权威规则 → 潜意识直发：不唤醒 LLM，按人工规则定级并说明权威性。"""
    m = manual[0]
    sev = str(m.get("severity") or alert.priority).strip().lower()
    desc = (m.get("description") or m.get("name") or m["rule_id"])
    just = (f"命中人工权威规则 {m['rule_id']}（{desc}，severity={sev}）。"
            f"人工规则为确定性权威：直接按规则定级告警，无需 LLM 推理。")
    ev = [h.rule_id for h in hits] + [m["rule_id"]]
    mitre = alert.mitre or {}
    if mitre.get("id") or mitre.get("technique"):
        just += f" 关联 MITRE {mitre.get('id') or mitre.get('technique')}。"
        ev.append(str(mitre.get("id") or mitre.get("technique")))
    return Verdict(classification=None, priority=_SEV_PRIO.get(sev, alert.priority),
                   method="rule_fallback", justification=just, evidence=ev)


def _write_conflict_feedback(store: MemoryStore, alert: Alert, event: AlertEvent,
                             gt: str, by: str = "system") -> None:
    """『处置与后续效果冲突』才沉淀：LLM 判定(TP/FP) 与官方真值冲突 → 纠错/降噪经验片段。

    - fragment_id = fb-{dataset}-{alert_id}（幂等 upsert，重复运行覆盖）；
    - method='conflict'，classification=真值；审计 op=conflict.feedback。
    未冲突/规则直发（无 TP/FP 判定）一律不写 —— 保证沉淀是"选择性的"。
    """
    aid = str(alert.alert_id or event.seq)
    fid = f"fb-{alert.dataset}-{aid}"
    rl = alert.rule or {}
    groups = [g for g in (rl.groups or []) if isinstance(g, str)] if rl.groups else []
    agent = alert.agent or {}
    summary = (f"[处置冲突·沉淀] {alert.dataset}#{event.seq} 告警 {aid} 规则 "
               f"{rl.id or '-'}(lvl {rl.level}) 处置判 {event.verdict.classification}"
               f"({event.verdict.method}) 与真值 {gt} 冲突 → 该样本回传为纠错经验，"
               f"供新一轮可疑模式/降噪挖掘。")
    frag = Fragment(
        fragment_id=fid, dataset=alert.dataset, alert_id=aid, seq=event.seq,
        host=str(agent.get("name") or "-"), ts_ms=alert.ts_ms,
        rule_id=str(rl.id) if rl.id is not None else None,
        rule_level=rl.level, groups=groups, mitre=alert.mitre,
        classification=gt, verdict_priority=event.verdict.priority,
        method="conflict", llm_error=False, summary=summary,
        source={"alert": {"seq": event.seq, "dataset": alert.dataset, "alert_id": aid,
                          "text": (alert.text or "")[:2000]},
                "conflict": {"disposition": event.verdict.classification,
                             "disposed_by": event.verdict.method, "gt": gt,
                             "reason": "处置判定与官方/复核真值冲突，仅此类效果冲突样本写回记忆。"}},
        created_at=now_ms())
    store.upsert_fragments([frag])
    store.audit("fragment", fid, "conflict.feedback", by,
                f"处置冲突沉淀 feedback 片段：{summary[:180]}")


def make_v3_graph(
    engine: RuleEngine,
    triage_resolver: Callable[[Alert, list[RuleHit], Optional[str]], Verdict],
    evidence_builder: Optional[EvidenceBuilder] = None,
    store: Optional[MemoryStore] = None,
    fallback_need_llm: Optional[Callable[[Alert, list[RuleHit]], bool]] = None,
    manual_direct: bool = True,
    conflict_feedback: bool = False,
    conflict_by: str = "system",
    bump_fired: bool = True,
):
    """处置分流 v3：**由命中源裁决是否唤醒 LLM**（规格 A · 双向匹配）。

    分流三态（channel 记入事件）：
    1. `manual`：命中记忆库**人工权威规则**(auto=0) 且 manual_direct → 潜意识直发，
       不检索证据、不唤醒 LLM（按人工规则定级）；
    2. `memory`：未命中人工，但命中**过去已成型的可疑模式**（支撑片段全早于当前、
       防泄漏）或**相似历史记忆** → gather_evidence(模式+片段+图谱) 后**必走 LLM 推理**；
    3. `policy`：无记忆命中 → 按 fallback_need_llm 策略决定是否 LLM（无证据）。

    冲突沉淀（可选，仅效果冲突写回）：LLM 处置 TP/FP 与官方真值（Alert.verdict.label）
    冲突 → `fb-{dataset}-{alert_id}` feedback 片段幂等写回（method='conflict'）供新一轮
    模式/降噪挖掘；规则直发(无 TP/FP 判定)或未冲突一律不写。

    兼容性：evidence_builder/store 均缺省时等价 v1 策略图（无记忆无人工池）。
    """
    mem_store = store or (evidence_builder.store if evidence_builder is not None else None)
    manual_rules = load_manual_rules(mem_store) if mem_store is not None else []

    def _node_match(s: dict) -> dict:
        alert: Alert = s["alert"]
        hits = engine.match(alert)
        manual = match_manual(alert, manual_rules)
        return {"rule_hits": hits, "manual_hits": manual}

    def _node_direct(s: dict) -> dict:
        """通道 manual：命中人工权威规则 → 直发结论（不耗 LLM）。"""
        alert: Alert = s["alert"]
        manual = s.get("manual_hits") or []
        verdict = _manual_fallback_verdict(alert, manual, s.get("rule_hits") or []) if manual \
            else fallback_verdict(alert, s.get("rule_hits") or [])
        return {"channel": "manual", "need_llm": False, "verdict": verdict}

    def _node_gather(s: dict) -> dict:
        """通道 memory/policy：先看是否存在『过去模式命中 / 相似记忆』。"""
        alert: Alert = s["alert"]
        hits = s.get("rule_hits") or []
        cover_pats: list = []
        sim_frags = 0
        evidence = None
        counts = None
        if evidence_builder is not None:
            query = ((alert.text or "") + " " +
                     (hits[0].description or "" if hits else ""))[:3000]
            res = evidence_builder.collect(
                dataset=alert.dataset, query=query,
                techniques=_mitre_techniques(alert), seq_now=s["seq"],
                with_memory=True, with_kb=True)
            evidence = res["evidence_text"] or None
            counts = res["counts"]
            sim_frags = counts["frags"]
            cover_pats = evidence_builder.active_patterns_covering_rule(
                alert.dataset, alert.rule_id, s["seq"]) if alert.rule_id else []
        # 命中可疑模式/相似记忆 → 显意识（记忆证据注入 LLM）；否则回退策略
        need = bool(cover_pats or sim_frags)
        channel = "memory" if need else "policy"
        if not need and fallback_need_llm is not None:
            need = bool(fallback_need_llm(alert, hits))
        if bump_fired and cover_pats and mem_store is not None:
            for p in cover_pats:
                rid = p.get("derived_rule_id")
                if not rid:
                    continue
                r = mem_store.rule_by_id(rid)
                if r is not None and r.get("enabled") and r.get("state") == "active" and r.get("auto"):
                    mem_store.bump_fired(rid, alert.ts_ms)
        return {"evidence": evidence, "evidence_counts": counts,
                "cover_patterns": cover_pats, "need_llm": need, "channel": channel}

    def _node_resolve(s: dict) -> dict:
        alert: Alert = s["alert"]
        verdict = triage_resolver(alert, s.get("rule_hits") or [], evidence=s.get("evidence"))
        return {"verdict": verdict, "need_llm": True}

    def _node_conflict(s: dict) -> dict:
        """仅效果冲突沉淀：LLM 判定与官方真值相反才写 feedback 片段。"""
        if conflict_feedback and mem_store is not None:
            alert: Alert = s["alert"]
            verdict = s.get("verdict")
            gt = (alert.verdict or {}).get("label")
            vc = verdict.classification if verdict else None
            if gt in ("TP", "FP") and vc in ("TP", "FP") and vc != gt:
                ev = AlertEvent(seq=s["seq"], ts_ms=alert.ts_ms,
                                ts_iso=(alert.time or {}).get("iso"),
                                dataset=alert.dataset,
                                alert_id=alert.alert_id, index=alert.index,
                                agent_name=(alert.agent or {}).get("name"),
                                rule_hits=s.get("rule_hits") or [], need_llm=True,
                                llm_used=verdict.method == "llm", verdict=verdict,
                                action="notify", notified=True, channel=s.get("channel", ""))
                _write_conflict_feedback(mem_store, alert, ev, gt, by=conflict_by)
        return {}

    def _node_alert_only(s: dict) -> dict:
        alert: Alert = s["alert"]
        verdict: Verdict = s["verdict"] or fallback_verdict(alert, s.get("rule_hits") or [])
        return {"event": AlertEvent(
            seq=s["seq"], ts_ms=alert.ts_ms, ts_iso=(alert.time or {}).get("iso"),
            dataset=alert.dataset, alert_id=alert.alert_id, index=alert.index,
            agent_name=(alert.agent or {}).get("name"),
            rule_hits=s.get("rule_hits") or [], need_llm=bool(s.get("need_llm")),
            llm_used=verdict.method == "llm", verdict=verdict,
            action="notify", notified=True, channel=s.get("channel", ""))}

    def _route_manual(s: dict) -> str:
        if manual_direct and (s.get("manual_hits") or []):
            return "direct"
        return "gather"

    def _route_memory(s: dict) -> str:
        return "resolve" if s.get("need_llm") else "alert_only"

    g = StateGraph(AgentState)
    g.add_node("match_rules", _node_match)
    g.add_node("decide_direct", _node_direct)
    g.add_node("gather_evidence", _node_gather)
    g.add_node("resolve", _node_resolve)
    g.add_node("check_conflict", _node_conflict)
    g.add_node("alert_only", _node_alert_only)
    g.add_edge(START, "match_rules")
    g.add_conditional_edges("match_rules", _route_manual,
                            {"direct": "decide_direct", "gather": "gather_evidence"})
    g.add_edge("decide_direct", "alert_only")
    g.add_conditional_edges("gather_evidence", _route_memory,
                            {"resolve": "resolve", "alert_only": "alert_only"})
    g.add_edge("resolve", "check_conflict")
    g.add_edge("check_conflict", "alert_only")
    g.add_edge("alert_only", END)
    return g.compile()

# -*- coding: utf-8 -*-
"""v1 Agent CLI：离线批量跑预处理产物 → LangGraph 处置流 → 仅告警(notify) JSONL 事件日志。

v1 能力边界：**Agent 只产生 notify 事件，无任何自主动作**（不封禁/不停服/不执行）。
每次运行重放一批告警：
    预处理 JSONL → Alert → 规则种子导入(人工规则池) → LangGraph 处置流
        → AlertEvent(action=notify) 逐条写 JSONL 事件日志 + 打印摘要

用法（在仓库根目录、conda scssa 环境内）：
    python scripts/run_agent_v1.py --source llm-soc --limit 5
    python scripts/run_agent_v1.py --source linux --limit 200 --no-llm
    python scripts/run_agent_v1.py --source all --llm-policy all        # llm-soc 178 全量研判
    python scripts/run_agent_v1.py --source llm-soc --joint-evidence   # v2：注入记忆+图谱证据再研判
    python scripts/run_agent_v1.py --out -                             # 事件打到 stdout 不写文件

LLM：默认读取环境变量 DEEPSEEK_API（base_url 默认 https://api.deepseek.com），
调用失败/超时自动回退规则结论并打 llm_error 标记；--no-llm 完全禁用真实调用。

--joint-evidence（处置流 v2）：need_llm 的告警先经 gather_evidence 检索"多层记忆相似片段
+ 可疑模式 + ATT&CK 图谱多跳"证据再注入 LLM 研判（需先有记忆基线 data/memory/memory.db；
seq 按数据集对齐，只引用 seq<当前 经验，防泄漏）。
"""
from __future__ import annotations

import argparse
import datetime as _dt
import io
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.config.settings import get_settings
from src.core.knowledge.graph import KnowledgeKB
from src.core.llm.client import LLMClient
from src.core.memory.evidence import EvidenceBuilder
from src.core.memory.store import MemoryStore
from src.core.models import Alert, AlertEvent
from src.core.rules.engine import RuleEngine, import_seed_rules
from src.core.workflow.disposition import (
    _default_state,
    make_triage_resolver,
    make_v2_graph,
    make_v3_graph,
)

SOURCE_FILES = {
    "linux": "data/processed/linux_apt_alerts.jsonl",
    "llm-soc": "data/processed/llm_soc_alerts.jsonl",
}


def load_alerts(path: str, limit: int) -> list[Alert]:
    """读取预处理 JSONL → Alert 列表（校验失败的跳过并计数）。"""
    out: list[Alert] = []
    bad = 0
    with io.open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(Alert.model_validate_json(line))
            except Exception:  # noqa: BLE001
                bad += 1
            if limit and len(out) >= limit:
                break
    if bad:
        print(f"[load] {path}: 跳过 {bad} 行解析失败")
    return out


def need_llm_rules(alert: Alert, hits) -> bool:
    """成本可控策略：先规则后模型。未命中 → 不判；命中 high(>=8) 或 中危带 MITRE 才走 LLM。"""
    if not hits:
        return False
    lv = hits[0].level or 0
    if lv >= 8:
        return True
    return bool(alert.mitre) and lv >= 4


def need_llm_all(alert: Alert, hits) -> bool:
    """命中即 LLM 研判（用于 llm-soc 178 全量评测基准）。"""
    return bool(hits)


def write_event_line(fh, event: AlertEvent) -> None:
    fh.write(json.dumps(event.model_dump(mode="json"), ensure_ascii=False) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser(description="v1 Agent：离线批量处置（仅告警 notify）")
    ap.add_argument("--source", choices=["linux", "llm-soc", "all"], default="all",
                    help="回放来源：单份预处理产物或全部（默认 all）")
    ap.add_argument("--limit", type=int, default=0,
                    help="只处理前 N 条（0=全部）")
    ap.add_argument("--no-llm", action="store_true",
                    help="禁用真实 LLM 调用（全部走规则回退）")
    ap.add_argument("--llm-policy", choices=["rules", "all"], default="rules",
                    help="need_llm 判定策略：rules=高危/带 MITRE 中危；all=命中即判")
    ap.add_argument("--joint-evidence", action="store_true",
                    help="处置流 v2：need_llm 告警先 gather_evidence（记忆+图谱）再注入 LLM 研判")
    ap.add_argument("--triage", choices=["v1", "v2", "v3"], default="v1",
                    help="处置图版本：v1=无证据策略；v2=need_llm 后 gather 证据；"
                         "v3=按命中源裁决（人工规则直发 / 可疑模式→必走 LLM）+ 可选冲突沉淀）")
    ap.add_argument("--v3-manual-llm", action="store_true",
                    help="v3：命中人工权威规则也走记忆→LLM（关闭‘人工直发’），用于评测对照")
    ap.add_argument("--conflict-feedback", action="store_true",
                    help="v3：仅当处置 TP/FP 与官方真值冲突时，写回 feedback 片段（纠错/降噪经验）")
    ap.add_argument("--out", default="", help="事件 JSONL 输出路径；'-'=stdout（默认 log/agent_v1_events_*.jsonl）")
    args = ap.parse_args()

    # 按数据集分批装载（seq 各自从 1 起，保证与记忆库片段序号对齐）
    srcs = ["linux", "llm-soc"] if args.source == "all" else [args.source]
    datasets: list[tuple[str, list[Alert]]] = []
    for s in srcs:
        p = SOURCE_FILES[s]
        if not os.path.exists(p):
            print(f"[err] 缺失预处理产物: {p}（先跑 scripts/preprocess_datasets.py）")
            return 2
        loaded = load_alerts(p, args.limit)
        if not loaded:
            print(f"[warn] {p} 为空，跳过")
            continue
        datasets.append((s, loaded))
    if not datasets:
        print("[err] 无可用告警输入")
        return 2
    alerts = [a for _, items in datasets for a in items]
    src_names = ", ".join(s for s, _ in datasets)

    # 1) 规则种子导入（人工规则池）+ 引擎
    seeds = import_seed_rules(alerts)
    engine = RuleEngine(seeds)
    print(f"[init] 导入 {len(seeds)} 条人工规则种子，回放 {len(alerts)} 条告警（{src_names}）")

    # 2) LLM 客户端 + 研判（--no-llm 时 llm=None 走规则回退）
    settings = get_settings()
    llm = None if args.no_llm else LLMClient(settings)
    if llm is None or not llm.available:
        print("[llm] 未启用（--no-llm 或无 DEEPSEEK_API），所有研判走规则回退 rule_fallback")
    else:
        print(f"[llm] 启用 {settings.llm_model} @ {settings.llm_base_url}")
    resolver = make_triage_resolver(llm)
    policy = need_llm_rules if args.llm_policy == "rules" else need_llm_all

    # 3) 处置图（v2/v3 = 可选 gather_evidence；默认 v1 只告警）
    store, evidence_builder = None, None
    triage = args.triage
    if args.joint_evidence and triage in ("v1", "v2"):
        triage = "v2"
    if triage in ("v2", "v3"):
        store = MemoryStore()
        evidence_builder = EvidenceBuilder(store, KnowledgeKB())
        print("[memory] 启用联合证据：多层记忆 + ATT&CK 图谱（流式 seq<当前 防泄漏）")
    if triage == "v1":
        graph = make_v2_graph(engine, policy, resolver, evidence_builder=None)
    elif triage == "v2":
        graph = make_v2_graph(engine, policy, resolver, evidence_builder=evidence_builder)
    else:  # v3：按命中源裁决（人工规则直发 / 模式命中必走 LLM / 可选冲突沉淀）
        graph = make_v3_graph(engine, resolver, evidence_builder=evidence_builder,
                              store=store, fallback_need_llm=policy,
                              manual_direct=not args.v3_manual_llm,
                              conflict_feedback=args.conflict_feedback)
        print("[triage] v3 分流：manual=人工规则直发（不耗 LLM）；memory=可疑模式/相似记忆→LLM 推理；"
              f"manual_direct={not args.v3_manual_llm}；conflict_feedback={args.conflict_feedback}")

    # 4) 批量跑批（seq 按数据集从 1 起，与记忆库片段序号对齐）
    events: list[AlertEvent] = []
    for _, items in datasets:
        for seq, alert in enumerate(items, start=1):
            state = graph.invoke(_default_state(seq, alert))
            events.append(state["event"])

    # 5) 输出事件日志
    out_path = args.out
    if out_path == "-":
        for e in events:
            print(json.dumps(e.model_dump(mode="json"), ensure_ascii=False))
    else:
        if not out_path:
            ts = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
            os.makedirs("log", exist_ok=True)
            out_path = os.path.join("log", f"agent_v1_events_{ts}.jsonl")
        with io.open(out_path, "w", encoding="utf-8") as fh:
            for e in events:
                write_event_line(fh, e)
        print(f"[out] 事件日志: {out_path}（{len(events)} 行）")

    # 6) 摘要
    n_hit = sum(1 for e in events if e.rule_hits)
    n_need_llm = sum(1 for e in events if e.need_llm)
    n_llm_used = sum(1 for e in events if e.llm_used)
    n_llm_err = sum(1 for e in events if e.verdict.llm_error)
    acts = {e.action for e in events}
    not_ntf = sum(1 for e in events if not e.notified)
    from collections import Counter
    cls = Counter(e.verdict.classification for e in events)
    print("\n===== Agent 运行摘要（仅告警 notify，禁止自主动作） =====")
    print(f"  告警总数      : {len(events)}")
    print(f"  命中人工规则  : {n_hit}（规则池 {len(engine)} 条）")
    print(f"  需 LLM 研判   : {n_need_llm}")
    print(f"  LLM 实判      : {n_llm_used}（失败回退: {n_llm_err}）")
    if triage == "v3":
        ch = Counter(e.channel or "-" for e in events)
        ch_llm = Counter(e.channel or "-" for e in events if e.need_llm)
        print(f"  v3 分流通路   : {dict(ch)}（其中需 LLM={dict(ch_llm)}）")
    print(f"  分类分布      : TP={cls['TP']} FP={cls['FP']} UNKNOWN={cls[None]}  (None=规则回退不判分类)")
    print(f"  动作集合      : {sorted(acts)}（v1 只允许 notify）")
    print(f"  未通知(异常)  : {not_ntf}")
    print("  命中 TOP 规则 :")
    for r in engine.stats()[:5]:
        print(f"    rule {r['rule_id']:<8} level={str(r['level']):<4} "
              f"fired={r['fired_times']:<5} {str(r['description'])[:60]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

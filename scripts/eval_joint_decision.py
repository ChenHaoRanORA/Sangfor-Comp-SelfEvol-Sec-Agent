# -*- coding: utf-8 -*-
"""联合决策消融评测（llm-soc 178 官方标签集）。

目的：验证"多层记忆 + 知识图谱"证据注入是否提升 LLM 研判效果（相对无上下文基线）。
- 基线：复用历史无上下文 LLM 处置事件（log/agent_v1_llm_soc_full_178.jsonl，与当前 triage 提示词一致）；
- 增强组（真实调用 DeepSeek）：+图谱(kb) / +多层记忆(mem) / +联合(joint)；
- 防泄漏：流式切分——每条告警只能引用 seq 更早的片段与由它们归纳出的模式；
- 指标：TP/FP 分类 Acc、决定子集 Acc、宏 F1、UNKNOWN 率、优先级命中率、LLM 调用数与耗时。

用法：
  python scripts/eval_joint_decision.py [--arms mem,kb,joint] [--limit N] [--fresh]
结果：log/eval_joint/{arm}.jsonl（逐条，可续跑）+ log/eval_joint/summary.json
"""
from __future__ import annotations

import argparse
import io
import json
import os
import sys
import time
from collections import Counter
from statistics import mean

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.core.knowledge.graph import KnowledgeKB          # noqa: E402
from src.core.llm.client import LLMClient, LLMError       # noqa: E402
from src.core.memory.evidence import EvidenceBuilder      # noqa: E402
from src.core.memory.store import MemoryStore             # noqa: E402
from src.core.models import Alert, RuleHit                # noqa: E402
from src.core.workflow.disposition import fingerprint     # noqa: E402

ALERTS = os.path.join("data", "processed", "llm_soc_alerts.jsonl")
EVENTS = os.path.join("log", "agent_v1_llm_soc_full_178.jsonl")
OUT_DIR = os.path.join("log", "eval_joint")
DATASET = "llm-soc"
_ALLOWED_CLS = ("TP", "FP", "UNKNOWN")
_ALLOWED_PRIO = ("low", "medium", "high", "critical")
_SEV = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def load_alerts(path: str) -> list[Alert]:
    with io.open(path, encoding="utf-8") as fh:
        return [Alert.model_validate_json(line) for line in fh if line.strip()]


def load_events(path: str) -> list[dict]:
    with io.open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def mitre_techniques(alert: Alert) -> list[str]:
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


def normalize_priority(p) -> Optional[str]:
    p = str(p or "").strip().lower()
    return p if p in _ALLOWED_PRIO else None


def severity(pred: Optional[str], gt: Optional[str]) -> Optional[dict]:
    """优先级细分（预测/真值精确、过度、不足、严重两类）。"""
    a, b = normalize_priority(pred), normalize_priority(gt)
    if a is None or b is None:
        return None
    d = _SEV[a] - _SEV[b]
    return {"exact": d == 0, "over": d > 0, "under": d < 0,
            "severe_pair": (a, b)}


def parse_verdict(obj: dict, fallback_prio: str) -> dict:
    """与处置流一致的 LLM 输出规整。"""
    cls = obj.get("classification")
    if cls not in _ALLOWED_CLS:
        cls = None
    prio = normalize_priority(obj.get("priority")) or fallback_prio
    return {"classification": cls, "priority": prio}


def summarize(rows: list[dict]) -> dict:
    n = len(rows)
    gt_lab = [r["gt"] for r in rows]
    got = [r["cls"] for r in rows]
    gt_prio = [r["gt_priority"] for r in rows]
    got_prio = [r["priority"] for r in rows]

    acc_all = sum(1 for g, c in zip(gt_lab, got) if c == g) / n if n else 0.0
    decided = [(g, c) for g, c in zip(gt_lab, got) if c in ("TP", "FP")]
    acc_dec = sum(1 for g, c in decided if c == g) / len(decided) if decided else 0.0

    # 宏 F1（TP/FP 两类，决定性输出上）
    prec_rec = {}
    for lab in ("TP", "FP"):
        tp = sum(1 for g, c in decided if g == lab and c == lab)
        fp = sum(1 for g, c in decided if g != lab and c == lab)
        fn = sum(1 for g, c in decided if g == lab and c != lab)
        p = tp / (tp + fp) if tp + fp else 0.0
        r = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * p * r / (p + r) if p + r else 0.0
        prec_rec[lab] = {"precision": p, "recall": r, "f1": f1}
    macro_f1 = mean([prec_rec["TP"]["f1"], prec_rec["FP"]["f1"]])

    unk = sum(1 for c in got if c == "UNKNOWN")
    none = sum(1 for c in got if c is None)
    prio_exact = sum(1 for a, b in zip(got_prio, gt_prio)
                     if a and b and normalize_priority(a) == normalize_priority(b)) / n if n else 0.0
    return {
        "n": n,
        "acc_all": round(acc_all, 4),
        "acc_decided": round(acc_dec, 4),
        "macro_f1_decided": round(macro_f1, 4),
        "tp": prec_rec["TP"],
        "fp": prec_rec["FP"],
        "unknown_rate": round(unk / n, 4) if n else 0.0,
        "none_rate": round(none / n, 4) if n else 0.0,
        "priority_exact": round(prio_exact, 4),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--arms", default="mem,kb,joint",
                    help="需真实调用 LLM 的增强组（逗号分隔：mem/kb/joint）")
    ap.add_argument("--limit", type=int, default=0, help=">0 时只跑前 N 条（冒烟）")
    ap.add_argument("--fresh", action="store_true", help="删除既有结果重跑")
    args = ap.parse_args()

    llm = LLMClient()
    if not llm.available:
        sys.exit("未配置 DEEPSEEK_API，增强组无法评测")
    arms = [a.strip() for a in args.arms.split(",") if a.strip()]
    os.makedirs(OUT_DIR, exist_ok=True)

    alerts = load_alerts(ALERTS)
    events = load_events(EVENTS)
    assert len(alerts) == len(events) == 178, (len(alerts), len(events))
    if args.limit:
        alerts, events = alerts[:args.limit], events[:args.limit]
    rows_n = len(alerts)

    store = MemoryStore()
    builder = EvidenceBuilder(store, KnowledgeKB())
    memo: dict[str, dict] = {}

    results: dict[str, list[dict]] = {"baseline": []}

    # ---- 基线：直接复用历史无上下文 LLM 处置事件
    for i, ev in enumerate(events):
        v = ev.get("verdict") or {}
        results["baseline"].append({
            "seq": i + 1,
            "alert_id": alerts[i].alert_id,
            "gt": (alerts[i].verdict or {}).get("label"),
            "gt_priority": (alerts[i].verdict or {}).get("gt_priority"),
            "cls": v.get("classification"), "priority": v.get("priority"),
            "method": v.get("method"), "evidence": {"frags": 0, "patterns": 0, "kb": 0},
            "calls": 0, "cost_s": 0.0,
        })

    for arm in arms:
        path = os.path.join(OUT_DIR, f"{arm}.jsonl")
        if args.fresh and os.path.exists(path):
            os.remove(path)
        done: set[int] = set()
        rows: list[dict] = []
        if os.path.exists(path):
            with io.open(path, encoding="utf-8") as fh:
                for line in fh:
                    r = json.loads(line)
                    done.add(r["seq"])
                    rows.append(r)
        results[arm] = rows

        calls = 0
        t0 = time.time()
        for i, alert in enumerate(alerts):
            seq = i + 1
            if seq in done:
                continue
            ev = events[i]
            hits = [RuleHit(**h) for h in (ev.get("rule_hits") or [])]
            desc = hits[0].description if hits else None
            lvl = hits[0].level if hits else None
            fp = fingerprint(alert)
            key = (arm, fp)
            if key in memo:
                obj = memo[key]
            else:
                with_memory = arm in ("mem", "joint")
                with_kb = arm in ("kb", "joint")
                q = (alert.text + " " + (desc or ""))[:3000]
                evd = builder.collect(
                    DATASET, q, mitre_techniques(alert), seq_now=seq,
                    with_memory=with_memory, with_kb=with_kb)
                try:
                    calls += 1
                    obj = llm.triage(
                        dataset=DATASET, text=alert.text,
                        rule_desc=desc, rule_level=lvl, mitre=alert.mitre,
                        fingerprint=fp, evidence=evd["evidence_text"])
                    obj["_eval"] = evd["counts"]
                except LLMError as exc:
                    print(f"[{arm}] seq={seq} LLM 失败，跳过本次续跑: {exc}")
                    continue
                memo[key] = obj
            v = parse_verdict(obj, alert.priority)
            row = {
                "seq": seq, "alert_id": alert.alert_id,
                "gt": (alert.verdict or {}).get("label"),
                "gt_priority": (alert.verdict or {}).get("gt_priority"),
                "cls": v["classification"], "priority": v["priority"],
                "method": "llm",
                "evidence": obj.get("_eval", {"frags": 0, "patterns": 0, "kb": 0}),
                "calls": 1, "cost_s": round((obj.get("_llm_meta") or {}).get("cost_s", 0.0), 3),
            }
            rows.append(row)
            with io.open(path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(row, ensure_ascii=False) + "\n")
        print(f"[{arm}] {len(rows)}/{rows_n} 完成，新增调用 {calls}，耗时 {time.time() - t0:.1f}s")

    # ---- 汇总对比
    print("\n" + "=" * 92)
    print(f"llm-soc 178 联合决策消融（流式防泄漏；每组 {rows_n} 条）")
    print("=" * 92)
    header = ["arm", "acc_all", "acc_dec", "macroF1", "TP(P/R/F1)", "unk%", "prio%", "calls"]
    print(f"{header[0]:<9}{header[1]:>8}{header[2]:>8}{header[3]:>8}"
          f"{header[4]:>18}{header[5]:>8}{header[6]:>8}{header[7]:>7}")
    for arm, rows in results.items():
        if not rows:
            continue
        s = summarize(rows)
        tp = s["tp"]
        calls = sum(r.get("calls") or 0 for r in rows)
        print(f"{arm:<9}{s['acc_all']:>8.3f}{s['acc_decided']:>8.3f}{s['macro_f1_decided']:>8.3f}"
              f"{tp['precision']:>6.2f}/{tp['recall']:.2f}/{tp['f1']:.2f}"
              f"{s['unknown_rate']:>8.2%}{s['priority_exact']:>8.2%}{calls:>7}")

    # 相对基线净变化（决定性输出上）
    base = results.get("baseline") or []
    for arm in arms:
        rows = results.get(arm) or []
        if not rows:
            continue
        by_seq = {r["seq"]: r for r in rows}
        base_by = {r["seq"]: r for r in base}
        chg_better = chg_worse = same = 0
        for seq, br in base_by.items():
            ar = by_seq.get(seq)
            if not ar or br.get("cls") is None:
                continue
            if ar["cls"] == br["cls"]:
                same += 1
                continue
            if ar["cls"] == br.get("gt"):
                chg_better += 1
            else:
                chg_worse += 1
        print(f"[{arm}] 相对基线分类翻转: 改对 {chg_better} / 改错 {chg_worse} / 不变 {same}")

    with io.open(os.path.join(OUT_DIR, "summary.json"), "w", encoding="utf-8") as fh:
        json.dump({k: summarize(v) for k, v in results.items() if v},
                  fh, ensure_ascii=False, indent=2)
    print(f"\n结果明细 → {OUT_DIR}/*.jsonl；汇总 → {os.path.join(OUT_DIR, 'summary.json')}")


if __name__ == "__main__":
    main()

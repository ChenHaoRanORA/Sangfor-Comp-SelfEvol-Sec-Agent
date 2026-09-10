# -*- coding: utf-8 -*-
"""处置分流 v3 冒烟：在临时副本 memory 上验证『命中源裁决 + 仅冲突沉淀』。

覆盖断言：
1. 命中记忆库人工权威规则(auto=0) → channel=manual、need_llm=False、**LLM 不被唤醒**；
2. 无记忆(seq 起点)且未命中人工 → 回退策略 policy：命中即走 LLM（可控 resolver）；
3. 命中『过去可疑模式』(防泄漏) → channel=memory、必走 LLM，且派生规则 fired_times 随命中递增；
4. 仅『处置与真值冲突』写回 feedback 片段（method=conflict、classification=真值、审计 conflict.feedback），
   未冲突不写；同告警重复冲突幂等覆盖（始终 1 条）。
"""
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ---------- 临时副本记忆库 ----------
tmp = tempfile.mkdtemp(prefix="smoke_v3_")
print("[smoke] temp memory copy:", tmp)
mem_src = os.path.join("data", "memory")
for name in os.listdir(mem_src):
    s = os.path.join(mem_src, name)
    d = os.path.join(tmp, name)
    (shutil.copytree(s, d) if os.path.isdir(s) else shutil.copy2(s, d))

import io  # noqa: E402
from src.core.memory.store import MemoryStore  # noqa: E402
from src.core.memory.evidence import EvidenceBuilder  # noqa: E402
from src.core.models import Alert, Verdict  # noqa: E402
from src.core.rules.engine import RuleEngine, import_seed_rules  # noqa: E402
from src.core.rules.pools import load_manual_rules  # noqa: E402
from src.core.workflow.disposition import make_v3_graph, _default_state  # noqa: E402

store = MemoryStore(db_path=os.path.join(tmp, "memory.db"), chroma_dir=os.path.join(tmp, "chroma"))

# ---------- llm-soc 告警 + 种子规则 ----------
alerts = [Alert.model_validate_json(line) for line in io.open(
    "data/processed/llm_soc_alerts.jsonl", encoding="utf-8") if line.strip()]
engine = RuleEngine(import_seed_rules(alerts))
print("[smoke] alerts=%d seeds=%d" % (len(alerts), len(engine)))

# 注入一条"人工权威规则"覆盖 rule 92032（模拟升格/人工创建 → auto=0）
store.add_rule({
    "rule_id": "MR-TEST-92032", "rule_type": "derived", "name": "92032 人工权威",
    "description": "人工拍板：92032 直接告警无需 LLM", "enabled": True, "state": "active",
    "expression": [{"field": "rule.id", "op": "in", "value": [92032]}],
    "severity": "High", "source_pattern_id": None, "owner": "analyst",
    "auto": False, "audit": []})
assert any(r["rule_id"] == "MR-TEST-92032" for r in load_manual_rules(store)), "人工规则应可被加载"

builder = EvidenceBuilder(store, kb=None)
PASS, FAIL = [], []


def check(label, cond, extra=""):
    (PASS if cond else FAIL).append(label)
    print(("  [PASS] " if cond else "  [FAIL] ") + label + ("" if not extra else "  " + str(extra)))


def idx_of(rule_id):
    """该规则第一次出现的 (seq, index, alert)。"""
    for i, a in enumerate(alerts, start=1):
        if a.rule_id == rule_id:
            return i, i - 1, a
    return None


def gt_of(alert):
    return (alert.verdict or {}).get("label")


# ============================================================ 场景 1：命中人工规则 → 直发（LLM 不得被唤醒）
_seq_m, _i_m, a_m = idx_of("92032")
assert a_m is not None, "llm-soc 应有 rule 92032 告警"

def _never_llm(alert, hits, evidence=None):
    raise AssertionError(f"人工规则命中不应唤醒 LLM (seq={_seq_m})")

g_manual = make_v3_graph(engine, _never_llm, evidence_builder=builder, store=store,
                         manual_direct=True, conflict_feedback=True)
ev_m = g_manual.invoke(_default_state(_seq_m, a_m))["event"]
check("人工规则命中 → channel=manual", ev_m.channel == "manual", ev_m.channel)
check("人工规则命中 → need_llm=False（不耗 LLM）", ev_m.need_llm is False)
check("人工规则命中 → 结论来自规则定级(rule_fallback)",
      ev_m.verdict.method == "rule_fallback" and "人工权威" in ev_m.verdict.justification)
check("人工规则命中 → 不写任何 feedback（无 TP/FP 冲突可判）",
      sum(1 for f in store.fragments(limit=10**6) if str(f["fragment_id"]).startswith("fb-llm-soc-")) == 0)

# ============================================================ 场景 2：无记忆起点 → 策略回退 policy（命中即 LLM）
_seq1 = 1
a1 = alerts[0]

def _resolver_gt(alert, hits, evidence=None):
    g = gt_of(alert)
    return Verdict(classification=g, priority=alert.priority, method="llm",
                   justification=f"[smoke-fake] 真值 {g}")

g_policy = make_v3_graph(engine, _resolver_gt, evidence_builder=builder, store=store,
                         fallback_need_llm=lambda a, h: bool(h), manual_direct=True,
                         conflict_feedback=True)
ev1 = g_policy.invoke(_default_state(_seq1, a1))["event"]
check("seq=1（无过去记忆）→ channel=policy", ev1.channel == "policy", ev1.channel)
check("seq=1 命中种子且策略 all → need_llm=True", ev1.need_llm is True)
check("seq=1 LLM 实判（fake resolver 被调用）", ev1.llm_used is True and ev1.verdict.method == "llm")
n_fb_before = sum(1 for f in store.fragments(limit=10**6)
                  if str(f["fragment_id"]) == f"fb-llm-soc-{a1.alert_id}")
check("处置与真值一致 → 不写 feedback（选择性沉淀）", n_fb_before == 0, n_fb_before)

# ============================================================ 场景 3：处置与真值冲突 → 仅冲突写回 + 幂等
def _resolver_flip(alert, hits, evidence=None):
    g = gt_of(alert)
    opp = "FP" if g == "TP" else "TP"
    return Verdict(classification=opp, priority=alert.priority, method="llm",
                   justification=f"[smoke-fake] 故意判反 → {opp}")

g_flip = make_v3_graph(engine, _resolver_flip, evidence_builder=builder, store=store,
                       fallback_need_llm=lambda a, h: bool(h), manual_direct=True,
                       conflict_feedback=True)
fid1 = f"fb-llm-soc-{a1.alert_id}"
g_flip.invoke(_default_state(_seq1, a1))
rows = [f for f in store.fragments(limit=10**6) if f["fragment_id"] == fid1]
check("冲突 → 写回 feedback 片段 1 条", len(rows) == 1, len(rows))
if rows:
    check("冲突片段 method=conflict / classification=真值",
          rows[0]["method"] == "conflict" and rows[0]["classification"] == gt_of(a1),
          (rows[0]["method"], rows[0]["classification"]))
check("冲突写审计 conflict.feedback",
      any(a["op"] == "conflict.feedback" for a in store.audit_log(scope="fragment", limit=100)))
g_flip.invoke(_default_state(_seq1, a1))   # 再冲突一次 → 幂等覆盖
n_after = sum(1 for f in store.fragments(limit=10**6) if f["fragment_id"] == fid1)
check("重复冲突 → 幂等（仍 1 条）", n_after == 1, n_after)

# ============================================================ 场景 4：命中『过去可疑模式』→ memory 必走 LLM + fired 递增
def first_cover(avoid_rule="92032"):
    """首个被 active 过去模式覆盖（防泄漏）且非人工覆盖的 (seq, alert, pattern)。"""
    pats = store.patterns(dataset="llm-soc", state="active")
    seq_map = store.fragment_seqs()
    for seq, a in enumerate(alerts, start=1):
        if a.rule_id == avoid_rule:
            continue
        for p in pats:
            if a.rule_id not in (p.get("rule_ids") or []):
                continue
            sids = p.get("supporting_fragment_ids") or []
            seqs = [seq_map[s] for s in sids if s in seq_map]
            if len(seqs) == len(sids) and all(s < seq for s in seqs):
                if p.get("derived_rule_id"):
                    return seq, a, p
    return None

cand = first_cover()
if cand:
    seq_c, a_c, pat_c = cand
    rid = pat_c["derived_rule_id"]
    before = store.rule_by_id(rid)["fired_times"]
    ev_c = g_policy.invoke(_default_state(seq_c, a_c))["event"]   # 复用正确 resolver
    after = store.rule_by_id(rid)["fired_times"]
    check("命中过去可疑模式 → channel=memory", ev_c.channel == "memory", ev_c.channel)
    check("命中可疑模式 → 必走 LLM 推理", ev_c.need_llm is True and ev_c.llm_used is True)
    check("命中可疑模式 → 对应衍生规则 fired_times +1", after == before + 1, (before, after))
    # 场景 4 告警未冲突（resolver 返回真值）→ 不新增 feedback
    nf = sum(1 for f in store.fragments(limit=10**6) if f["fragment_id"] == f"fb-llm-soc-{a_c.alert_id}")
    check("命中模式且处置正确 → 不写 feedback", nf == 0, nf)
else:
    check("发现可复现的‘过去模式命中’样本（库基线含该场景）", False, "未找到 cover 样本")

print()
print(f"[smoke] 分流 v3 冒烟: PASS={len(PASS)} FAIL={len(FAIL)}")
print("[smoke] temp removed")
shutil.rmtree(tmp, ignore_errors=True)
raise SystemExit(1 if FAIL else 0)

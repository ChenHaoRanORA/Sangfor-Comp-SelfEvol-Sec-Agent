# -*- coding: utf-8 -*-
"""衍生规则器 v1：可疑模式 → 衍生规则自动编译入库（自动 CRUD，含审计）。

- 自动 create：active 的可疑模式编译为衍生规则（DSL = 命中 rule.id 集 + 严重度）；
- 自动 merge：规则集与既有衍生规则重复 → 模式并入旧规则（superseded + 审计），不重复建；
- fp_noise 降噪提议默认 state=draft（需人工确认启用），不参与实时命中基线；
- 门控：受演化总开关约束（auto_evolve off → 只保留模式，不建规则）；
- fired 基线：离线跑批按支撑片段回放，统计衍生规则在该数据集的生效次数。
"""
from __future__ import annotations

import datetime
from typing import Optional

from src.core.evolve.common import level_sev
from src.core.memory.models import now_ms
from src.core.memory.store import MemoryStore


def _set_key(expression: list) -> frozenset:
    for p in expression or []:
        if p.get("field") == "rule.id" and p.get("op") == "in":
            return frozenset(str(x) for x in p["value"])
    return frozenset()


def _val(value: list) -> list:
    """rule.id 值类型尽量贴合数据集（数字规则 id 转 int，字符串保持 str）。"""
    return [int(r) if str(r).isdigit() else r for r in value]


class RuleCompiler:
    def __init__(self, store: MemoryStore, by: str = "system"):
        self.store = store
        self.by = by
        self._date = datetime.datetime.now().strftime("%Y%m%d")

    # ---------------------------------------------------------- 单模式编译
    def _rule_id(self) -> str:
        return f"DR-{self._date}-{len(self.store.rules()) + 1:04d}"

    def _severity_of(self, p: dict) -> str:
        """模式支撑片段的最大告警等级 → 严重度。"""
        frags = self.store.fragment_by_ids(p.get("supporting_fragment_ids") or [])
        levels = []
        for f in frags:
            for hit in (f.get("source") or {}).get("rule_hits") or []:
                lv = hit.get("level")
                if lv:
                    levels.append(int(lv))
        return level_sev(max(levels)) if levels else "medium"

    def compile_one(self, p: dict) -> Optional[dict]:
        pid = p["pattern_id"]
        rule_ids = sorted({str(x) for x in (p.get("rule_ids") or [])})
        if not rule_ids or int(p.get("hits") or 0) < 2:
            return None
        sig = frozenset(rule_ids)
        for old in self.store.rules(state="active"):
            if _set_key(old.get("expression") or []) == sig:
                self.store.pattern_merge_link(pid, old["rule_id"], by=self.by)
                return None
        rid = self._rule_id()
        sev = self._severity_of(p)
        action = {"max_tier": "A1", "allow": ["snapshot", "query"]} \
            if sev in ("High", "Critical") else {"max_tier": "A0", "allow": []}
        # fp_noise：降噪提议 draft（需人工确认启用），不自动激活
        state = "draft" if p.get("kind") == "fp_noise" else "active"
        enabled = state == "active"
        rule = {
            "rule_id": rid, "rule_type": "derived",
            "name": (p.get("title") or pid)[:120],
            "description": p.get("description") or "",
            "enabled": enabled,
            "state": state,
            "expression": [{"field": "rule.id", "op": "in", "value": _val(rule_ids)}],
            "severity": sev if p.get("kind") != "fp_noise" else "Low",
            "action_policy": action if p.get("kind") != "fp_noise"
            else {"max_tier": "A0", "allow": []},
            "source_pattern_id": pid,
            "owner": "system",
            "auto": True,
            "audit": [{"ts": now_ms(), "op": "auto.create", "by": self.by,
                       "note": f"由可疑模式 {pid}（{p.get('kind')}，{p.get('hits')} 片段支撑）编译，"
                               + ("门控通过(active)。" if state == "active"
                                  else "降噪提议 draft，需人工确认后启用。")}],
        }
        self.store.add_rule(rule)
        self.store.audit("rule", rid, "auto.create", self.by,
                         f"衍生规则 {rid} 由模式 {pid} 编译（severity={rule['severity']}，"
                         f"覆盖 {len(rule_ids)} 条规则，state={state}）")
        # 模式回填指向（溯源：模式 → 衍生规则）；下次跑批自动跳过
        self.store.pattern_patch(pid, by=self.by, derived_rule_id=rid)
        return self.store.rule_by_id(rid)

    # ---------------------------------------------------------- 跑批（演化入口）
    def run(self, dataset: str) -> dict:
        if not self.store.auto_evolve():
            active = self.store.patterns(dataset=dataset, state="active")
            return {"created": [], "skipped": [p["pattern_id"] for p in active],
                    "auto_evolve": False,
                    "note": "自动演化总开关关闭：模式已留存，未编译衍生规则。"}
        created, skipped = [], []
        for p in self.store.patterns(dataset=dataset, state="active"):
            if p.get("derived_rule_id"):
                continue
            r = self.compile_one(p)
            if r:
                created.append(r)
            else:
                skipped.append(p["pattern_id"])
        return {"created": created, "skipped": skipped, "auto_evolve": True}

    # ---------------------------------------------------------- fired 基线回放
    def _rules_of_dataset(self, dataset: str) -> list[dict]:
        """只取"本数据集模式编译出的"衍生规则（经 source_pattern → pattern.dataset）。"""
        ds_pattern_ids = {p["pattern_id"] for p in self.store.patterns(dataset=dataset)}
        return [r for r in self.store.rules(state="active")
                if r.get("source_pattern_id") in ds_pattern_ids]

    def replay_baseline(self, dataset: str) -> dict:
        """按支撑片段回放：统计本数据集衍生规则命中成员规则的事件次数（数据集内）。"""
        by_rid: dict[str, list[int]] = {}
        for f in self.store.fragments(dataset=dataset, limit=10_000_000):
            rid = str(f.get("rule_id") or "")
            if rid:
                by_rid.setdefault(rid, []).append(int(f.get("ts_ms") or 0))
        fired: dict[str, dict] = {}
        for r in self._rules_of_dataset(dataset):
            tss = []
            for rid in _set_key(r.get("expression") or []):
                tss += by_rid.get(rid, [])
            self.store.set_fired(r["rule_id"], len(tss), max(tss) if tss else None)
            fired[r["rule_id"]] = {"fired": len(tss),
                                   "last_triggered_at": max(tss) if tss else None}
        return {"dataset": dataset, "fired": fired}

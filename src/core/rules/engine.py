# -*- coding: utf-8 -*-
"""v1 规则引擎：人工规则池 = 数据集中 Wazuh 规则种子；命中即 fired_times++。"""
from __future__ import annotations

from typing import Iterable, Optional

from src.core.models import Alert, RuleHit, RuleSeed


def _merge_groups(base: Optional[list], incoming: Optional[list]) -> Optional[list]:
    out = list(base or [])
    for g in incoming or []:
        if isinstance(g, str) and g not in out:
            out.append(g)
    return out or None


def import_seed_rules(alerts: Iterable[Alert]) -> dict[str, RuleSeed]:
    """从告警流聚合规则种子：以 rule_id 去重，保留首个非空描述与等级。

    说明：v1 的"人工规则"= 由数据集导入的 Wazuh 规则（rule.id），导入后视为人工
    规则库基线；后续阶段再区分"衍生规则池/自动演化"。
    """
    seeds: dict[str, RuleSeed] = {}
    for a in alerts:
        rid = a.rule_id
        if not rid:
            continue
        r = a.rule
        seed = seeds.get(rid)
        if seed is None:
            seeds[rid] = RuleSeed(
                rule_id=rid,
                level=r.level,
                description=(r.description if r.description and r.description != "MISSING" else None),
                groups=_merge_groups(None, r.groups if isinstance(r.groups, list) else None),
                mitre=a.mitre or None,
                sources=[a.dataset],
            )
        else:
            if seed.description is None and r.description and r.description != "MISSING":
                seed.description = r.description
            if seed.level is None and r.level is not None:
                seed.level = r.level
            merged = _merge_groups(seed.groups, r.groups if isinstance(r.groups, list) else None)
            if merged is not None:
                seed.groups = merged
            if a.dataset not in seed.sources:
                seed.sources.append(a.dataset)
    return seeds


class RuleEngine:
    """双规则池 v1：仅人工规则池（种子）。命中即计数；衍生池留待后续阶段。"""

    def __init__(self, seeds: dict[str, RuleSeed]):
        self.seeds = seeds

    def match(self, alert: Alert) -> list[RuleHit]:
        rid = alert.rule_id
        seed = self.seeds.get(rid) if rid else None
        if seed is None or not seed.is_active:
            return []
        seed.fired_times += 1
        return [RuleHit(
            rule_id=seed.rule_id,
            level=seed.level,
            description=seed.description,
            groups=seed.groups,
            mitre=seed.mitre,
            fired_times_after=seed.fired_times,
        )]

    def stats(self) -> list[dict]:
        rows = []
        for s in self.seeds.values():
            rows.append({
                "rule_id": s.rule_id, "level": s.level,
                "description": s.description, "groups": s.groups,
                "sources": s.sources, "fired_times": s.fired_times,
                "is_active": s.is_active,
            })
        rows.sort(key=lambda x: (-x["fired_times"], x["rule_id"]))
        return rows

    def __len__(self) -> int:
        return len(self.seeds)

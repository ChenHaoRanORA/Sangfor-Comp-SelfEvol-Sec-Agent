# -*- coding: utf-8 -*-
"""v3 处置分流 · 规则池工具：记忆库"人工规则(auto=0)" 的 DSL 命中判定。

处置分流（开发计划"自进化人机协同闭环 · 规格 v1 · A"）的命中源裁决：
- 人工规则库（权威）：本模块从 MemoryStore 读取 auto=0 且 active/enabled 的规则
  （升格自可疑模式 / 人工治理），判定告警 rule_id 是否被其 DSL 表达式覆盖。
- 命中人工规则 → 潜意识直发（need_llm=False，不唤醒 LLM）；
  未命中人工但命中可疑模式/相似记忆（EvidenceBuilder 判定）→ 显意识 LLM 推理处置。

结构化 DSL 谓词沿用架构约定，如 [{"field": "rule.id", "op": "in", "value": [...]}]。
"""
from __future__ import annotations

from typing import Iterable, Optional

from src.core.memory.store import MemoryStore


def rule_covers(rule: dict, rule_id: Optional[str]) -> bool:
    """衍生/人工规则 expression（rule.id in [...]）是否覆盖该告警 rule_id。"""
    if not rule_id:
        return False
    for p in rule.get("expression") or []:
        if p.get("field") != "rule.id":
            continue
        if p.get("op") == "in" and rule_id in {str(x) for x in (p.get("value") or [])}:
            return True
        if p.get("op") in ("eq", "==") and str(p.get("value")) == rule_id:
            return True
    return False


def load_manual_rules(store: MemoryStore, dataset: Optional[str] = None) -> list[dict]:
    """记忆库人工规则池：auto=0（人工拍板升格/人工创建）+ active + enabled。

    仅取携带结构化 expression 的规则（无 expression 的人工规则无法在规则层命中，
    需走语义/相似记忆通道——由 LLM 显意识覆盖）。
    """
    out = []
    for r in store.rules(state="active"):
        if r.get("auto"):
            continue                  # 只收人工权威规则（含升格）
        if not r.get("enabled"):
            continue
        if not r.get("expression"):
            continue
        if dataset:
            # 经来源模式归属数据集（无来源模式的人工规则视为跨数据集，全匹配）
            pid = r.get("source_pattern_id")
            if pid:
                p = store.pattern_by_id(pid)
                if p is not None and p.get("dataset") != dataset:
                    continue
        out.append(r)
    return out


def match_manual(alert, manual_rules: Iterable[dict]) -> list[dict]:
    """返回覆盖该告警 rule_id 的记忆库人工规则列表。"""
    rid = alert.rule_id if alert else None
    if not rid:
        return []
    return [r for r in manual_rules if rule_covers(r, rid)]

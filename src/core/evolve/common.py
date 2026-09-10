# -*- coding: utf-8 -*-
"""evolve 公共小工具与 LLM 提示词。"""
from __future__ import annotations

from typing import Optional

from src.core.memory.models import now_ms  # noqa: F401  复用时间戳

_SEV_BY_LEVEL = ((12, "Critical"), (7, "High"), (4, "Medium"), (1, "Low"))


def level_sev(level: Optional[int]) -> str:
    lv = int(level or 0)
    for thr, sev in _SEV_BY_LEVEL:
        if lv >= thr:
            return sev
    return "Low"


SYSTEM_INDUCE = (
    "你是资深安全分析师。以下是在同一台主机上、很短时间内（<=3 分钟）连续触发的多条安全告警片段，"
    "它们可能同属一个攻击行为/攻击链。请判断这些规则共现是否有真实的安全语义，若是，归纳为一个\"可疑行为模式\"。\n"
    "只输出一个 JSON 对象，字段：{\"meaningful\": true|false, \"title\": \"<≤25字模式名>\", "
    "\"description\": \"<2-4句说明：攻击者行为链条、为何可疑、建议关注点>\", "
    "\"mitre_techniques\": [\"<ATT&CK技术ID或名称，最多3个>\"], "
    "\"mitre_tactics\": [\"<ATT&CK战术ID如TA0001，最多2个>\"], "
    "\"severity\": \"low\"|\"medium\"|\"high\"|\"critical\", "
    "\"confidence\": 0.0-1.0}。若只是无关告警挤在一起，则 meaningful=false。不要输出其他文字。"
)

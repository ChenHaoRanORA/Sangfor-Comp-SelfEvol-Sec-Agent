# -*- coding: utf-8 -*-
"""多层记忆数据模型（阶段四 v1）。

对齐《系统架构.md》§4.2/4.3：历史片段 Fragment（可向量检索）→
可疑模式 Pattern（门控后入库）→ 衍生规则 DerivedRule（模式自动编译，
系统自动 CRUD、人工可改/停用、全部带审计）。规则表达式沿用结构化 DSL。
"""
from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

MEM_CONFIG = ConfigDict(extra="ignore", arbitrary_types_allowed=True)


class Fragment(BaseModel):
    """一条历史片段：一次告警处置沉淀（低风险可随时写）。"""
    model_config = MEM_CONFIG
    fragment_id: str
    dataset: str                       # linux | llm-soc
    alert_id: Optional[str] = None
    seq: int = 0
    host: str = "-"
    ts_ms: Optional[int] = None
    rule_id: Optional[str] = None
    rule_level: Optional[int] = None
    groups: list = []
    mitre: Optional[dict] = None
    classification: Optional[str] = None   # TP/FP/None（规则回退）
    verdict_priority: str = "low"
    method: str = "none"                   # llm | rule_fallback
    llm_error: bool = False
    summary: str = ""                      # 供向量检索/展示的浓缩文本
    source: Optional[dict] = None          # 原始 AlertEvent（含 rule_hits/verdict）
    created_at: Optional[int] = None

    @property
    def embed_text(self) -> str:
        """向量检索用文本：规则描述 + 组 + 判定理由 + 原始文本片段。"""
        return self.summary


class Pattern(BaseModel):
    """可疑模式：LLM 结合图谱从相似片段归纳，门控后 draft→active。"""
    model_config = MEM_CONFIG
    pattern_id: str
    dataset: str
    title: str
    description: str
    kind: str = "behavior"                 # behavior(共现规则族) | burst | fp_noise
    state: str = "draft"                   # draft | active | superseded
    confidence: float = 0.0
    hits: int = 0                          # 支撑片段数
    supporting_fragment_ids: list = []
    rule_ids: list = []                    # 覆盖的命中规则 id（表达层面）
    mitre_techniques: list = []
    mitre_tactics: list = []
    derived_rule_id: Optional[str] = None
    meta: dict = Field(default_factory=dict)   # llm_session/created_by 等
    created_at: Optional[int] = None
    updated_at: Optional[int] = None


class DerivedRule(BaseModel):
    """衍生规则：由可疑模式自动编译；系统自动 CRUD，可人工改/停用。"""
    model_config = MEM_CONFIG
    rule_id: str
    rule_type: str = "derived"
    name: str
    description: str = ""
    enabled: bool = True
    state: str = "active"                  # draft | active | paused | superseded
    expression: list = []                  # DSL 谓词列表 [{field,op,value}]
    severity: str = "medium"
    action_policy: dict = Field(default_factory=lambda: {"max_tier": "A1", "allow": ["snapshot", "query"]})
    source_pattern_id: Optional[str] = None
    fired_times: int = 0
    last_triggered_at: Optional[int] = None
    owner: str = "system"
    created_at: Optional[int] = None
    updated_at: Optional[int] = None
    revision: int = 1
    auto: bool = True
    audit: list = []                       # [{ts,op,by,note}]


def now_ms() -> int:
    import time
    return int(time.time() * 1000)

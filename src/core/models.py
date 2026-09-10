# -*- coding: utf-8 -*-
"""v1 Agent 核心数据结构（Pydantic v2）。

统一告警 Alert 与 data/processed/*.jsonl 同构（extra 容忍），供规则引擎与
LangGraph 处置流消费；RuleSeed = 双规则池中的"人工规则"种子（v1 由数据集规则导入）。
"""
from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, ConfigDict

MODEL_CONFIG = ConfigDict(extra="ignore", arbitrary_types_allowed=True)


class AlertRule(BaseModel):
    model_config = MODEL_CONFIG
    id: Optional[Any] = None          # linux 为 int、llm-soc 为 str，引擎统一按 str 匹配
    level: Optional[int] = None
    description: Optional[str] = None
    groups: Optional[Any] = None
    firedtimes: Optional[int] = None


class Alert(BaseModel):
    """一条归一化告警（两份预处理产物的统一结构）。"""
    model_config = MODEL_CONFIG
    dataset: str
    alert_id: Optional[str] = None
    index: Optional[str] = None
    agent: Optional[dict] = None
    os: Optional[str] = None
    time: Optional[dict] = None          # {ms, iso}
    time_raw: Optional[str] = None
    rule: Optional[AlertRule] = None
    mitre: Optional[dict] = None
    decoder: Optional[dict] = None
    location: Optional[str] = None
    program: Optional[str] = None
    text: str = ""
    priority: str = "low"                # low|medium|high|critical（由 level 映射）
    verdict: Optional[dict] = None       # 数据集自带 ground truth（评测用，研判不读取）
    extra: Optional[dict] = None

    @property
    def rule_id(self) -> Optional[str]:
        if self.rule is None or self.rule.id is None:
            return None
        return str(self.rule.id)

    @property
    def ts_ms(self) -> Optional[int]:
        return (self.time or {}).get("ms")


class RuleSeed(BaseModel):
    """规则库种子（人工规则池）：v1 由数据集 Wazuh rule 自动导入，命中计数 self.fired_times。"""
    model_config = MODEL_CONFIG
    rule_id: str
    level: Optional[int] = None
    description: Optional[str] = None
    groups: Optional[list] = None
    mitre: Optional[dict] = None
    sources: list = []                   # 出现过的数据集
    is_active: bool = True
    fired_times: int = 0                 # 本次运行累计生效次数

    @property
    def key(self) -> str:
        return self.rule_id


class RuleHit(BaseModel):
    """一次命中记录（含自增后的生效次数，便于归因）。"""
    model_config = MODEL_CONFIG
    rule_id: str
    level: Optional[int]
    description: Optional[str]
    groups: Optional[list]
    mitre: Optional[dict]
    fired_times_after: int


class Verdict(BaseModel):
    """研判结论（LLM 或规则回退）。classification 沿用 TP/FP/UNKNOWN。"""
    model_config = MODEL_CONFIG
    classification: Optional[str] = None  # TP / FP / UNKNOWN
    priority: str = "low"
    confidence: Optional[float] = None
    method: str = "none"                  # llm | rule_fallback
    llm_error: bool = False               # 需要 LLM 但调用失败（网络/key/解析）
    justification: str = ""
    evidence: list = []


class AlertEvent(BaseModel):
    """单条告警的完整处置事件（写 JSONL，供复现/回放/统计）。"""
    model_config = MODEL_CONFIG
    seq: int
    ts_ms: Optional[int]
    ts_iso: Optional[str]
    dataset: str
    alert_id: Optional[str]
    index: Optional[str]
    agent_name: Optional[str]
    rule_hits: list[RuleHit]
    need_llm: bool
    llm_used: bool
    verdict: Verdict
    action: str = "notify"                # v1 仅告警通知，禁止其他自主动作
    notified: bool = True
    channel: str = ""                     # v3 处置分流通路: manual(人工直发)|memory(模式→LLM)|policy(策略直发/LLM)

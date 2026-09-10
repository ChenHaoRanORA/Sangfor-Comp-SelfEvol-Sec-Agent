# -*- coding: utf-8 -*-
"""LLM 研判客户端（openai 库，OpenAI 兼容端点 DeepSeek）。

- 无 key / 网络不可达 / 输出非法 → 抛 LLMError，由处置流回退规则结论；
- 所有调用记录 {model,耗时,输入指纹} 便于成本与消融。
"""
from __future__ import annotations

import json
import re
import time
from typing import Optional

from openai import OpenAI

from src.config.settings import Settings

SYSTEM_TRIAGE = (
    "你是服务器安全运营中心(SOC)的分析师。给你一条安全告警及其命中的规则信息，请研判它是否为真实威胁(True Positive, TP)，"
    "还是误报(False Positive, FP)或信息性告警(UNKNOWN)，并给出严重度优先级(仅 low/medium/high/critical 四档)与简短理由。"
    "只输出一个 JSON 对象，字段：{\"classification\": \"TP\"|\"FP\"|\"UNKNOWN\", "
    "\"priority\": \"low\"|\"medium\"|\"high\"|\"critical\", \"justification\": \"<2-3 句中文理由>\"}。"
)


class LLMError(RuntimeError):
    pass


def extract_json_object(text: str) -> dict:
    """容忍模型额外文本，截取首尾花括号之间的 JSON。

    模型常在理由里直接写 Windows 路径（如 C:\\Windows），产生非法转义；
    先在严格解析失败后做"反斜杠消毒 + 允许原始控制字符"的兜底再解析。
    """
    s = text.strip()
    i, j = s.find("{"), s.rfind("}")
    if j <= i:
        raise LLMError(f"响应中无 JSON 对象: {text[:200]!r}")
    chunk = s[i:j + 1]
    try:
        return _loads(chunk)
    except ValueError:
        pass
    # 消毒：把紧跟非转义保留字符的反斜杠补成双反斜杠，避免 Invalid \escape
    chunk2 = re.sub(r'(?<!\\)\\(?![\\"/bfnrtu])', r"\\\\", chunk)
    try:
        obj = _loads(chunk2, strict=False)
    except ValueError as exc:
        raise LLMError(f"JSON 解析失败: {exc}") from exc
    if not isinstance(obj, dict):
        raise LLMError("响应 JSON 非对象")
    return obj


def _loads(chunk: str, strict: bool = True) -> dict:
    obj = json.loads(chunk, strict=strict)
    if not isinstance(obj, dict):
        raise ValueError("not an object")
    return obj


class LLMClient:
    def __init__(self, settings: Optional[Settings] = None):
        self.s = settings or Settings.from_env()
        self._client: Optional[OpenAI] = None
        if self.s.llm_api_key:
            self._client = OpenAI(
                api_key=self.s.llm_api_key,
                base_url=self.s.llm_base_url,
                timeout=self.s.llm_timeout,
                max_retries=self.s.llm_max_retries,
            )

    @property
    def available(self) -> bool:
        return self._client is not None

    def _chat_json(self, system: str, user: str) -> dict:
        """通用：单轮 chat + 提取 JSON 对象；失败抛 LLMError。"""
        if self._client is None:
            raise LLMError("未配置 DEEPSEEK_API")
        t0 = time.time()
        try:
            resp = self._client.chat.completions.create(
                model=self.s.llm_model,
                messages=[{"role": "system", "content": system},
                          {"role": "user", "content": user}],
                temperature=0.0,
            )
        except Exception as exc:  # noqa: BLE001  网络/鉴权/限流等
            raise LLMError(f"LLM 调用失败: {type(exc).__name__}: {exc}") from exc
        content = resp.choices[0].message.content or ""
        obj = extract_json_object(content)
        obj["_llm_meta"] = {"model": self.s.llm_model,
                            "cost_s": round(time.time() - t0, 3)}
        return obj

    def complete(self, system: str, user: str) -> dict:
        """通用 JSON 任务（模式归纳/规则编译/NL 助手等）。"""
        return self._chat_json(system, user)

    def triage(self, dataset: str, text: str, rule_desc: Optional[str],
               rule_level: Optional[int], mitre: Optional[dict], fingerprint: str,
               evidence: Optional[str] = None) -> dict:
        """调用 LLM 研判；失败抛 LLMError。
        evidence：可选历史证据（多层记忆召回 + 知识图谱多跳）文本块，辅助研判但不强制采纳。"""
        user = (
            f"[数据集] {dataset}\n"
            f"[命中规则] {rule_desc or '-'} (level={rule_level})\n"
            f"[MITRE] {json.dumps(mitre, ensure_ascii=False) if mitre else '-'}\n"
        )
        if evidence:
            user += f"{evidence}\n\n"
        user += f"[告警内容]\n{text[:4000]}"
        return self._chat_json(SYSTEM_TRIAGE, user)

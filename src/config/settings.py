# -*- coding: utf-8 -*-
"""v1 Agent 配置：读取环境变量 DEEPSEEK_API，指向 https://api.deepseek.com。"""
from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache


@dataclass(frozen=True)
class Settings:
    # LLM（openai 兼容，DeepSeek）
    llm_api_key: str = ""
    llm_base_url: str = "https://api.deepseek.com"
    llm_model: str = "deepseek-chat"
    llm_timeout: float = 45.0
    llm_max_retries: int = 1

    # 数据产物路径（与 docs/data 预处理产物一致）
    processed_dir: str = "data/processed"
    linux_alerts: str = "data/processed/linux_apt_alerts.jsonl"
    llm_soc_alerts: str = "data/processed/llm_soc_alerts.jsonl"

    @property
    def llm_enabled(self) -> bool:
        return bool(self.llm_api_key)

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            llm_api_key=os.getenv("DEEPSEEK_API", "").strip(),
            llm_base_url=os.getenv("DEEPSEEK_API_BASE", "https://api.deepseek.com").strip(),
            llm_model=os.getenv("DEEPSEEK_MODEL", "deepseek-chat").strip(),
            llm_timeout=float(os.getenv("LLM_TIMEOUT", "45")),
            llm_max_retries=int(os.getenv("LLM_MAX_RETRIES", "1")),
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings.from_env()

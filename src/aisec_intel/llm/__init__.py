"""LLM 接入包（PROJECT_PLAN.md §3.1）：全项目唯一允许调用模型的出口。

对外只导出抽象与工厂；Agent 层不得直接依赖 ``langchain_openai`` 等具体 SDK。
"""

from __future__ import annotations

from aisec_intel.llm.provider import (
    DEFAULT_MAX_TOKENS,
    LLMConfigError,
    LLMError,
    LLMProvider,
    LLMUnsupportedProviderError,
    ModelRole,
    OpenAICompatibleProvider,
    build_provider,
)

__all__ = [
    "DEFAULT_MAX_TOKENS",
    "LLMConfigError",
    "LLMError",
    "LLMProvider",
    "LLMUnsupportedProviderError",
    "ModelRole",
    "OpenAICompatibleProvider",
    "build_provider",
]

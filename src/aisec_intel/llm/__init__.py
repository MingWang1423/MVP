"""LLM 接入包（PROJECT_PLAN.md §3.1）：全项目唯一允许调用模型的出口。

对外只导出抽象与工厂；Agent 层不得直接依赖 ``langchain_openai`` 等具体 SDK。
"""

from __future__ import annotations

from aisec_intel.llm.cache import (
    CachedStructuredRunner,
    TokenUsage,
    TokenUsageTracker,
    cache_key,
    extract_usage,
    wrap_with_cache,
)
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
from aisec_intel.llm.schemas import (
    DEFAULT_MAX_RETRIES,
    StructuredOutputError,
    invoke_structured,
)

__all__ = [
    "DEFAULT_MAX_RETRIES",
    "DEFAULT_MAX_TOKENS",
    "CachedStructuredRunner",
    "LLMConfigError",
    "LLMError",
    "LLMProvider",
    "LLMUnsupportedProviderError",
    "ModelRole",
    "OpenAICompatibleProvider",
    "StructuredOutputError",
    "TokenUsage",
    "TokenUsageTracker",
    "build_provider",
    "cache_key",
    "extract_usage",
    "invoke_structured",
    "wrap_with_cache",
]

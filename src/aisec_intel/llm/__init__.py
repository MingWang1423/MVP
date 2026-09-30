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
    AUTO_METHOD_VALUES,
    DEFAULT_MAX_TOKENS,
    DEFAULT_STRUCTURED_METHOD,
    FALLBACK_STRUCTURED_METHOD,
    JSON_MODE_HINT,
    NATIVE_STRUCTURED_METHOD,
    STRUCTURED_METHODS,
    JsonModeRunnable,
    LLMConfigError,
    LLMError,
    LLMProvider,
    LLMUnsupportedProviderError,
    ModelRole,
    OpenAICompatibleProvider,
    StructuredMethod,
    build_provider,
    ensure_json_hint,
    is_think_model,
    resolve_structured_method,
)
from aisec_intel.llm.schemas import (
    DEFAULT_MAX_RETRIES,
    StructuredOutputError,
    invoke_structured,
)

__all__ = [
    "AUTO_METHOD_VALUES",
    "DEFAULT_MAX_RETRIES",
    "DEFAULT_MAX_TOKENS",
    "DEFAULT_STRUCTURED_METHOD",
    "FALLBACK_STRUCTURED_METHOD",
    "JSON_MODE_HINT",
    "NATIVE_STRUCTURED_METHOD",
    "STRUCTURED_METHODS",
    "CachedStructuredRunner",
    "JsonModeRunnable",
    "LLMConfigError",
    "LLMError",
    "LLMProvider",
    "LLMUnsupportedProviderError",
    "ModelRole",
    "OpenAICompatibleProvider",
    "StructuredMethod",
    "StructuredOutputError",
    "TokenUsage",
    "TokenUsageTracker",
    "build_provider",
    "cache_key",
    "ensure_json_hint",
    "extract_usage",
    "invoke_structured",
    "is_think_model",
    "resolve_structured_method",
    "wrap_with_cache",
]

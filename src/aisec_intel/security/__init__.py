"""安全加固包（Day18 任务 1/2）：提示词注入防护与 LLM 输出校验。

对外只暴露 :mod:`aisec_intel.security.prompt_guard` 的守卫函数；
本包**不依赖任何业务模型**（纯文本 + 通用 Pydantic 校验），可被 L3 富化层、L4 问答层与
L5 API 层共用，避免「各层各写一套过滤」导致口径漂移。
"""

from __future__ import annotations

from aisec_intel.security.prompt_guard import (
    MAX_PROMPT_CHARS,
    MAX_QUERY_CHARS,
    GuardVerdict,
    InjectionFinding,
    OutputValidationError,
    PromptInjectionError,
    assert_safe_query,
    detect_injection,
    guard_input,
    normalize_text,
    sanitize_for_llm,
    strip_chat_markup,
    strip_control_chars,
    validate_llm_output,
)

__all__ = [
    "MAX_PROMPT_CHARS",
    "MAX_QUERY_CHARS",
    "GuardVerdict",
    "InjectionFinding",
    "OutputValidationError",
    "PromptInjectionError",
    "assert_safe_query",
    "detect_injection",
    "guard_input",
    "normalize_text",
    "sanitize_for_llm",
    "strip_chat_markup",
    "strip_control_chars",
    "validate_llm_output",
]

"""结构化输出二次校验与降级路径（PROJECT_PLAN.md §3.2 闸门 ①/②、§5.6）。

闸门定义（违反即视为缺陷）：

1. **闸门①**：所有 Agent 的 LLM 调用必须走 ``provider.structured(Schema)``
   （由 :mod:`aisec_intel.llm.provider` 统一提供 ``with_structured_output``）；
2. **闸门②**：返回对象必须再过一次 ``Schema.model_validate(...)``；
   失败 → 按 ``LLM_MAX_RETRIES`` 重试（首次附加错误信息），仍失败 → **抛异常**，
   由调用方标记该字段为 ``None`` + ``confidence=0``，**绝不写入猜测值**（§6.2 P5 ③）。

本模块提供 :func:`invoke_structured`：对任意「可 ``ainvoke`` 的结构化 Runnable」做
统一的调用 + 校验 + 重试，是 Agent 侧唯一的调用入口。
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, TypeVar

from pydantic import BaseModel, ValidationError

from aisec_intel.logging_config import get_logger

logger = get_logger(__name__)

TModel = TypeVar("TModel", bound=BaseModel)

DEFAULT_MAX_RETRIES: int = 2
"""默认重试次数（与 ``LLM_MAX_RETRIES`` 语义一致）。"""


class StructuredOutputError(RuntimeError):
    """结构化输出在重试后仍无法通过校验（调用方须降级为「无结论」，不得写脏数据）。"""


async def invoke_structured(
    runnable: Any,
    schema: type[TModel],
    messages: Sequence[Any],
    *,
    max_retries: int = DEFAULT_MAX_RETRIES,
) -> TModel:
    """调用结构化 Runnable 并执行闸门②校验（带重试）。

    Args:
        runnable: 支持 ``ainvoke`` 的对象（``provider.structured(schema)`` 或
            :class:`aisec_intel.llm.cache.CachedStructuredRunner`）。
        schema: 目标 Pydantic 模型类。
        messages: 消息序列（``SystemMessage`` / ``HumanMessage`` 或字符串）。
        max_retries: 校验失败后的额外重试次数（默认 2）。

    Returns:
        校验通过的 ``schema`` 实例。

    Raises:
        StructuredOutputError: 重试耗尽仍未通过校验（**不得**返回半成品）。
    """
    attempts = max(1, max_retries + 1)
    conversation = list(messages)
    last_error: Exception | None = None

    for attempt in range(1, attempts + 1):
        try:
            raw = await runnable.ainvoke(conversation)
            candidate = _unwrap_raw(raw)
            if isinstance(candidate, schema):
                # 已由 with_structured_output 构造，仍显式二次校验（闸门②）
                return schema.model_validate(candidate.model_dump())
            return schema.model_validate(candidate)
        except ValidationError as exc:
            last_error = exc
            logger.warning(f"结构化输出校验失败（第 {attempt}/{attempts} 次）：{exc.error_count()} 处错误")
            conversation = [*conversation, _repair_message(schema, exc)]
        except Exception as exc:  # noqa: BLE001 - 网络/超时同样按重试处理，最终显式失败
            last_error = exc
            logger.warning(f"LLM 调用失败（第 {attempt}/{attempts} 次）：{type(exc).__name__}: {exc}")

    raise StructuredOutputError(
        f"{schema.__name__} 结构化输出在 {attempts} 次尝试后仍失败：{type(last_error).__name__}: {last_error}"
    ) from last_error


def _unwrap_raw(response: Any) -> Any:
    """拆解 ``include_raw=True`` 的返回结构（``{"raw": ..., "parsed": ...}``）。

    Args:
        response: ``ainvoke`` 的返回值。

    Returns:
        结构化对象本体（``parsed``）或原样返回。

    Raises:
        ValueError: ``parsed`` 为空（模型输出无法解析为 JSON 结构）。
    """
    if isinstance(response, dict) and "parsed" in response:
        parsed = response.get("parsed")
        if parsed is None:
            raise ValueError(f"结构化输出解析失败：{response.get('parsing_error')!r}")
        return parsed
    return response


def _repair_message(schema: type[BaseModel], error: ValidationError) -> str:
    """构造「修复提示」消息（把校验错误回灌给模型，提高重试成功率）。

    Args:
        schema: 目标模型类。
        error: 校验异常。

    Returns:
        追加到对话末尾的提示文本。
    """
    details = "; ".join(
        f"{'.'.join(str(part) for part in item['loc'])}: {item['msg']}" for item in error.errors()[:5]
    )
    fields = ", ".join(schema.model_fields)
    return (
        f"上一次输出不符合 schema {schema.__name__} 的约束（{details}）。"
        f"请仅输出符合该 schema 的 JSON，必填/可选字段：{fields}。"
    )

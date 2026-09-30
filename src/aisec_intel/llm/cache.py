"""LLM 响应缓存与 token 计量（PROJECT_PLAN.md §3.4 / §5.6）。

两个组件：

1. :func:`cache_key`：纯函数生成幂等键 ``sha256(prompt + model + temperature + schema)``；
2. :class:`TokenUsageTracker`：累计各模型的 prompt / completion token，用于**成本评估**
   （交付物「LLM 调用 token 消耗统计」）。

设计取舍：缓存**不侵入** ``llm/provider.py``（P0 的唯一模型出口），
而是以「装饰器式包装」复用同一协议：:class:`CachedStructuredRunner` 持有
``provider.structured(schema)`` 的返回对象与一个会话工厂，命中即返回、未命中则调用并落库。
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, TypeVar

from pydantic import BaseModel

from aisec_intel.logging_config import get_logger
from aisec_intel.storage.repositories.llm_cache_repo import LLMCacheRepository

if TYPE_CHECKING:
    from contextlib import AbstractAsyncContextManager

    from sqlalchemy.ext.asyncio import AsyncSession

logger = get_logger(__name__)

TModel = TypeVar("TModel", bound=BaseModel)

CACHE_KEY_SCHEMA: str = "llm_cache/v1"
"""缓存键版本前缀（键算法变更时递增，避免读到旧语义的缓存）。"""


def _message_text(message: Any) -> str:
    """把 LangChain 消息对象或普通字符串转为文本（缓存键输入）。

    Args:
        message: ``BaseMessage`` 或任意对象。

    Returns:
        文本形式（``content`` 优先）。
    """
    content = getattr(message, "content", None)
    if isinstance(content, str):
        return content
    if content is None:
        return str(message)
    return str(content)


def cache_key(
    *,
    model: str,
    temperature: float,
    messages: Sequence[Any],
    schema_name: str,
) -> str:
    """生成缓存幂等键（纯函数）。

    规则（§3.4）：``sha256(prompt + model + temperature)``，并额外纳入 ``schema_name``
    与键版本前缀——同一 prompt 配不同输出结构时不得互相命中。

    Args:
        model: 模型名。
        temperature: 采样温度。
        messages: 消息序列（``BaseMessage`` 或字符串）。
        schema_name: 结构化输出目标模型名。

    Returns:
        64 位十六进制键。
    """
    parts = [CACHE_KEY_SCHEMA, model, f"{temperature:.4f}", schema_name]
    parts.extend(_message_text(message) for message in messages)
    return hashlib.sha256("\n\u0001".join(parts).encode("utf-8")).hexdigest()


@dataclass(slots=True)
class TokenUsage:
    """单个模型的累计 token 消耗。

    Attributes:
        model: 模型名。
        calls: 实际发起（未命中缓存）的调用次数。
        cache_hits: 命中缓存的次数。
        prompt_tokens: 输入 token 合计。
        completion_tokens: 输出 token 合计。
    """

    model: str
    calls: int = 0
    cache_hits: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        """输入 + 输出 token 合计。"""
        return self.prompt_tokens + self.completion_tokens


@dataclass(slots=True)
class TokenUsageTracker:
    """按模型累计 token 消耗（成本评估用）。

    Attributes:
        usages: ``模型名 → 累计消耗``。
    """

    usages: dict[str, TokenUsage] = field(default_factory=dict)

    def record_call(self, model: str, *, prompt_tokens: int = 0, completion_tokens: int = 0) -> None:
        """记录一次真实调用。

        Args:
            model: 模型名。
            prompt_tokens: 输入 token 数。
            completion_tokens: 输出 token 数。
        """
        usage = self.usages.setdefault(model, TokenUsage(model=model))
        usage.calls += 1
        usage.prompt_tokens += max(0, int(prompt_tokens))
        usage.completion_tokens += max(0, int(completion_tokens))

    def record_cache_hit(self, model: str) -> None:
        """记录一次缓存命中（未产生 token 消耗）。

        Args:
            model: 模型名。
        """
        usage = self.usages.setdefault(model, TokenUsage(model=model))
        usage.cache_hits += 1

    @property
    def total_prompt_tokens(self) -> int:
        """全部模型输入 token 合计。"""
        return sum(usage.prompt_tokens for usage in self.usages.values())

    @property
    def total_completion_tokens(self) -> int:
        """全部模型输出 token 合计。"""
        return sum(usage.completion_tokens for usage in self.usages.values())

    @property
    def total_tokens(self) -> int:
        """全部模型 token 合计。"""
        return self.total_prompt_tokens + self.total_completion_tokens

    @property
    def cache_hits(self) -> int:
        """缓存命中总数。"""
        return sum(usage.cache_hits for usage in self.usages.values())

    def summary(self) -> list[dict[str, Any]]:
        """返回可直接打印 / 落报告的汇总行。

        Returns:
            每模型一行（``model`` / ``calls`` / ``cache_hits`` / ``prompt_tokens`` /
            ``completion_tokens`` / ``total_tokens``）。
        """
        return [
            {
                "model": usage.model,
                "calls": usage.calls,
                "cache_hits": usage.cache_hits,
                "prompt_tokens": usage.prompt_tokens,
                "completion_tokens": usage.completion_tokens,
                "total_tokens": usage.total_tokens,
            }
            for usage in sorted(self.usages.values(), key=lambda item: item.model)
        ]


def extract_usage(response: Any) -> tuple[int, int]:
    """从 LangChain 响应中提取 token 用量（缺失时返回 ``(0, 0)``）。

    兼容三种来源：``usage_metadata``（langchain-core ≥0.2）、``response_metadata["token_usage"]``、
    ``response_metadata["usage"]``（不同 OpenAI 兼容端点字段差异）。

    Args:
        response: ``ainvoke`` 的返回对象。

    Returns:
        ``(prompt_tokens, completion_tokens)``。
    """
    metadata = getattr(response, "usage_metadata", None)
    if isinstance(metadata, dict):
        prompt = metadata.get("input_tokens") or metadata.get("prompt_tokens") or 0
        completion = metadata.get("output_tokens") or metadata.get("completion_tokens") or 0
        if prompt or completion:
            return int(prompt), int(completion)

    raw = getattr(response, "response_metadata", None)
    if isinstance(raw, dict):
        for key in ("token_usage", "usage"):
            usage = raw.get(key)
            if isinstance(usage, dict):
                prompt = usage.get("prompt_tokens") or usage.get("input_tokens") or 0
                completion = usage.get("completion_tokens") or usage.get("output_tokens") or 0
                return int(prompt), int(completion)
    return 0, 0


class CachedStructuredRunner:
    """结构化输出 + 缓存的 Runnable 包装器（对上层透明）。

    Attributes:
        schema_name: 结构化输出目标模型名（参与缓存键）。
        model: 模型名（参与缓存键与计量）。
    """

    def __init__(
        self,
        *,
        runnable: Any,
        schema: type[TModel],
        model: str,
        provider: str,
        temperature: float = 0.0,
        session_factory: Callable[[], AbstractAsyncContextManager[AsyncSession]] | None = None,
        tracker: TokenUsageTracker | None = None,
        enabled: bool = True,
    ) -> None:
        """初始化包装器。

        Args:
            runnable: ``provider.structured(schema)`` 的返回对象（需支持 ``ainvoke``）。
            schema: 目标 Pydantic 模型。
            model: 模型名。
            provider: 提供方名称。
            temperature: 采样温度。
            session_factory: 会话工厂（``session_scope`` 风格）；``None`` 时禁用缓存读写。
            tracker: token 计量器；``None`` 时不计量。
            enabled: ``False`` 时直通（不读不写缓存，用于强制刷新）。
        """
        self._runnable = runnable
        self._schema = schema
        self._model = model
        self._provider = provider
        self._temperature = temperature
        self._session_factory = session_factory
        self._tracker = tracker
        self._enabled = enabled
        self.schema_name = schema.__name__
        self.model = model

    @property
    def cache_enabled(self) -> bool:
        """是否启用缓存（需同时具备 ``session_factory``）。"""
        return self._enabled and self._session_factory is not None

    async def ainvoke(self, messages: Sequence[Any]) -> TModel:
        """调用模型（优先缓存）。

        Args:
            messages: 消息序列。

        Returns:
            经 ``schema`` 校验的对象。

        Raises:
            Exception: 底层模型的异常原样上抛（由 :mod:`aisec_intel.llm.schemas` 统一兜底）。
        """
        key = cache_key(
            model=self._model,
            temperature=self._temperature,
            messages=messages,
            schema_name=self.schema_name,
        )
        if self.cache_enabled:
            cached = await self._read_cache(key)
            if cached is not None:
                if self._tracker is not None:
                    self._tracker.record_cache_hit(self._model)
                logger.info(f"LLM 缓存命中 model={self._model} schema={self.schema_name} key={key[:12]}…")
                return self._schema.model_validate_json(cached.response_json)

        response = await self._runnable.ainvoke(list(messages))
        parsed, usage = self._normalize_response(response)
        if self._tracker is not None:
            self._tracker.record_call(self._model, prompt_tokens=usage[0], completion_tokens=usage[1])
        if self.cache_enabled:
            await self._write_cache(key, parsed)
        return parsed

    def _normalize_response(self, response: Any) -> tuple[TModel, tuple[int, int]]:
        """把 Runnable 的返回统一为 ``(结构化对象, (输入 token, 输出 token))``。

        支持三种形态：

        1. ``{"raw": AIMessage, "parsed": Schema | None, ...}``（``include_raw=True``，
           可拿到**真实** ``usage_metadata``）；
        2. ``Schema`` 实例（``include_raw=False`` 或第三方实现）；
        3. 普通 ``dict``（模型直接返回 JSON 对象）。

        Args:
            response: ``ainvoke`` 的返回值。

        Returns:
            ``(结构化对象, 用量元组)``。

        Raises:
            ValueError: ``include_raw`` 形态下解析失败（``parsed`` 为 ``None``）。
        """
        if isinstance(response, dict) and "parsed" in response:
            parsed = response.get("parsed")
            usage = extract_usage(response.get("raw"))
            if parsed is None:
                raise ValueError(f"结构化输出解析失败：{response.get('parsing_error')!r}")
            return (parsed if isinstance(parsed, self._schema) else self._schema.model_validate(parsed)), usage
        if isinstance(response, self._schema):
            return response, extract_usage(response)
        return self._schema.model_validate(response), extract_usage(response)

    async def _read_cache(self, key: str) -> Any:
        """读取缓存（会话级失败不影响主流程；命中计数需提交）。"""
        factory = self._session_factory
        if factory is None:  # pragma: no cover - cache_enabled 已保证
            return None
        try:
            async with factory() as session:
                entry = await LLMCacheRepository(session).get(key)
                await session.commit()
                return entry
        except Exception as exc:  # noqa: BLE001 - 缓存故障必须降级为「未命中」
            logger.warning(f"LLM 缓存读取失败（按未命中处理）：{exc!r}")
            return None

    async def _write_cache(self, key: str, value: TModel) -> None:
        """写入缓存（会话级失败不影响主流程）。"""
        factory = self._session_factory
        if factory is None:  # pragma: no cover
            return
        try:
            async with factory() as session:
                await LLMCacheRepository(session).put(
                    cache_key=key,
                    provider=self._provider,
                    model=self._model,
                    temperature=self._temperature,
                    schema_name=self.schema_name,
                    response_json=value.model_dump_json(),
                )
                await session.commit()
        except Exception as exc:  # noqa: BLE001 - 写缓存失败不得影响富化
            logger.warning(f"LLM 缓存写入失败（忽略）：{exc!r}")


def wrap_with_cache(
    runnable: Any,
    *,
    schema: type[TModel],
    model: str,
    provider: str,
    temperature: float = 0.0,
    session_factory: Callable[[], AbstractAsyncContextManager[AsyncSession]] | None = None,
    tracker: TokenUsageTracker | None = None,
) -> CachedStructuredRunner:
    """把 ``provider.structured(schema)`` 的结果包装为带缓存的 runner（便捷工厂）。

    Args:
        runnable: 结构化输出 Runnable。
        schema: 目标 Pydantic 模型。
        model: 模型名。
        provider: 提供方名称。
        temperature: 采样温度。
        session_factory: 会话工厂（``None`` 时仅计量不缓存）。
        tracker: token 计量器。

    Returns:
        :class:`CachedStructuredRunner`。
    """
    return CachedStructuredRunner(
        runnable=runnable,
        schema=schema,
        model=model,
        provider=provider,
        temperature=temperature,
        session_factory=session_factory,
        tracker=tracker,
    )

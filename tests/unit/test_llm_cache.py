"""Day7 LLM 缓存与 token 计量测试（PROJECT_PLAN.md §3.4 / §5.6 ``llm/cache.py``）。

覆盖：缓存键（纯函数）、缓存命中不调用模型、缓存故障降级、token 计量与用量提取。
SQLite 内存库提供 ``llm_cache`` 表（**不依赖 PostgreSQL**）。
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import pytest
from pydantic import BaseModel

from aisec_intel.llm.cache import (
    CACHE_KEY_SCHEMA,
    CachedStructuredRunner,
    TokenUsageTracker,
    cache_key,
    extract_usage,
    wrap_with_cache,
)
from aisec_intel.storage.database import create_session_factory
from aisec_intel.storage.repositories.llm_cache_repo import LLMCacheRepository


class Payload(BaseModel):
    """测试用结构化输出模型。"""

    verdict: str
    score: float = 0.0


class FakeResponse:
    """带 ``usage_metadata`` 的假 ``AIMessage``（模拟 ``include_raw=True`` 的 raw 字段）。"""

    def __init__(self, *, prompt: int = 0, completion: int = 0) -> None:
        """初始化假响应。

        Args:
            prompt: 输入 token 数。
            completion: 输出 token 数。
        """
        self.usage_metadata = {"input_tokens": prompt, "output_tokens": completion}


def raw_payload(payload: Payload, *, prompt: int = 0, completion: int = 0) -> dict[str, Any]:
    """构造 ``with_structured_output(schema, include_raw=True)`` 的返回结构。

    Args:
        payload: 结构化结果。
        prompt: 输入 token 数。
        completion: 输出 token 数。

    Returns:
        ``{"raw": AIMessage 桩, "parsed": payload, "parsing_error": None}``。
    """
    return {"raw": FakeResponse(prompt=prompt, completion=completion), "parsed": payload, "parsing_error": None}


class CountingRunnable:
    """记录调用次数的结构化 Runnable 桩。"""

    def __init__(self, responses: list[Any]) -> None:
        """初始化。

        Args:
            responses: 依次返回的响应。
        """
        self._responses = list(responses)
        self.calls = 0

    async def ainvoke(self, messages: Any) -> Any:
        """返回下一个响应。"""
        self.calls += 1
        return self._responses.pop(0) if self._responses else Payload(verdict="empty")


@pytest.fixture()
async def session_factory(memory_engine: Any) -> AsyncIterator[Any]:
    """提供绑定到内存库的会话工厂（``session_scope`` 风格）。"""
    factory = create_session_factory(memory_engine)
    yield factory


def session_scope_factory(factory: Any) -> Any:
    """用会话工厂打开一个会话上下文（测试内读取缓存表）。

    Args:
        factory: ``create_session_factory`` 的产物。

    Returns:
        异步上下文管理器（``async with`` 用法）。
    """
    return factory()


class TestCacheKey:
    """缓存键（纯函数）。"""

    def test_merged_batch1(self) -> None:
        """合并用例批次 1：顺序执行 2 个子用例并汇总失败。"""
        failures: list[str] = []
        try:
            self._case_test_deterministic_and_versioned()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_deterministic_and_versioned: {type(exc).__name__}: {exc}")
        try:
            self._case_test_accepts_message_objects()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_accepts_message_objects: {type(exc).__name__}: {exc}")
        assert not failures, "合并用例失败：" + " | ".join(failures)
    def _case_test_deterministic_and_versioned(self) -> None:
        """同输入同键；键带版本前缀（算法变更可作废旧缓存）。"""
        first = cache_key(model="deepseek-chat", temperature=0.0, messages=["prompt"], schema_name="Payload")
        second = cache_key(model="deepseek-chat", temperature=0.0, messages=["prompt"], schema_name="Payload")
        assert first == second
        assert len(first) == 64
        assert CACHE_KEY_SCHEMA == "llm_cache/v1"

    @pytest.mark.parametrize(
        "changed",
        [
            {"model": "deepseek-reasoner"},
            {"temperature": 0.7},
            {"messages": ["other prompt"]},
            {"schema_name": "OtherPayload"},
        ],
    )
    def test_sensitive_to_inputs(self, changed: dict[str, Any]) -> None:
        """模型 / 温度 / 提示 / schema 任一变化都会改变键。"""
        base: dict[str, Any] = {
            "model": "deepseek-chat",
            "temperature": 0.0,
            "messages": ["prompt"],
            "schema_name": "Payload",
        }
        assert cache_key(**base) != cache_key(**{**base, **changed})

    def _case_test_accepts_message_objects(self) -> None:
        """``BaseMessage`` 对象按其 ``content`` 参与计算。"""
        from langchain_core.messages import HumanMessage

        assert cache_key(
            model="m", temperature=0.0, messages=[HumanMessage(content="prompt")], schema_name="Payload"
        ) == cache_key(model="m", temperature=0.0, messages=["prompt"], schema_name="Payload")


class TestTokenUsage:
    """token 计量。"""

    def test_merged_batch1(self) -> None:
        """合并用例批次 1：顺序执行 5 个子用例并汇总失败。"""
        failures: list[str] = []
        try:
            self._case_test_records_calls_and_hits()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_records_calls_and_hits: {type(exc).__name__}: {exc}")
        try:
            self._case_test_negative_values_are_clamped()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_negative_values_are_clamped: {type(exc).__name__}: {exc}")
        try:
            self._case_test_extract_usage_from_metadata()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_extract_usage_from_metadata: {type(exc).__name__}: {exc}")
        try:
            self._case_test_extract_usage_from_response_metadata()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_extract_usage_from_response_metadata: {type(exc).__name__}: {exc}")
        try:
            self._case_test_extract_usage_absent()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_extract_usage_absent: {type(exc).__name__}: {exc}")
        assert not failures, "合并用例失败：" + " | ".join(failures)
    def _case_test_records_calls_and_hits(self) -> None:
        """分别累计真实调用与缓存命中。"""
        tracker = TokenUsageTracker()
        tracker.record_call("deepseek-chat", prompt_tokens=100, completion_tokens=20)
        tracker.record_call("deepseek-chat", prompt_tokens=50, completion_tokens=10)
        tracker.record_cache_hit("deepseek-chat")

        assert tracker.total_prompt_tokens == 150
        assert tracker.total_completion_tokens == 30
        assert tracker.total_tokens == 180
        assert tracker.cache_hits == 1
        assert tracker.summary()[0]["calls"] == 2

    def _case_test_negative_values_are_clamped(self) -> None:
        """负数 token 被夹到 0（防御性）。"""
        tracker = TokenUsageTracker()
        tracker.record_call("m", prompt_tokens=-5, completion_tokens=10)
        assert tracker.total_prompt_tokens == 0 and tracker.total_completion_tokens == 10

    def _case_test_extract_usage_from_metadata(self) -> None:
        """优先读 ``usage_metadata``。"""
        assert extract_usage(FakeResponse(prompt=11, completion=7)) == (11, 7)

    def _case_test_extract_usage_from_response_metadata(self) -> None:
        """回退读 ``response_metadata.token_usage``（OpenAI 兼容端点差异）。"""
        response = type("R", (), {"response_metadata": {"token_usage": {"prompt_tokens": 3, "completion_tokens": 4}}})()
        assert extract_usage(response) == (3, 4)

    def _case_test_extract_usage_absent(self) -> None:
        """无用量信息时返回 ``(0, 0)``。"""
        assert extract_usage(object()) == (0, 0)


class TestCachedStructuredRunner:
    """缓存包装器行为。"""

    async def test_first_call_uses_model_and_stores(self, session_factory: Any) -> None:
        """首次未命中：调用模型、写入缓存、计量 token。"""
        runnable = CountingRunnable(
            [raw_payload(Payload(verdict="relevant", score=0.9), prompt=120, completion=15)]
        )
        tracker = TokenUsageTracker()
        runner = wrap_with_cache(
            runnable,
            schema=Payload,
            model="deepseek-chat",
            provider="deepseek",
            session_factory=session_factory,
            tracker=tracker,
        )

        result = await runner.ainvoke(["prompt"])

        assert result.verdict == "relevant"
        assert runnable.calls == 1
        assert tracker.total_tokens == 135
        assert tracker.cache_hits == 0
        async with session_scope_factory(session_factory) as session:
            assert await LLMCacheRepository(session).count() == 1

    async def test_second_call_hits_cache(self, session_factory: Any) -> None:
        """二次同输入命中缓存：**不再调用模型**，只计命中。"""
        runnable = CountingRunnable([raw_payload(Payload(verdict="relevant", score=0.9), prompt=10, completion=5)])
        tracker = TokenUsageTracker()
        runner = wrap_with_cache(
            runnable,
            schema=Payload,
            model="deepseek-chat",
            provider="deepseek",
            session_factory=session_factory,
            tracker=tracker,
        )

        first = await runner.ainvoke(["prompt"])
        second = await runner.ainvoke(["prompt"])

        assert first == second == Payload(verdict="relevant", score=0.9)
        assert runnable.calls == 1  # 第二次走缓存
        assert tracker.cache_hits == 1
        assert tracker.total_tokens == 15  # 未重复计费

    async def test_different_prompt_misses(self, session_factory: Any) -> None:
        """提示不同则视为新请求（不误命中）。"""
        runnable = CountingRunnable(
            [raw_payload(Payload(verdict="a")), raw_payload(Payload(verdict="b"))]
        )
        runner = wrap_with_cache(
            runnable, schema=Payload, model="m", provider="p", session_factory=session_factory
        )
        assert (await runner.ainvoke(["p1"])).verdict == "a"
        assert (await runner.ainvoke(["p2"])).verdict == "b"
        assert runnable.calls == 2

    async def test_unparsed_response_raises(self, session_factory: Any) -> None:
        """``include_raw`` 形态下解析失败（``parsed=None``）显式报错（不写脏数据）。"""
        runnable = CountingRunnable([{"raw": FakeResponse(), "parsed": None, "parsing_error": "bad json"}])
        runner = wrap_with_cache(
            runnable, schema=Payload, model="m", provider="p", session_factory=session_factory
        )
        with pytest.raises(ValueError, match="解析失败"):
            await runner.ainvoke(["prompt"])

    async def test_cache_failure_degrades_to_miss(self) -> None:
        """缓存会话不可用 → 按未命中处理（不阻断富化）。"""
        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def broken_factory() -> Any:
            raise RuntimeError("db down")
            yield  # pragma: no cover

        runnable = CountingRunnable([raw_payload(Payload(verdict="ok"))])
        runner = wrap_with_cache(
            runnable, schema=Payload, model="m", provider="p", session_factory=broken_factory
        )
        assert (await runner.ainvoke(["prompt"])).verdict == "ok"
        assert runnable.calls == 1

    async def test_plain_schema_instance_is_supported(self) -> None:
        """``include_raw=False``（直接返回模型实例）也能工作。"""
        runnable = CountingRunnable([Payload(verdict="direct")])
        runner = CachedStructuredRunner(runnable=runnable, schema=Payload, model="m", provider="p")
        assert (await runner.ainvoke(["prompt"])).verdict == "direct"

    async def test_without_session_factory_skips_cache(self) -> None:
        """未提供会话工厂时直通（不缓存、不报错）。"""
        runnable = CountingRunnable([raw_payload(Payload(verdict="ok")), raw_payload(Payload(verdict="ok"))])
        runner = CachedStructuredRunner(runnable=runnable, schema=Payload, model="m", provider="p")
        assert runner.cache_enabled is False
        await runner.ainvoke(["prompt"])
        await runner.ainvoke(["prompt"])
        assert runnable.calls == 2
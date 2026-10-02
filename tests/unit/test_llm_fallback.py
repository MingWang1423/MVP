"""Day17 任务 4.2：LLM 降级链测试（``llm/fallback.py``）。

覆盖点：
    1. ``fallback_plan``：``smart → chat → ollama``、``fast → ollama``；
    2. :class:`DegradingStructuredRunnable`：首候选失败自动降级；
    3. 全候选失败时抛出最后一次异常（由各 Agent 走确定性兜底）；
    4. 降级事件累加 ``aisec_self_heal_total{component=llm}`` 与 LLM 连续失败计数。
"""

from __future__ import annotations

from typing import Any

import pytest

from aisec_intel.llm.fallback import Candidate, DegradingStructuredRunnable, fallback_plan


class _StubRunnable:
    """最小 Runnable 替身（记录调用次数，可配置失败）。"""

    def __init__(self, label: str, *, fail: bool) -> None:
        self.label = label
        self.fail = fail
        self.calls = 0

    async def ainvoke(self, messages: Any, config: Any | None = None) -> dict[str, str]:
        """返回候选标识（失败时抛异常，用于驱动降级）。"""
        del messages, config
        self.calls += 1
        if self.fail:
            raise RuntimeError(f"{self.label} unavailable")
        return {"model": self.label}


class TestFallbackPlan:
    def test_smart_chain(self) -> None:
        """推理模型降级链：``chat`` → ``ollama``。"""
        plan = fallback_plan("smart", fast_model="deepseek-chat", smart_model="deepseek-reasoner")
        assert plan == (("fast", "deepseek-chat"), ("ollama", "qwen2.5:7b"))

    def test_fast_chain(self) -> None:
        """轻量模型只需一档降级：``ollama``。"""
        assert fallback_plan("fast", fast_model="deepseek-chat", smart_model="deepseek-reasoner") == (
            ("ollama", "qwen2.5:7b"),
        )


class TestDegradingRunnable:
    async def test_falls_back_to_next_candidate(self) -> None:
        """首候选失败 → 次候选成功，返回值来自次候选。"""
        primary = _StubRunnable("deepseek-reasoner", fail=True)
        secondary = _StubRunnable("deepseek-chat", fail=False)
        chain = DegradingStructuredRunnable(
            [Candidate("deepseek-reasoner", primary), Candidate("deepseek-chat", secondary)],
            schema_name="AttackChainDraft",
        )
        result = await chain.ainvoke(["prompt"], config=None)
        assert result == {"model": "deepseek-chat"}
        assert primary.calls == 1 and secondary.calls == 1
        assert chain.model == "deepseek-reasoner"  # 缓存键仍用主候选

    async def test_raises_last_error_when_all_fail(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """全部候选失败 → 抛出最后一次异常（调用方据此走确定性兜底）。"""
        import aisec_intel.llm.fallback as module

        monkeypatch.setattr(module, "log_self_heal", lambda event: None)
        chain = DegradingStructuredRunnable(
            [Candidate("a", _StubRunnable("a", fail=True)), Candidate("b", _StubRunnable("b", fail=True))],
            schema_name="Remediation",
        )
        with pytest.raises(RuntimeError, match="b unavailable"):
            await chain.ainvoke(["prompt"])

    async def test_empty_candidates_rejected(self) -> None:
        """空候选列表直接报错（构造期暴露配置缺陷）。"""
        with pytest.raises(ValueError, match="至少需要一个候选"):
            DegradingStructuredRunnable([], schema_name="X")

    async def test_self_heal_metrics_recorded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """降级链会累加自愈指标（``component=llm, action=fallback``）与 LLM 失败计数。"""
        import aisec_intel.llm.fallback as module
        import aisec_intel.services.self_heal as self_heal_module
        from aisec_intel.services.metrics_service import M_SELF_HEAL, MetricsRegistry

        fresh = MetricsRegistry()
        monkeypatch.setattr(self_heal_module, "METRICS", fresh)
        monkeypatch.setattr(self_heal_module, "configure_self_heal_log", lambda settings=None: None)
        monkeypatch.setattr(
            module, "record_llm_failure", lambda model: fresh.inc("stub_failure", {"model": model})
        )
        chain = DegradingStructuredRunnable(
            [Candidate("a", _StubRunnable("a", fail=True)), Candidate("b", _StubRunnable("b", fail=False))],
            schema_name="CVSSInference",
        )
        await chain.ainvoke(["prompt"])
        assert fresh.counter("stub_failure", {"model": "a"}) == 1
        assert fresh.counter(M_SELF_HEAL, {"component": "llm", "action": "fallback"}) == 1
        assert fresh.counter(M_SELF_HEAL, {"component": "llm", "action": "recovered"}) == 1
        assert chain.candidate_models == ("a", "b")

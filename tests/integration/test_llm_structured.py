"""Day7 LLM structured 接入集成测试（PROJECT_PLAN.md §3.2 / §5.6 任务 5）。

**真实调用 DeepSeek**（需在 ``.env`` 配置有效 ``LLM_API_KEY``），因此标记
``@pytest.mark.integration`` —— 默认 ``python -m pytest`` 会跳过。

运行::

    python -m pytest tests/integration/test_llm_structured.py -m integration -q -s

覆盖：
    1. ``provider.structured(schema)`` 绑定 + ``invoke_structured`` 二次校验（闸门①+②）；
    2. ``structured_with_usage`` 能拿到**真实 token 用量**（成本评估）；
    3. 缓存命中：同 prompt 第二次不产生 token 消耗（写入真实 PG 的 ``llm_cache``）。
"""

from __future__ import annotations

import pytest
from langchain_core.messages import HumanMessage, SystemMessage

from aisec_intel.config import Settings
from aisec_intel.llm.cache import TokenUsageTracker, wrap_with_cache
from aisec_intel.llm.provider import build_provider
from aisec_intel.llm.schemas import invoke_structured
from aisec_intel.models.agent_io import PaperRelevanceBatch
from aisec_intel.services.enrich_service import PLACEHOLDER_API_KEYS, llm_available
from aisec_intel.storage.database import get_engine, session_scope

pytestmark = pytest.mark.integration

PROMPT = (
    "漏洞：CVE-2024-3400（PAN-OS GlobalProtect 命令注入，CWE-77）。"
    "候选论文 1：paper_id=arxiv:2404.00001，标题《Prompt Injection Against Network Appliances》，"
    "摘要：We study prompt injection in network appliances and report a command injection case.\n"
    "候选论文 2：paper_id=arxiv:2404.00002，标题《Quantum Error Correction》，"
    "摘要：A study on quantum error correcting codes.\n"
    "请判断两篇论文是否与该漏洞直接相关。"
)


@pytest.fixture(scope="module")
def settings() -> Settings:
    """真实配置（读取 ``.env``）。"""
    return Settings()


@pytest.fixture(scope="module", autouse=True)
def require_real_key(settings: Settings) -> None:
    """未配置真实 API Key 时跳过（占位值 ``sk-REPLACE_ME``）。"""
    if not llm_available(settings) or settings.llm_api_key.get_secret_value() in PLACEHOLDER_API_KEYS:
        pytest.skip("未配置真实 LLM_API_KEY（.env 仍为占位值），跳过真实调用测试")


async def test_structured_binding_and_validation(settings: Settings) -> None:
    """``structured()`` 绑定成功且输出可被 Pydantic 二次校验（闸门②）。"""
    provider = build_provider(settings)
    runnable = provider.structured(PaperRelevanceBatch, role="fast")
    messages = [SystemMessage(content="你是漏洞情报分析员。"), HumanMessage(content=PROMPT)]

    batch = await invoke_structured(runnable, PaperRelevanceBatch, messages)

    assert isinstance(batch, PaperRelevanceBatch)
    assert batch.items, "模型应至少返回一条判定"
    assert {item.paper_id for item in batch.items}


async def test_usage_metadata_is_captured(settings: Settings) -> None:
    """``structured_with_usage`` 能拿到真实 token 用量（用于成本评估）。"""
    provider = build_provider(settings)
    tracker = TokenUsageTracker()
    runner = wrap_with_cache(
        provider.structured_with_usage(PaperRelevanceBatch, role="fast"),
        schema=PaperRelevanceBatch,
        model=provider.model_for("fast"),
        provider=provider.name,
        tracker=tracker,
    )

    await runner.ainvoke([HumanMessage(content=PROMPT)])

    assert tracker.total_prompt_tokens > 0, "应统计到输入 token"
    assert tracker.total_completion_tokens > 0, "应统计到输出 token"
    print(f"\n[token] {tracker.summary()}")


async def test_cache_hit_avoids_second_call(settings: Settings) -> None:
    """同一 prompt 第二次走缓存（token 消耗不增加）——写入真实 PG 的 ``llm_cache``。"""
    provider = build_provider(settings)
    tracker = TokenUsageTracker()
    runner = wrap_with_cache(
        provider.structured_with_usage(PaperRelevanceBatch, role="fast"),
        schema=PaperRelevanceBatch,
        model=provider.model_for("fast"),
        provider=provider.name,
        session_factory=lambda: session_scope(get_engine(settings)),
        tracker=tracker,
    )
    messages = [HumanMessage(content=PROMPT)]

    first = await runner.ainvoke(messages)
    tokens_after_first = tracker.total_tokens
    second = await runner.ainvoke(messages)

    assert first == second
    assert tracker.cache_hits >= 1, "第二次应命中缓存"
    assert tracker.total_tokens == tokens_after_first, "命中缓存不得再消耗 token"

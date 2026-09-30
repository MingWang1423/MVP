"""Day7 LLM structured 接入集成测试（PROJECT_PLAN.md §3.2 / §5.6 任务 5）。

**真实调用 DeepSeek**（``.env`` 已配置有效 ``LLM_API_KEY``），因此标记
``@pytest.mark.integration`` —— 默认 ``python -m pytest`` 会跳过。

运行::

    python -m pytest tests/integration/test_llm_structured.py -m integration -q -s

覆盖：
    1. **缺陷回归**：``json_schema`` 在 DeepSeek 报 400，``function_calling`` 正常（根因锚点）；
    2. ``provider.structured()`` 实际使用 ``function_calling``（断言裁决结果 + 真实调用成功）；
    3. ``invoke_structured`` 二次校验（闸门①+②）；
    4. ``structured_with_usage`` 拿到**真实 token 用量**；缓存命中不重复消耗 token（写真实 PG ``llm_cache``）。
"""

from __future__ import annotations

import pytest
from langchain_core.messages import HumanMessage, SystemMessage

from aisec_intel.config import Settings
from aisec_intel.llm.cache import TokenUsageTracker, wrap_with_cache
from aisec_intel.llm.provider import DEFAULT_STRUCTURED_METHOD, build_provider
from aisec_intel.llm.schemas import invoke_structured
from aisec_intel.models.agent_io import PaperRelevanceBatch
from aisec_intel.services.enrich_service import PLACEHOLDER_API_KEYS, llm_available
from aisec_intel.storage.database import get_engine, session_scope

pytestmark = [pytest.mark.integration, pytest.mark.asyncio(loop_scope="module")]
"""本模块全部用例共用**同一个事件循环**。

原因：``openai`` SDK 在每个 ``ChatOpenAI`` 实例内持有 ``httpx.AsyncClient``；
pytest-asyncio 默认按用例新建事件循环，上一个用例的循环关闭后，SDK 客户端会报
``RuntimeError: Event loop is closed``（与本模块第 2 个用例起必现）。
"""

PROMPT = (
    "漏洞：CVE-2024-3400（PAN-OS GlobalProtect 命令注入，CWE-77）。"
    "候选论文 1：paper_id=arxiv:2404.00001，标题《Prompt Injection Against Network Appliances》，"
    "摘要：We study prompt injection in network appliances and report a command injection case.\n"
    "候选论文 2：paper_id=arxiv:2404.00002，标题《Quantum Error Correction》，"
    "摘要：A study on quantum error correcting codes.\n"
    '输出 JSON：{"items": [{"paper_id": "...", "relevant": true, "relation": "mentions",'
    ' "confidence": 0.0, "evidence": "..."}]}'
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


async def test_resolved_method_is_function_calling(settings: Settings) -> None:
    """DeepSeek 的裁决结果必须是 ``function_calling``（库默认 ``json_schema`` 会报 400）。"""
    provider = build_provider(settings)
    assert provider.structured_method_for("fast") == DEFAULT_STRUCTURED_METHOD == "function_calling"


async def test_json_schema_fails_but_function_calling_works(settings: Settings) -> None:
    """**缺陷回归**：同一请求 ``json_schema`` → 400，``function_calling`` → 正常。

    该用例锁定根因（避免有人把 provider 改回库默认），400 不产生生成 token。
    """
    provider = build_provider(settings)
    messages = [SystemMessage(content="只输出 JSON 对象。"), HumanMessage(content=PROMPT)]

    with pytest.raises(Exception) as excinfo:  # noqa: B017 - 断言的是 SDK 侧 400
        await provider.structured(PaperRelevanceBatch, role="fast", method="json_schema").ainvoke(messages)
    status = getattr(excinfo.value, "status_code", None)
    assert status == 400, f"预期 400（response_format 不支持），实际：{type(excinfo.value).__name__} {excinfo.value}"
    print(f"\n[根因固化] json_schema -> HTTP {status}: {str(excinfo.value)[:120]}")

    ok = await provider.structured(PaperRelevanceBatch, role="fast", method="function_calling").ainvoke(messages)
    assert isinstance(ok, PaperRelevanceBatch)


async def test_structured_binding_and_validation(settings: Settings) -> None:
    """``structured()`` 绑定成功且输出可被 Pydantic 二次校验（闸门②）。"""
    provider = build_provider(settings)
    runnable = provider.structured(PaperRelevanceBatch, role="fast")
    messages = [SystemMessage(content="你是漏洞情报分析员。"), HumanMessage(content=PROMPT)]

    batch = await invoke_structured(runnable, PaperRelevanceBatch, messages)

    assert isinstance(batch, PaperRelevanceBatch)
    assert batch.items, "模型应至少返回一条判定"
    assert {item.paper_id for item in batch.items}
    print(f"\n[LLM 判定] {[(item.paper_id, item.relevant, item.confidence) for item in batch.items]}")


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

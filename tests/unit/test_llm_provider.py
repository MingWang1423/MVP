"""Day7 修复：结构化输出 method 裁决测试（DeepSeek 400 缺陷回归）。

背景：``langchain-openai`` 的 ``with_structured_output`` 默认 ``method="json_schema"``，
DeepSeek 官方 API 不支持该 ``response_format``，报
``400 This response_format type is unavailable now``。本模块锁定裁决逻辑与绑定行为。

**全部离线**（不触网）：``ChatOpenAI`` 用桩类替换，断言真实传入的 ``method`` 参数。
"""

from __future__ import annotations

from typing import Any

import pytest

from aisec_intel.llm import provider as provider_module
from aisec_intel.llm.provider import (
    DEFAULT_STRUCTURED_METHOD,
    FALLBACK_STRUCTURED_METHOD,
    NATIVE_STRUCTURED_METHOD,
    JsonModeRunnable,
    LLMConfigError,
    OpenAICompatibleProvider,
    ensure_json_hint,
    is_think_model,
    resolve_structured_method,
)

Schema = type("Schema", (), {})
"""占位 schema（桩模型不校验内容，仅记录方法名）。"""


class FakeStructured:
    """``with_structured_output`` 的返回值桩（记录参数与调用消息）。"""

    def __init__(self, **kwargs: Any) -> None:
        """记录调用参数。"""
        self.kwargs = kwargs
        self.awaited: list[Any] = []

    async def ainvoke(self, messages: Any) -> Any:
        """记录消息并回显。"""
        self.awaited.append(messages)
        return {"messages": messages}


class FakeChatModel:
    """``ChatOpenAI`` 桩（记录构造参数与本轮 ``with_structured_output`` 调用）。"""

    instances: list[FakeChatModel] = []

    def __init__(self, **kwargs: Any) -> None:
        """记录构造参数。"""
        self.init_kwargs = kwargs
        self.calls: list[dict[str, Any]] = []
        FakeChatModel.instances.append(self)

    def with_structured_output(self, schema: Any, **kwargs: Any) -> FakeStructured:
        """记录 ``method`` / ``include_raw`` 等参数。"""
        structured = FakeStructured(**kwargs)
        self.calls.append({"schema": schema.__name__, "bound": structured, **kwargs})
        return structured


@pytest.fixture()
def fake_chat(monkeypatch: pytest.MonkeyPatch) -> type[FakeChatModel]:
    """把 ``langchain_openai.ChatOpenAI`` 替换为桩类（provider 内部延迟导入，故打模块属性）。"""
    import langchain_openai

    FakeChatModel.instances.clear()
    monkeypatch.setattr(langchain_openai, "ChatOpenAI", FakeChatModel)
    return FakeChatModel


class TestResolveMethod:
    """method 裁决（纯函数，覆盖实测矩阵）。"""

    @pytest.mark.parametrize(
        ("provider", "model", "configured", "expected"),
        [
            ("deepseek", "deepseek-chat", None, DEFAULT_STRUCTURED_METHOD),
            ("deepseek", "deepseek-chat", "auto", DEFAULT_STRUCTURED_METHOD),
            ("deepseek", "deepseek-chat", "", DEFAULT_STRUCTURED_METHOD),
            ("deepseek", "deepseek-chat", "  ", DEFAULT_STRUCTURED_METHOD),
            ("deepseek", "deepseek-reasoner", None, FALLBACK_STRUCTURED_METHOD),
            ("deepseek", "deepseek-r1", None, FALLBACK_STRUCTURED_METHOD),
            ("openai", "o1-mini", None, FALLBACK_STRUCTURED_METHOD),
            ("openai", "gpt-4o-mini", None, NATIVE_STRUCTURED_METHOD),
            ("ollama", "qwen2.5", None, NATIVE_STRUCTURED_METHOD),
            ("deepseek", "deepseek-chat", "json_mode", "json_mode"),
            ("deepseek", "deepseek-reasoner", "json_schema", "json_schema"),
            ("openai", "gpt-4o-mini", "function_calling", "function_calling"),
            ("deepseek", "deepseek-chat", "FUNCTION_CALLING", "function_calling"),
        ],
    )
    def test_matrix(self, provider: str, model: str, configured: str | None, expected: str) -> None:
        """裁决结果符合实测支持度矩阵（大小写不敏感、显式配置优先）。"""
        assert resolve_structured_method(provider=provider, model=model, configured=configured) == expected

    def test_invalid_configured_raises(self) -> None:
        """非法配置立即报错（含可选值提示），避免运行期才 400。"""
        with pytest.raises(LLMConfigError, match="LLM_STRUCTURED_METHOD"):
            resolve_structured_method(provider="deepseek", model="deepseek-chat", configured="tools")

    @pytest.mark.parametrize(
        ("model", "expected"),
        [("deepseek-reasoner", True), ("deepseek-chat", False), ("o1-mini", True), ("gpt-4o", False)],
    )
    def test_is_think_model(self, model: str, expected: bool) -> None:
        """思考型模型识别。"""
        assert is_think_model(model) is expected


class TestProviderWiring:
    """provider 与 ``with_structured_output`` 的接线（DeepSeek 400 缺陷的回归锚点）。"""

    @staticmethod
    def _provider(**kwargs: Any) -> OpenAICompatibleProvider:
        """构造默认 DeepSeek provider（fast=chat / smart=reasoner）。"""
        params: dict[str, Any] = {
            "provider": "deepseek",
            "base_url": "https://api.deepseek.com/v1",
            "api_key": "sk-test",
            "model_fast": "deepseek-chat",
            "model_smart": "deepseek-reasoner",
        }
        params.update(kwargs)
        return OpenAICompatibleProvider(**params)

    def test_structured_passes_function_calling(self, fake_chat: type[FakeChatModel]) -> None:
        """**关键回归**：绑定结构化输出时显式传 ``method="function_calling"``（不用库默认）。"""
        self._provider().structured(Schema, role="fast")
        call = fake_chat.instances[-1].calls[-1]
        assert call["method"] == "function_calling"
        assert call["include_raw"] is False

    def test_reasoner_uses_json_mode_and_wraps_hint(self, fake_chat: type[FakeChatModel]) -> None:
        """思考型模型走 ``json_mode``，并包装为自动补 ``json`` 提示词的 Runnable。"""
        runnable = self._provider().structured_with_usage(Schema, role="smart")
        assert isinstance(runnable, JsonModeRunnable)
        assert fake_chat.instances[-1].calls[-1]["method"] == "json_mode"

    def test_configured_method_wins(self, fake_chat: type[FakeChatModel]) -> None:
        """``LLM_STRUCTURED_METHOD`` 显式配置覆盖自动推断（多 provider 兼容）。"""
        provider = self._provider(structured_method="json_schema")
        provider.structured(Schema, role="fast")
        assert fake_chat.instances[-1].calls[-1]["method"] == "json_schema"
        assert provider.structured_method_for("fast") == "json_schema"

    def test_structured_method_for_roles(self) -> None:
        """同一 provider 下不同角色的方式可不同（fast=chat / smart=reasoner）。"""
        provider = self._provider()
        assert provider.structured_method_for("fast") == "function_calling"
        assert provider.structured_method_for("smart") == "json_mode"

    def test_invalid_method_raises_before_calling(self, fake_chat: type[FakeChatModel]) -> None:
        """配置非法时在绑定阶段即失败（不产生网络请求、无实例被创建）。"""
        provider = self._provider(structured_method="bad")
        with pytest.raises(LLMConfigError):
            provider.structured(Schema)
        assert fake_chat.instances == []

    async def test_json_mode_hint_is_injected(self, fake_chat: type[FakeChatModel]) -> None:
        """``json_mode`` 包装器在调用前补充含 ``json`` 的约束（否则部分端点 400）。"""
        runnable = self._provider().structured_with_usage(Schema, role="smart")
        await runnable.ainvoke([("human", "判断相关性")])
        bound = fake_chat.instances[-1].calls[-1]["bound"]
        forwarded = " ".join(str(item) for item in bound.awaited[-1]).lower()
        assert "json" in forwarded


class TestEnsureJsonHint:
    """``json`` 提示词兜底（纯函数）。"""

    def test_merged_batch1(self) -> None:
        """合并用例批次 1：顺序执行 4 个子用例并汇总失败。"""
        failures: list[str] = []
        try:
            self._case_test_appends_when_missing()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_appends_when_missing: {type(exc).__name__}: {exc}")
        try:
            self._case_test_keeps_when_present()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_keeps_when_present: {type(exc).__name__}: {exc}")
        try:
            self._case_test_string_input()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_string_input: {type(exc).__name__}: {exc}")
        try:
            self._case_test_methods_constant()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_methods_constant: {type(exc).__name__}: {exc}")
        assert not failures, "合并用例失败：" + " | ".join(failures)
    def _case_test_appends_when_missing(self) -> None:
        """无 ``json`` 字样时补一条系统消息。"""
        messages = ensure_json_hint([("human", "判断相关性")])
        assert len(messages) == 2
        assert "json" in str(messages[0].content).lower()

    def _case_test_keeps_when_present(self) -> None:
        """已含 ``json`` 时原样返回（不重复注入）。"""
        assert len(ensure_json_hint([("system", "只输出 JSON 对象"), ("human", "判断相关性")])) == 2

    def _case_test_string_input(self) -> None:
        """纯字符串输入就地追加约束（兼容直接传 prompt 的调用方）。"""
        assert "json" in ensure_json_hint("判断相关性").lower()

    def _case_test_methods_constant(self) -> None:
        """可选方式集合与库支持的取值一致（防止误改常量）。"""
        assert provider_module.STRUCTURED_METHODS == ("function_calling", "json_mode", "json_schema")
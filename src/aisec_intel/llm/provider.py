"""LLM 接入抽象（PROJECT_PLAN.md §3.1）：全项目**唯一**允许调用模型的地方。

设计约束（§3.1）：
    1. 只暴露两个方法：``chat()`` 与 ``structured(schema)``，Agent 不允许自行拼 URL / new 客户端；
    2. 模型分层：``fast`` 处理抽取类任务（成本敏感），``smart`` 只用于跨文档多跳推理与 Reviewer；
    3. 切换零成本：``LLM_PROVIDER=ollama`` + ``LLM_BASE_URL=http://localhost:11434/v1`` 即可离线运行。

Day1 落地范围：
    - ``deepseek``：完整支持（默认）；
    - ``ollama``：复用同一 OpenAI 兼容实现（离线兜底，免 Key）；
    - ``qwen`` / ``zhipu``：TODO —— 需先实测 ``with_structured_output`` 支持度后再接入（§3.2）。
"""

from __future__ import annotations

from typing import Any, Literal, Protocol, TypeVar, runtime_checkable

from pydantic import BaseModel

from aisec_intel.config import Settings

TModel = TypeVar("TModel", bound=BaseModel)
"""结构化输出目标类型，必须是 Pydantic 模型。"""

ModelRole = Literal["fast", "smart"]
"""模型角色：``fast``（轻量抽取） / ``smart``（跨文档推理、Reviewer）。"""

DEFAULT_MAX_TOKENS: int = 2048
"""默认单次生成上限（§3.4 额度保护）。"""


class LLMError(RuntimeError):
    """LLM 相关错误基类。"""


class LLMConfigError(LLMError):
    """LLM 配置缺失或非法（如未设置 API Key、缺少依赖）。"""


class LLMUnsupportedProviderError(LLMError):
    """尚未接入的 LLM 提供方。"""


@runtime_checkable
class LLMProvider(Protocol):
    """LLM 接入协议：所有 Agent 只能通过该协议拿模型，禁止直接 new 客户端。"""

    @property
    def name(self) -> str:
        """提供方名称（``deepseek`` / ``ollama`` / ...）。"""
        ...

    def model_for(self, role: ModelRole) -> str:
        """返回指定角色使用的模型名。"""
        ...

    def chat(
        self,
        *,
        role: ModelRole = "fast",
        temperature: float = 0.0,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> Any:
        """返回配置好的 LangChain ChatModel（普通对话用）。"""
        ...

    def structured(
        self,
        schema: type[TModel],
        *,
        role: ModelRole = "fast",
        temperature: float = 0.0,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> Any:
        """返回绑定了结构化输出的模型：输出必须可被 ``schema`` 校验通过。"""
        ...


class OpenAICompatibleProvider:
    """基于 OpenAI 兼容协议的 provider（DeepSeek 主用，Ollama 离线兜底）。

    构造时不做任何网络调用；只有真正构造 ChatModel（``chat`` / ``structured``）时才校验密钥。
    """

    def __init__(
        self,
        *,
        provider: str,
        base_url: str,
        api_key: str,
        model_fast: str,
        model_smart: str,
        timeout_s: int = 60,
        max_retries: int = 2,
        requires_api_key: bool = True,
    ) -> None:
        """初始化 provider。

        Args:
            provider: 提供方标识，如 ``deepseek``。
            base_url: OpenAI 兼容入口地址。
            api_key: 密钥明文（本地 Ollama 可为占位值）。
            model_fast: 轻量模型名。
            model_smart: 推理模型名。
            timeout_s: 单次调用超时（秒）。
            max_retries: SDK 层重试次数。
            requires_api_key: 是否强制要求非空 API Key（Ollama 为 ``False``）。
        """
        self._provider = provider
        self._base_url = base_url
        self._api_key = api_key
        self._model_fast = model_fast
        self._model_smart = model_smart
        self._timeout_s = timeout_s
        self._max_retries = max_retries
        self._requires_api_key = requires_api_key

    @property
    def name(self) -> str:
        """提供方名称。"""
        return self._provider

    @property
    def base_url(self) -> str:
        """OpenAI 兼容入口地址。"""
        return self._base_url

    def model_for(self, role: ModelRole) -> str:
        """返回指定角色的模型名。

        Args:
            role: ``fast`` 或 ``smart``。

        Returns:
            模型名。
        """
        return self._model_smart if role == "smart" else self._model_fast

    def _resolved_api_key(self) -> str:
        """返回可用的 API Key。

        Returns:
            密钥明文；本地提供方缺省为占位值 ``"ollama"``。

        Raises:
            LLMConfigError: 云端提供方未配置 ``LLM_API_KEY``。
        """
        key = self._api_key.strip()
        if self._requires_api_key and not key:
            raise LLMConfigError(
                f"未配置 LLM_API_KEY（provider={self._provider}）："
                "请在 .env 中设置 LLM_API_KEY，或改用 LLM_PROVIDER=ollama 走离线兜底（§3.3）。"
            )
        return key or "ollama"

    def _build_chat_model(self, *, role: ModelRole, temperature: float, max_tokens: int) -> Any:
        """构造 LangChain ChatModel（延迟导入，缺依赖时给出可操作提示）。

        Args:
            role: 模型角色。
            temperature: 采样温度（抽取类任务用 ``0.0``）。
            max_tokens: 生成上限。

        Returns:
            ``langchain_openai.ChatOpenAI`` 实例。

        Raises:
            LLMConfigError: 缺少 ``langchain-openai`` 依赖或未配置 API Key。
        """
        try:
            from langchain_openai import ChatOpenAI
        except ImportError as exc:  # pragma: no cover - 依赖缺失路径
            raise LLMConfigError(
                "缺少依赖 langchain-openai，请执行：pip install langchain-openai"
            ) from exc

        return ChatOpenAI(
            model=self.model_for(role),
            api_key=self._resolved_api_key(),
            base_url=self._base_url,
            temperature=temperature,
            max_tokens=max_tokens,
            timeout=self._timeout_s,
            max_retries=self._max_retries,
        )

    def chat(
        self,
        *,
        role: ModelRole = "fast",
        temperature: float = 0.0,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> Any:
        """返回配置好的 ChatModel（普通对话用）。

        Args:
            role: 模型角色。
            temperature: 采样温度。
            max_tokens: 生成上限。

        Returns:
            可直接 ``ainvoke`` 的 ChatModel。
        """
        return self._build_chat_model(role=role, temperature=temperature, max_tokens=max_tokens)

    def structured(
        self,
        schema: type[TModel],
        *,
        role: ModelRole = "fast",
        temperature: float = 0.0,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> Any:
        """返回绑定结构化输出的模型（§3.2 闸门 ①）。

        Args:
            schema: 目标 Pydantic 模型类。
            role: 模型角色（跨文档推理 / Reviewer 传 ``smart``）。
            temperature: 采样温度。
            max_tokens: 生成上限。

        Returns:
            绑定了 ``with_structured_output(schema)`` 的 Runnable。
        """
        return self.structured_with_usage(
            schema, role=role, temperature=temperature, max_tokens=max_tokens, include_raw=False
        )

    def structured_with_usage(
        self,
        schema: type[TModel],
        *,
        role: ModelRole = "fast",
        temperature: float = 0.0,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        include_raw: bool = True,
    ) -> Any:
        """返回「结构化输出 + 原始响应」的 Runnable（P5 增补，用于 token 计量）。

        ``include_raw=True`` 时 ``ainvoke`` 返回 ``{"raw": AIMessage, "parsed": Schema | None,
        "parsing_error": Exception | None}``，其中的 ``raw.usage_metadata`` 是**真实 token 用量**；
        否则等价于 :meth:`structured`（直接返回 ``Schema``）。

        Args:
            schema: 目标 Pydantic 模型类。
            role: 模型角色。
            temperature: 采样温度。
            max_tokens: 生成上限。
            include_raw: 是否同时返回原始 ``AIMessage``（默认 ``True``）。

        Returns:
            结构化输出 Runnable。

        Raises:
            LLMConfigError: 缺少依赖或未配置 API Key。
        """
        model = self._build_chat_model(role=role, temperature=temperature, max_tokens=max_tokens)
        if not include_raw:
            return model.with_structured_output(schema)
        try:
            return model.with_structured_output(schema, include_raw=True)
        except TypeError:  # pragma: no cover - 兼容不支持 include_raw 的旧版实现
            return model.with_structured_output(schema)


def build_provider(settings: Settings) -> LLMProvider:
    """按配置构建 LLM provider（工厂，唯一构造入口）。

    Args:
        settings: 全局配置对象。

    Returns:
        可用的 ``LLMProvider`` 实例。

    Raises:
        LLMUnsupportedProviderError: ``qwen`` / ``zhipu`` 尚未接入（Day1 起为 TODO）。
    """
    provider = settings.llm_provider
    if provider in {"deepseek", "ollama"}:
        return OpenAICompatibleProvider(
            provider=provider,
            base_url=settings.effective_llm_base_url,
            api_key=settings.llm_api_key.get_secret_value(),
            model_fast=settings.effective_llm_model_fast,
            model_smart=settings.effective_llm_model_smart,
            timeout_s=settings.llm_timeout_s,
            max_retries=settings.llm_max_retries,
            requires_api_key=provider != "ollama",
        )
    # TODO(Day2, §3.2)：用 scripts/smoke_llm.py 实测 with_structured_output 支持度后接入
    #   - qwen : DashScope 兼容模式 / qwen-plus / qwen-max
    #   - zhipu: BigModel / glm-4 系列
    raise LLMUnsupportedProviderError(
        f"LLM_PROVIDER={provider} 尚未接入（TODO Day2）："
        "需先完成 with_structured_output 支持度实测（§3.2），暂请使用 deepseek 或 ollama。"
    )

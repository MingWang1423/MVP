"""LLM 接入抽象（PROJECT_PLAN.md §3.1）：全项目**唯一**允许调用模型的地方。

设计约束（§3.1）：
    1. 只暴露两个方法：``chat()`` 与 ``structured(schema)``，Agent 不允许自行拼 URL / new 客户端；
    2. 模型分层：``fast`` 处理抽取类任务（成本敏感），``smart`` 只用于跨文档多跳推理与 Reviewer；
    3. 切换零成本：``LLM_PROVIDER=ollama`` + ``LLM_BASE_URL=http://localhost:11434/v1`` 即可离线运行。

**结构化输出模式（§3.2 闸门 ①实测结论）**：``langchain-openai`` 的
``with_structured_output`` 默认 ``method="json_schema"``，而 **DeepSeek 官方 API 不支持
``response_format={"type": "json_schema"}``** —— 会返回
``400 This response_format type is unavailable now``。2026-09-30 对真实 API 的实测矩阵：

| provider / model | ``json_schema`` | ``function_calling`` | ``json_mode`` |
|---|---|---|---|
| deepseek / ``deepseek-chat`` | ❌ 400 response_format | ✅ | ✅ |
| deepseek / ``deepseek-reasoner`` | ❌ 400 response_format | ❌ 400（思考模式不支持 tool_choice） | ✅ |
| openai 兼容（Qwen / Zhipu / Ollama 等） | 视端点而定 | ✅（通用最优） | ✅ |

因此本模块**不再使用库默认值**，而是由 :func:`resolve_structured_method` 统一裁决：
``LLM_STRUCTURED_METHOD`` 显式配置优先 → 否则按「思考型模型 → ``json_mode``；
DeepSeek → ``function_calling``；其余 → ``json_schema``」自动推断。

Note:
    ``json_mode`` 依赖提示词中出现 "json" 字样（OpenAI 系同源约束），
    调用方提示词须含该字样（见 :data:`JSON_MODE_HINT`）；``json_mode`` **不做 schema 强约束**，
    因此 :mod:`aisec_intel.llm.schemas` 的二次校验（闸门②）是必需环节。

Day1 落地范围：
    - ``deepseek``：完整支持（默认）；
    - ``ollama``：复用同一 OpenAI 兼容实现（离线兜底，免 Key）；
    - ``qwen`` / ``zhipu``：TODO —— 需先实测 ``with_structured_output`` 支持度后再接入（§3.2）。
"""

from __future__ import annotations

from typing import Any, Literal, Protocol, TypeVar, runtime_checkable

from pydantic import BaseModel

from aisec_intel.config import Settings
from aisec_intel.logging_config import get_logger

logger = get_logger(__name__)

TModel = TypeVar("TModel", bound=BaseModel)
"""结构化输出目标类型，必须是 Pydantic 模型。"""

ModelRole = Literal["fast", "smart"]
"""模型角色：``fast``（轻量抽取） / ``smart``（跨文档推理、Reviewer）。"""

StructuredMethod = Literal["function_calling", "json_mode", "json_schema"]
"""结构化输出实现方式（透传给 ``ChatOpenAI.with_structured_output(method=...)``）。"""

STRUCTURED_METHODS: tuple[StructuredMethod, ...] = ("function_calling", "json_mode", "json_schema")
"""允许的取值（``LLM_STRUCTURED_METHOD`` 的合法集合；``auto`` 表示自动推断）。"""

DEFAULT_STRUCTURED_METHOD: StructuredMethod = "function_calling"
"""DeepSeek 的默认方式（实测可用；``json_schema`` 不可用、``json_mode`` 次优）。"""

FALLBACK_STRUCTURED_METHOD: StructuredMethod = "json_mode"
"""思考型模型（``deepseek-reasoner`` 等不支持 tool_choice）的回退方式。"""

NATIVE_STRUCTURED_METHOD: StructuredMethod = "json_schema"
"""其它 provider 的默认方式（OpenAI 原生最严格；不支持时用配置覆盖）。"""

JSON_MODE_HINT: str = "json"
"""``json_mode`` 要求提示词包含的标识词（小写比对）。"""

_THINK_MODEL_MARKERS: tuple[str, ...] = ("reasoner", "thinking", "-r1", "o1-", "o3-", "o4-")
"""思考型模型标识（不支持 tool_choice → 必须走 ``json_mode``）。"""

AUTO_METHOD_VALUES: frozenset[str] = frozenset({"", "auto", "none", "null"})
"""``LLM_STRUCTURED_METHOD`` 中表示「自动推断」的取值。"""

DEFAULT_MAX_TOKENS: int = 2048
"""默认单次生成上限（§3.4 额度保护）。"""


class LLMError(RuntimeError):
    """LLM 相关错误基类。"""


class LLMConfigError(LLMError):
    """LLM 配置缺失或非法（如未设置 API Key、缺少依赖）。"""


class LLMUnsupportedProviderError(LLMError):
    """尚未接入的 LLM 提供方。"""


def is_think_model(model: str) -> bool:
    """判断是否为思考型模型（不支持 function calling / tool_choice）。

    Args:
        model: 模型名（如 ``deepseek-reasoner``）。

    Returns:
        命中思考型标识返回 ``True``。
    """
    lowered = model.strip().lower()
    return any(marker in lowered for marker in _THINK_MODEL_MARKERS)


def resolve_structured_method(
    *,
    provider: str,
    model: str,
    configured: str | None = None,
) -> StructuredMethod:
    """裁决 ``with_structured_output`` 的 ``method`` 参数（纯函数）。

    优先级：**显式配置 > 模型能力推断 > provider 默认**。

    Args:
        provider: provider 名称（``deepseek`` / ``ollama`` / ...）。
        model: 具体模型名（思考型模型不能走 function calling）。
        configured: ``LLM_STRUCTURED_METHOD`` 取值；``None`` / 空 / ``auto`` 表示自动推断。

    Returns:
        合法的 ``StructuredMethod``。

    Raises:
        LLMConfigError: ``configured`` 非 ``auto`` 且不在 :data:`STRUCTURED_METHODS` 内。
    """
    raw = (configured or "").strip().lower()
    if raw in AUTO_METHOD_VALUES:
        if is_think_model(model):
            return FALLBACK_STRUCTURED_METHOD
        if provider.strip().lower() == "deepseek":
            return DEFAULT_STRUCTURED_METHOD
        return NATIVE_STRUCTURED_METHOD
    if raw not in STRUCTURED_METHODS:
        allowed = ", ".join(STRUCTURED_METHODS)
        raise LLMConfigError(f"LLM_STRUCTURED_METHOD={configured!r} 非法；可选：auto, {allowed}")
    return raw  # type: ignore[return-value]


def ensure_json_hint(messages: Any) -> Any:
    """``json_mode`` 兜底：确保消息中出现 ``json`` 字样（否则部分端点报 400）。

    Args:
        messages: 消息序列（``BaseMessage`` / 字符串 / 单条消息）。

    Returns:
        原消息序列（已含 ``json`` 时原样返回）；否则补充一条含 ``json`` 的系统消息。
    """
    from langchain_core.messages import SystemMessage

    hint = f"Respond with a single JSON object ({JSON_MODE_HINT} only, no extra text)."
    if isinstance(messages, (str, bytes)):
        text = messages.decode("utf-8", "ignore") if isinstance(messages, bytes) else messages
        return text if JSON_MODE_HINT in text.lower() else f"{text}\n\n{hint}"
    if not hasattr(messages, "__iter__"):
        return messages
    items = list(messages)
    joined = " ".join(str(getattr(item, "content", item)) for item in items).lower()
    if JSON_MODE_HINT in joined:
        return items
    return [SystemMessage(content=hint), *items]


class JsonModeRunnable:
    """``json_mode`` 包装器：调用前自动补齐 ``json`` 提示词约束（对上层透明）。

    Attributes:
        method: 固定为 ``json_mode``（便于测试与日志断言）。
    """

    method: str = "json_mode"
    """结构化输出方式。"""

    def __init__(self, runnable: Any) -> None:
        """初始化包装器。

        Args:
            runnable: ``with_structured_output(schema, method="json_mode")`` 的返回值。
        """
        self._runnable = runnable

    async def ainvoke(self, messages: Any) -> Any:
        """异步调用（调用前注入 ``json`` 约束）。

        Args:
            messages: 消息序列。

        Returns:
            结构化输出结果。
        """
        return await self._runnable.ainvoke(ensure_json_hint(messages))

    def invoke(self, messages: Any) -> Any:
        """同步调用（调用前注入 ``json`` 约束）。

        Args:
            messages: 消息序列。

        Returns:
            结构化输出结果。
        """
        return self._runnable.invoke(ensure_json_hint(messages))

    @property
    def wrapped(self) -> Any:
        """被包装的原始 Runnable。"""
        return self._runnable

    def __getattr__(self, item: str) -> Any:
        """未定义的属性透传给被包装对象（便于内省 / 复用接口）。"""
        return getattr(self._runnable, item)



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
        method: str | None = None,
    ) -> Any:
        """返回绑定了结构化输出的模型：输出必须可被 ``schema`` 校验通过。"""
        ...

    def structured_method_for(self, role: ModelRole = "fast") -> str:
        """返回该角色将使用的结构化输出方式（``function_calling`` / ``json_mode`` / ``json_schema``）。"""
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
        structured_method: str | None = None,
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
            structured_method: ``LLM_STRUCTURED_METHOD``；``None``/``auto`` 时按模型能力推断
                （见 :func:`resolve_structured_method`）。
        """
        self._provider = provider
        self._base_url = base_url
        self._api_key = api_key
        self._model_fast = model_fast
        self._model_smart = model_smart
        self._timeout_s = timeout_s
        self._max_retries = max_retries
        self._requires_api_key = requires_api_key
        self._structured_method = structured_method

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
        method: str | None = None,
    ) -> Any:
        """返回绑定结构化输出的模型（§3.2 闸门 ①）。

        **不再使用库默认的 ``json_schema``**：DeepSeek 官方 API 不支持
        ``response_format={"type":"json_schema"}``（实测返回
        ``400 This response_format type is unavailable now``），因此本方法显式传入
        :func:`resolve_structured_method` 裁决出的 ``method``（默认 DeepSeek →
        ``function_calling``；思考型模型 → ``json_mode``）。

        Args:
            schema: 目标 Pydantic 模型类。
            role: 模型角色（跨文档推理 / Reviewer 传 ``smart``）。
            temperature: 采样温度。
            max_tokens: 生成上限。
            method: 显式覆盖 ``LLM_STRUCTURED_METHOD``；``None`` 时按配置 / 模型能力推断。

        Returns:
            绑定了 ``with_structured_output(schema, method=...)`` 的 Runnable。

        Raises:
            LLMConfigError: 缺少依赖、未配置 API Key，或 ``method`` / 配置值非法。
        """
        return self.structured_with_usage(
            schema,
            role=role,
            temperature=temperature,
            max_tokens=max_tokens,
            include_raw=False,
            method=method,
        )

    def structured_method_for(self, role: ModelRole = "fast") -> str:
        """返回该角色将使用的结构化输出方式（可观测性 / 测试断言用）。

        Args:
            role: 模型角色。

        Returns:
            ``function_calling`` / ``json_mode`` / ``json_schema``。
        """
        return resolve_structured_method(
            provider=self._provider,
            model=self.model_for(role),
            configured=self._structured_method,
        )

    def structured_with_usage(
        self,
        schema: type[TModel],
        *,
        role: ModelRole = "fast",
        temperature: float = 0.0,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        include_raw: bool = True,
        method: str | None = None,
    ) -> Any:
        """返回「结构化输出 + 原始响应」的 Runnable（P5 增补，用于 token 计量）。

        ``include_raw=True`` 时 ``ainvoke`` 返回 ``{"raw": AIMessage, "parsed": Schema | None,
        "parsing_error": Exception | None}``，其中的 ``raw.usage_metadata`` 是**真实 token 用量**；
        否则等价于 ``with_structured_output(schema, method=...)``（直接返回 ``Schema``）。

        ``method`` 裁决与 ``json_mode`` 提示词兜底见模块 docstring 与 :class:`JsonModeRunnable`。

        Args:
            schema: 目标 Pydantic 模型类。
            role: 模型角色。
            temperature: 采样温度。
            max_tokens: 生成上限。
            include_raw: 是否同时返回原始 ``AIMessage``（默认 ``True``）。
            method: 显式覆盖结构化输出方式；``None`` 时按配置 / 模型能力推断。

        Returns:
            结构化输出 Runnable。

        Raises:
            LLMConfigError: 缺少依赖、未配置 API Key，或 ``method`` / 配置值非法。
        """
        resolved = method or self.structured_method_for(role)
        model = self._build_chat_model(role=role, temperature=temperature, max_tokens=max_tokens)
        logger.info(
            f"结构化输出绑定：provider={self._provider} model={self.model_for(role)} "
            f"schema={schema.__name__} method={resolved}"
        )
        try:
            runnable = model.with_structured_output(schema, method=resolved, include_raw=include_raw)
        except TypeError:
            # 兼容旧版实现：不支持 method / include_raw 时退回库默认（仅 OpenAI 系能成功）
            logger.warning("当前 langchain 实现不支持 method/include_raw 参数，退回库默认行为")
            runnable = model.with_structured_output(schema)
        if resolved == FALLBACK_STRUCTURED_METHOD:
            return JsonModeRunnable(runnable)
        return runnable


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
            structured_method=settings.llm_structured_method,
        )
    # TODO(Day2, §3.2)：用 scripts/smoke_llm.py 实测 with_structured_output 支持度后接入
    #   - qwen : DashScope 兼容模式 / qwen-plus / qwen-max
    #   - zhipu: BigModel / glm-4 系列
    raise LLMUnsupportedProviderError(
        f"LLM_PROVIDER={provider} 尚未接入（TODO Day2）："
        "需先完成 with_structured_output 支持度实测（§3.2），暂请使用 deepseek 或 ollama。"
    )

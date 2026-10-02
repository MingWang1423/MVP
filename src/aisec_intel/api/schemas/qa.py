"""问答 API 的数据传输契约（Day11 任务 5；PROJECT_PLAN.md §5.8 ``api/schemas/qa.py``）。

设计原则：**直接复用冻结模型**（``models.agent_io.QAQuery`` / ``QAResponse``），
不另造一套 DTO——避免「API 与契约漂移」。本模块只做两件事：

1. 为请求补上默认 ``trace_id``（客户端可不传）；
2. 定义探活响应 :class:`QAHealthResponse`。
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import ConfigDict, Field, field_validator, model_validator

from aisec_intel.models.agent_io import QAQuery
from aisec_intel.models.base import IntelBaseModel, new_trace_id
from aisec_intel.qa.agents.reasoner import MAX_HOPS
from aisec_intel.security.prompt_guard import (
    MAX_QUERY_CHARS,
    PromptInjectionError,
    guard_input,
)


class AskRequest(QAQuery):
    """``POST /qa/ask`` 的请求体（在冻结契约 ``QAQuery`` 之上补默认值 + 安全校验）。

    Day18 任务 2 加固：
        1. **严格模式**（``strict=True``）：类型不符直接 422，不做隐式类型转换；
        2. **长度上限** :data:`~aisec_intel.security.prompt_guard.MAX_QUERY_CHARS`（500 字符）；
        3. **敏感字符 / 注入过滤**：请求进入问答图之前先过
           :func:`~aisec_intel.security.prompt_guard.guard_input`
           （去控制字符 / 零宽字符 / 聊天模板标记，命中注入规则即拒绝）。

    Attributes:
        trace_id: 全链路追踪 ID；客户端不传时自动生成。
        top_k: 单路召回条数上限。
        max_hops: 多跳上限。
        session_context: 多轮会话历史（Day12 任务 6）；不传时由服务端按
            ``session_id`` 从检查点还原上一轮。
    """

    model_config = ConfigDict(extra="forbid", strict=True)

    query: str = Field(
        min_length=1,
        max_length=MAX_QUERY_CHARS,
        description=f"自然语言问题（≤{MAX_QUERY_CHARS} 字符；命中提示词注入规则将被拒绝）",
    )
    trace_id: str = Field(default_factory=new_trace_id, description="全链路追踪 ID（缺省自动生成）")
    max_hops: int = Field(default=MAX_HOPS, ge=1, le=4, description="多跳上限（≥2）")
    session_context: list[str] = Field(default_factory=list, description="多轮会话历史（时间正序）")

    @field_validator("query", mode="before")
    @classmethod
    def _sanitize_query(cls, value: Any) -> Any:
        """清洗查询文本并拦截注入（Day18 任务 2；字段级校验避免赋值递归）。

        Args:
            value: 客户端传入的原始查询值。

        Returns:
            清洗后的查询文本（非字符串原样返回，交由类型校验报错）。

        Raises:
            PromptInjectionError: 命中注入规则或清洗后为空。
        """
        if not isinstance(value, str):
            return value
        verdict = guard_input(value, scope="api")
        if not verdict.allowed:
            raise PromptInjectionError(verdict)
        if verdict.truncated:
            raise ValueError(
                f"查询长度 {verdict.original_chars} 超过上限 {MAX_QUERY_CHARS} 字符，请精简后重试"
            )
        return verdict.text

    @model_validator(mode="after")
    def _ensure_trace(self) -> AskRequest:
        """确保 ``trace_id`` 非空（客户端显式传空串时补生成）。

        Returns:
            校验后的请求体。
        """
        if not self.trace_id.strip():
            self.trace_id = new_trace_id()
        return self



class QAHealthResponse(IntelBaseModel):
    """``GET /qa/health`` 的响应体（问答链路探活快照）。

    Attributes:
        status: 总体状态（``ok`` / ``degraded``）。
        llm_enabled: 是否启用 LLM（云端或本地）。
        degraded_mode: 是否处于降级模式（SQLite + 内存向量库 + 跳过多跳）。
        vector_backend: 向量后端标识。
        neo4j_enabled: 图数据库是否启用。
        plan: 主干节点顺序。
        rate_limit_per_minute: 限流额度。
    """

    model_config = ConfigDict(extra="forbid")

    status: Literal["ok", "degraded"] = Field(description="总体状态")
    llm_enabled: bool = Field(description="是否启用 LLM")
    degraded_mode: bool = Field(description="是否处于降级模式")
    vector_backend: str = Field(description="向量后端标识")
    neo4j_enabled: bool = Field(description="图数据库是否启用")
    plan: list[str] = Field(default_factory=list, description="主干节点顺序")
    rate_limit_per_minute: int = Field(description="每分钟限流额度")

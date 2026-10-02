"""LLM 降级链（Day17 任务 4.2；PROJECT_PLAN.md §3.3 离线兜底）。

降级顺序（对同一结构化输出 schema）：

1. **主候选**：按角色的首选模型（``smart`` → ``deepseek-reasoner``；``fast`` → ``deepseek-chat``）；
2. **次候选**：`reasoner → chat`（思考型模型不可用时降到轻量模型）；
3. **末候选**：``ollama`` 本地模型（``qwen2.5:7b``，断网 / 额度耗尽时的最后兜底）。

实现方式：:class:`DegradingStructuredRunnable` 包装多个「已绑定结构化输出」的 Runnable，
被 :func:`aisec_intel.llm.cache.wrap_with_cache` 包在内层——因此**缓存、token 计量与降级可叠加**。

Note:
    1. 缓存键仍以**主候选模型**为准（保证命中率）；降级结果会写入同一键，
       ``selfheal`` 日志中留有 ``from → to`` 记录，便于追溯；
    2. 所有候选都失败时抛出最后一次异常，由各 Agent 走**确定性兜底**（不阻断整图）。
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from aisec_intel.config import OLLAMA_MODEL_FAST
from aisec_intel.logging_config import get_logger
from aisec_intel.services.metrics_service import record_llm_failure, record_llm_success
from aisec_intel.services.self_heal import (
    ACTION_DEGRADED,
    ACTION_FALLBACK,
    ACTION_RECOVERED,
    COMPONENT_LLM,
    SelfHealEvent,
    log_self_heal,
)

logger = get_logger(__name__)

DEGRADE_CHAIN: tuple[str, ...] = ("smart", "fast", "ollama")
"""降级链的角色顺序（文档与断言共用）。"""


def fallback_plan(
    role: str,
    *,
    fast_model: str,
    smart_model: str,
    ollama_model: str = OLLAMA_MODEL_FAST,
) -> tuple[tuple[str, str], ...]:
    """返回某角色的降级候选计划（``(角色, 模型名)`` 序列，**不含主候选**）。

    规则（Day17 任务 4.2）：
        - ``smart``（reasoner）：``→ fast（chat）→ ollama``；
        - ``fast``（chat）：``→ ollama``。

    Args:
        role: 主候选角色（``fast`` / ``smart``）。
        fast_model: 轻量模型名（chat）。
        smart_model: 推理模型名（reasoner）；为空时按轻量模型处理。
        ollama_model: 本地兜底模型名。

    Returns:
        降级候选序列。
    """
    if role == "smart":
        plan: list[tuple[str, str]] = []
        if fast_model:
            plan.append(("fast", fast_model))
        plan.append(("ollama", ollama_model))
        return tuple(plan)
    del smart_model
    return (("ollama", ollama_model),)



@dataclass(frozen=True, slots=True)
class Candidate:
    """一个候选结构化输出 Runnable。

    Attributes:
        label: 候选标识（模型名，用于日志 / 指标 / 缓存键）。
        runnable: 已绑定 schema 的 Runnable（需支持 ``ainvoke``）。
    """

    label: str
    runnable: Any


class DegradingStructuredRunnable:
    """按序尝试候选 Runnable，失败即降级到下一个（reasoner → chat → Ollama）。

    Attributes:
        schema_name: 目标 Pydantic 模型名（日志用）。
        model: 主候选模型名（供缓存键使用）。
    """

    def __init__(self, candidates: Sequence[Candidate], *, schema_name: str) -> None:
        """初始化降级链。

        Args:
            candidates: 候选序列（第一个为主候选，顺序即降级顺序）。
            schema_name: 目标 Pydantic 模型名。

        Raises:
            ValueError: 候选为空。
        """
        if not candidates:
            raise ValueError("DegradingStructuredRunnable 至少需要一个候选 Runnable")
        self._candidates: tuple[Candidate, ...] = tuple(candidates)
        self.schema_name: str = schema_name
        self.model: str = self._candidates[0].label

    @property
    def candidate_models(self) -> tuple[str, ...]:
        """候选模型名序列（主候选在前）。"""
        return tuple(candidate.label for candidate in self._candidates)

    async def ainvoke(self, messages: Sequence[Any], config: Any | None = None) -> Any:
        """按降级链调用结构化输出。

        Args:
            messages: 消息序列。
            config: LangChain 运行时配置（透传，本实现不使用）。

        Returns:
            首个成功候选的返回值（形态与底层 Runnable 一致）。

        Raises:
            Exception: 全部候选均失败时抛出最后一次异常。
        """
        del config  # 本包装层不消费运行时配置
        last_exc: Exception | None = None
        for index, candidate in enumerate(self._candidates):
            try:
                result = await candidate.runnable.ainvoke(messages)
            except Exception as exc:  # noqa: BLE001 - 需要捕获全部异常以便降级
                last_exc = exc
                record_llm_failure(candidate.label)
                nxt = self._candidates[index + 1] if index + 1 < len(self._candidates) else None
                log_self_heal(
                    SelfHealEvent(
                        component=COMPONENT_LLM,
                        action=ACTION_FALLBACK if nxt else ACTION_DEGRADED,
                        reason=f"{type(exc).__name__}: {exc}",
                        label=f"{self.schema_name}@{candidate.label}",
                        attempt=index + 1,
                        details={"from": candidate.label, "to": nxt.label if nxt else ""},
                    )
                )
                if nxt is None:
                    break
                continue
            record_llm_success()
            if index > 0:
                log_self_heal(
                    SelfHealEvent(
                        component=COMPONENT_LLM,
                        action=ACTION_RECOVERED,
                        reason="降级后成功",
                        label=f"{self.schema_name}@{candidate.label}",
                        attempt=index + 1,
                        details={"candidates": list(self.candidate_models)},
                    )
                )
            return result
        raise last_exc if last_exc is not None else RuntimeError("降级链无可用候选（不应到达）")

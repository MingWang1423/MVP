"""CVSS 推断 Agent（富化维度⑥，P5 收尾；PROJECT_PLAN.md §5.6 ``extractor`` 的数值补齐位）。

**仅在事实缺失时工作**：``UnifiedVuln.cvss`` 非空 → **直接跳过**（§10.2 不变式 4：不得覆写事实）。

推断链路（LLM 只做文本理解，数值全部由 L2 公式给出）：

1. 提示词给出描述 / CWE / 标题，要求输出 **CVSS v3.1 向量串**（``CVSSInference``，闸门①）；
2. 向量串交给 :func:`~aisec_intel.normalize.cvss.parse_cvss_vector` **复算**基础分与严重度（闸门③）；
3. 复算失败（非法向量）或置信度低于阈值 → **丢弃**，只记录错误（**不写脏数据**）。

输出写入 ``state["cvss_inferred"]``（推断值与事实分离，不污染 ``unified_vuln.cvss``）。
"""

from __future__ import annotations

import time
from typing import Any

from aisec_intel.enrich.state import EnrichmentState
from aisec_intel.llm.schemas import StructuredOutputError, invoke_structured
from aisec_intel.logging_config import get_logger
from aisec_intel.models.agent_io import CVSSInference
from aisec_intel.models.enriched_vuln import AgentStep
from aisec_intel.models.unified_vuln import CVSSVector, UnifiedVuln
from aisec_intel.normalize.cvss import parse_cvss_vector, severity_from_vectors
from aisec_intel.security.prompt_guard import sanitize_for_llm

logger = get_logger(__name__)

AGENT_NAME: str = "cvss_enricher"
"""节点名（写入 ``agent_trace.agent``）。"""

MODEL_TAG_OFFLINE: str = "no-llm"
"""未启用 LLM 时的模型标识。"""

DEFAULT_MIN_CONFIDENCE: float = 0.5
"""采纳推断结果的最低置信度。"""

SUPPORTED_VERSION: str = "3.1"
"""允许推断的 CVSS 版本（v2.0 / v4.0 口径差异大，暂不推断）。"""

SYSTEM_PROMPT: str = (
    "你是漏洞评分专家。根据漏洞描述推断 CVSS v3.1 基础向量，"
    "只输出 JSON 对象（含 vector / confidence / rationale），不要输出解释文字或 Markdown。"
    "vector 必须是合法的 CVSS:3.1/AV:... 形式；不确定时给出保守（偏低）赋值并降低 confidence。"
)
"""推断提示词（含 ``json`` 字样以兼容 ``json_mode`` 结构化方式）。"""


def needs_inference(vuln: UnifiedVuln) -> bool:
    """判断是否需要推断 CVSS（纯函数）。

    Args:
        vuln: 漏洞实体。

    Returns:
        ``cvss`` 为空且描述非空时返回 ``True``。
    """
    return not vuln.cvss and bool(vuln.description.strip())


def derive_severity(vector: CVSSVector) -> str:
    """由推断出的向量推导严重度（纯函数，复用 L2 口径）。

    Args:
        vector: 已复算的 CVSS 向量。

    Returns:
        严重度字符串（``NONE`` / ``LOW`` / ``MEDIUM`` / ``HIGH`` / ``CRITICAL``）。
    """
    return str(severity_from_vectors([vector]) or vector.severity)


def validate_inference(inference: CVSSInference) -> CVSSVector:
    """复算校验 LLM 推断的向量（闸门③：数值必须由公式给出）。

    Args:
        inference: LLM 推断结果。

    Returns:
        经公式复算的 :class:`~aisec_intel.models.unified_vuln.CVSSVector`。

    Raises:
        ValueError: 向量非法（无法解析 / 版本不受支持）。
    """
    vector = parse_cvss_vector(inference.vector.strip())
    if vector.version != SUPPORTED_VERSION:
        raise ValueError(f"仅支持推断 CVSS v{SUPPORTED_VERSION}，得到 v{vector.version}（向量：{inference.vector}）")
    return vector


def build_prompt(vuln: UnifiedVuln) -> str:
    """构造 CVSS 推断提示（确定性拼装）。

    Args:
        vuln: 漏洞实体。

    Returns:
        提示文本。
    """
    return "\n".join(
        [
            f"漏洞：{vuln.vuln_id}",
            f"标题：{vuln.title or '(无)'}",
            f"CWE：{', '.join(vuln.cwe_ids) or '(无)'}",
            f"受影响组件：{', '.join(cpe.product for cpe in vuln.cpe_matches) or '(无)'}",
            f"描述：{vuln.description[:1200]}",
            "",
            "推断 CVSS v3.1 基础向量（AV/AC/PR/UI/S/C/I/A 八项齐全），并给出 0-1 的 confidence。",
        ]
    )


class CVSSEnricherAgent:
    """CVSS 推断节点（可调用对象，供 LangGraph 直接注册）。

    Attributes:
        min_confidence: 采纳推断的最低置信度。
    """

    def __init__(
        self,
        *,
        structured_llm: Any | None = None,
        min_confidence: float = DEFAULT_MIN_CONFIDENCE,
        model_tag: str = MODEL_TAG_OFFLINE,
    ) -> None:
        """初始化节点。

        Args:
            structured_llm: ``provider.structured(CVSSInference)``；``None`` 时跳过推断。
            min_confidence: 采纳阈值。
            model_tag: 模型标识（写入轨迹）。
        """
        self._llm = structured_llm
        self._min_confidence = min_confidence
        self._model_tag = model_tag

    async def __call__(self, state: EnrichmentState) -> dict[str, Any]:
        """执行推断（事实缺失时）并返回状态增量。

        Args:
            state: 富化图状态。

        Returns:
            含 ``cvss_inferred``（``list[CVSSVector]``）/ ``agent_steps`` / ``errors`` 的增量字典。
        """
        started = time.perf_counter()
        vuln = state["unified_vuln"]
        errors: list[str] = []
        inferred: list[CVSSVector] = []
        digest = "skipped"

        if vuln.cvss:
            digest = f"skip:已有 CVSS {len(vuln.cvss)} 条（不覆写事实）"
        elif not needs_inference(vuln):
            digest = "skip:描述为空，无法推断"
        elif self._llm is None:
            errors.append(f"{AGENT_NAME}: 未启用 LLM，跳过 CVSS 推断")
            digest = "skip:offline"
        else:
            from langchain_core.messages import HumanMessage, SystemMessage

            messages = [
                SystemMessage(content=SYSTEM_PROMPT),
                # Day18 任务 1：外部文本入模前软清洗
                HumanMessage(content=sanitize_for_llm(build_prompt(vuln))),
            ]
            try:
                inference: CVSSInference = await invoke_structured(self._llm, CVSSInference, messages)
            except StructuredOutputError as exc:
                errors.append(f"{AGENT_NAME}: 结构化输出失败（{exc}）")
                digest = "err:structured"
            else:
                if inference.confidence < self._min_confidence:
                    digest = f"reject:置信度 {inference.confidence} < {self._min_confidence}"
                else:
                    try:
                        vector = validate_inference(inference)
                    except ValueError as exc:
                        errors.append(f"{AGENT_NAME}: 向量复算失败（{exc}）")
                        digest = "err:invalid-vector"
                    else:
                        inferred.append(vector)
                        digest = f"{vector.vector} -> base_score={vector.base_score} ({derive_severity(vector)})"

        step = AgentStep(
            agent=AGENT_NAME,
            round=int(state.get("round", 0)),
            confidence=round(max((vector.base_score / 10 for vector in inferred), default=0.0), 3),
            latency_ms=int((time.perf_counter() - started) * 1000),
            model_used=self._model_tag if self._llm is not None else MODEL_TAG_OFFLINE,
            output_digest=digest[:180],
            error=errors[0] if errors else None,
        )
        return {"cvss_inferred": inferred, "agent_steps": [step], "errors": errors}

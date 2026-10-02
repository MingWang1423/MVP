"""修复建议 Agent（富化维度⑦，P5 收尾）。

流程：

1. **确定性提取**：从 ``UnifiedVuln.references`` 中挑出 ``tags`` 含 ``patch`` 的链接
   （:func:`patch_references`，纯函数）—— 这是「补丁链接」的**唯一可信来源**；
2. **缓解措施**：按受影响组件 / 版本给出确定性兜底建议（:func:`fallback_remediation`，离线可用）；
3. **LLM 增强**（可选）：输出修复结论 / 修复版本 / 缓解措施（``Remediation``，闸门①）；
4. **防幻觉**：LLM 给出的 ``patch_urls`` 若不在 ``references`` 白名单内 → **剔除**
   （:func:`sanitize_remediation`），避免凭空生成链接（§7 R2）。

输出写入 ``state["remediation"]``（``Remediation``），由服务层随 ``EnrichmentOutput`` 返回。
"""

from __future__ import annotations

import time
from typing import Any

from aisec_intel.enrich.state import EnrichmentState
from aisec_intel.llm.schemas import StructuredOutputError, invoke_structured
from aisec_intel.logging_config import get_logger
from aisec_intel.models.agent_io import Remediation
from aisec_intel.models.enriched_vuln import AgentStep
from aisec_intel.models.unified_vuln import Reference, UnifiedVuln
from aisec_intel.security.prompt_guard import sanitize_for_llm

logger = get_logger(__name__)

AGENT_NAME: str = "remediation"
"""节点名（写入 ``agent_trace.agent``）。"""

MODEL_TAG_OFFLINE: str = "no-llm"
"""兜底路径的模型标识。"""

PATCH_TAG: str = "patch"
"""``Reference.tags`` 中表示补丁的标签。"""

MAX_MITIGATIONS: int = 5
"""缓解措施条数上限。"""

SYSTEM_PROMPT: str = (
    "你是漏洞修复顾问。根据漏洞描述、受影响版本与官方补丁链接，给出可执行的修复建议，"
    "只输出 JSON 对象（summary / fixed_versions / mitigations / patch_urls / confidence），"
    "不要输出解释文字或 Markdown。patch_urls 只能从给定链接中挑选，禁止编造 URL。"
)
"""修复建议提示词（含 ``json`` 字样以兼容 ``json_mode``）。"""


def patch_references(vuln: UnifiedVuln) -> list[Reference]:
    """挑出补丁类参考链接（纯函数）。

    Args:
        vuln: 漏洞实体。

    Returns:
        ``tags``（或 ``source``）中含 ``patch`` 的链接列表（保序去重）。
    """
    found: list[Reference] = []
    seen: set[str] = set()
    for reference in vuln.references:
        haystack = " ".join([*reference.tags, reference.source]).lower()
        if PATCH_TAG in haystack and reference.url not in seen:
            seen.add(reference.url)
            found.append(reference)
    return found


def sanitize_remediation(remediation: Remediation, *, allowed_urls: set[str]) -> Remediation:
    """剔除 LLM 编造的补丁链接（纯函数，防幻觉）。

    Args:
        remediation: LLM 产出。
        allowed_urls: ``references`` 中出现的合法 URL 集合。

    Returns:
        仅保留合法链接的修复建议（其余字段原样）。
    """
    kept = [url for url in remediation.patch_urls if url in allowed_urls]
    dropped = [url for url in remediation.patch_urls if url not in allowed_urls]
    if dropped:
        logger.warning(f"修复建议剔除 {len(dropped)} 条不在 references 中的链接：{dropped[:3]}")
    return remediation.model_copy(update={"patch_urls": kept, "mitigations": remediation.mitigations[:MAX_MITIGATIONS]})


def fallback_remediation(vuln: UnifiedVuln, *, patches: list[Reference]) -> Remediation:
    """确定性修复建议（无 LLM / LLM 失败时的兜底，纯函数）。

    Args:
        vuln: 漏洞实体。
        patches: 已提取的补丁链接。

    Returns:
        :class:`~aisec_intel.models.agent_io.Remediation`。
    """
    components = sorted({cpe.product for cpe in vuln.cpe_matches}) or ["受影响组件"]
    versions = vuln.affected_versions or []
    mitigations = [
        f"升级 {component} 至官方修复版本（参考补丁链接）" for component in components[:2]
    ]
    if vuln.kev:
        mitigations.append("该漏洞已进入 CISA KEV（存在在野利用），建议优先处置或临时下线暴露面")
    mitigations.append("收敛网络暴露面：仅允许可信来源访问相关接口 / 服务")
    return Remediation(
        summary=(
            f"{vuln.vuln_id} 建议升级至官方修复版本；"
            f"受影响版本：{', '.join(versions) if versions else '见 CPE 区间'}"
        ),
        fixed_versions=[],
        mitigations=mitigations[:MAX_MITIGATIONS],
        patch_urls=[reference.url for reference in patches],
        confidence=0.5,
        evidence_refs=[
            *(f"patch:{reference.url}" for reference in patches),
            *(f"cpe:{cpe.vendor}:{cpe.product}" for cpe in vuln.cpe_matches),
        ],
    )


def build_prompt(vuln: UnifiedVuln, *, patches: list[Reference]) -> str:
    """构造修复建议提示（确定性拼装）。

    Args:
        vuln: 漏洞实体。
        patches: 已提取的补丁链接。

    Returns:
        提示文本。
    """
    return "\n".join(
        [
            f"漏洞：{vuln.vuln_id}",
            f"标题：{vuln.title or '(无)'}",
            f"受影响组件：{', '.join(cpe.product for cpe in vuln.cpe_matches) or '(无)'}",
            f"受影响版本：{'; '.join(vuln.affected_versions) or '(无)'}",
            f"是否在野利用（KEV）：{'是' if vuln.kev else '否'}",
            f"官方补丁链接：{'; '.join(reference.url for reference in patches) or '(无)'}",
            f"描述：{vuln.description[:800]}",
            "",
            "给出：summary（一句话）、fixed_versions（修复版本号，未知则空）、"
            "mitigations（1-3 条缓解措施）、patch_urls（只能从上面的链接中挑选）、confidence（0-1）。",
        ]
    )


class RemediationAgent:
    """修复建议节点（可调用对象，供 LangGraph 直接注册）。

    Attributes:
        allow_fallback: 无 LLM / LLM 失败时是否使用确定性兜底建议。
    """

    def __init__(
        self,
        *,
        structured_llm: Any | None = None,
        model_tag: str = MODEL_TAG_OFFLINE,
        allow_fallback: bool = True,
    ) -> None:
        """初始化节点。

        Args:
            structured_llm: ``provider.structured(Remediation)``；``None`` 时走确定性兜底。
            model_tag: 模型标识（写入轨迹）。
            allow_fallback: 是否启用确定性兜底。
        """
        self._llm = structured_llm
        self._model_tag = model_tag
        self._allow_fallback = allow_fallback

    async def __call__(self, state: EnrichmentState) -> dict[str, Any]:
        """生成修复建议并返回状态增量。

        Args:
            state: 富化图状态。

        Returns:
            含 ``remediation``（``Remediation | None``）/ ``agent_steps`` / ``errors`` 的增量字典。
        """
        started = time.perf_counter()
        vuln = state["unified_vuln"]
        errors: list[str] = []
        patches = patch_references(vuln)
        allowed_urls = {reference.url for reference in vuln.references}
        remediation: Remediation | None = None
        digest = "skipped"
        tags: list[str] = []

        if self._llm is not None:
            from langchain_core.messages import HumanMessage, SystemMessage

            messages = [
                SystemMessage(content=SYSTEM_PROMPT),
                # Day18 任务 1：外部文本入模前软清洗（去控制字符 / 零宽字符 / 聊天模板标记）
                HumanMessage(content=sanitize_for_llm(build_prompt(vuln, patches=patches))),
            ]
            try:
                raw: Remediation = await invoke_structured(self._llm, Remediation, messages)
            except StructuredOutputError as exc:
                errors.append(f"{AGENT_NAME}: 结构化输出失败（{exc}）")
                digest = "err:structured"
            else:
                remediation = sanitize_remediation(raw, allowed_urls=allowed_urls)
                tags.append(self._model_tag)
                digest = (
                    f"fixed={len(remediation.fixed_versions)} mitigations={len(remediation.mitigations)} "
                    f"patch_urls={len(remediation.patch_urls)}"
                )

        if remediation is None and self._allow_fallback:
            remediation = fallback_remediation(vuln, patches=patches)
            tags.append(MODEL_TAG_OFFLINE)
            digest = f"fallback patches={len(patches)} mitigations={len(remediation.mitigations)}"

        step = AgentStep(
            agent=AGENT_NAME,
            round=int(state.get("round", 0)),
            confidence=round(remediation.confidence if remediation else 0.0, 3),
            latency_ms=int((time.perf_counter() - started) * 1000),
            model_used="+".join(tags) if tags else MODEL_TAG_OFFLINE,
            output_digest=digest[:180],
            error=errors[0] if errors else None,
        )
        return {"remediation": remediation, "agent_steps": [step], "errors": errors}

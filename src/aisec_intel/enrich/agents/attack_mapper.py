r"""ATT&CK 映射 Agent（富化维度⑤，PROJECT_PLAN.md §5.6 ``attack_chain.py``）。

输入 ``cwe_ids`` + ``description`` + ``title``，用 LLM 映射到 **MITRE ATT&CK 技术**并组织成攻击链。

质量控制（防幻觉）：
    1. ``technique_id`` 必须匹配 ``^T\\d{4}(\\.\\d{3})?$``，``tactic`` 必须在白名单内；
    2. 非法步骤被**剔除**并重排 ``order``（不阻断整链）；
    3. 无有效步骤时 ``attack_chain=None`` 且记录错误（**不写脏数据**）；
    4. **无 LLM 时走确定性 CWE → ATT&CK 兜底表**（离线演示链路仍可产出攻击链）；
    5. **模型门控（Day9）**：仅 ``kev=True``（已在野利用）或 ``risk_level ∈ {high, critical}``
       时使用 ``deepseek-reasoner``（``smart`` 角色），其余走 ``deepseek-chat``；
       开关 :attr:`aisec_intel.config.Settings.llm_smart_gate`（``LLM_SMART_GATE``，默认 ``true``）、
       裁决函数 :func:`needs_smart_model`（纯函数，可单测）。
"""

from __future__ import annotations

import re
import time
from collections.abc import Mapping
from typing import Any

from aisec_intel.enrich.agents.risk_scorer import score_risk
from aisec_intel.enrich.state import EnrichmentState
from aisec_intel.llm.schemas import StructuredOutputError, invoke_structured
from aisec_intel.logging_config import get_logger
from aisec_intel.models.agent_io import AttackChainDraft
from aisec_intel.models.enriched_vuln import AgentStep, AttackChain, AttackChainStep
from aisec_intel.models.unified_vuln import UnifiedVuln

logger = get_logger(__name__)

AGENT_NAME: str = "attack_mapper"
"""节点名（写入 ``agent_trace.agent``）。"""

MODEL_TAG_OFFLINE: str = "no-llm"
"""兜底路径的模型标识。"""

MAX_STEPS: int = 6
"""攻击链最大步数（超出截断，避免 LLM 无限展开）。"""

TECHNIQUE_PATTERN: re.Pattern[str] = re.compile(r"^T\d{4}(\.\d{3})?$")
"""ATT&CK 技术 ID 格式（``T1190`` / ``T1059.004``）。"""

TACTICS: frozenset[str] = frozenset(
    {
        "reconnaissance",
        "resource-development",
        "initial-access",
        "execution",
        "persistence",
        "privilege-escalation",
        "defense-evasion",
        "credential-access",
        "discovery",
        "lateral-movement",
        "collection",
        "command-and-control",
        "exfiltration",
        "impact",
    }
)
"""ATT&CK 企业战术白名单。"""

SMART_RISK_LEVELS: frozenset[str] = frozenset({"high", "critical"})
"""触发 ``deepseek-reasoner`` 的风险级别（Day9 门控：只有高危/严重才值得付推理成本）。"""


def needs_smart_model(
    vuln: UnifiedVuln,
    *,
    risk_level: str | None = None,
    gate_enabled: bool = True,
) -> bool:
    """判断攻击链映射是否需要「推理模型」（纯函数，Day9 门控）。

    门控规则（``LLM_SMART_GATE=true`` 时生效）：

        - ``vuln.kev is True``（CISA KEV 已在野利用）→ 用 ``deepseek-reasoner``；
        - ``risk_level ∈ {high, critical}`` → 用 ``deepseek-reasoner``；
        - 其余（``medium`` / ``low`` / 未评分）→ 用 ``deepseek-chat``（便宜且足够）。

    Args:
        vuln: 漏洞事实实体（读取 ``kev``）。
        risk_level: 风险级别（与 ``EnrichedVuln.risk_level`` 同构：``low``/``medium``/``high``/``critical``）；
            ``None`` 表示尚未评分，按「非高危」处理。
        gate_enabled: ``False`` 时**关闭门控**、无条件使用推理模型（等价 P5 行为）。

    Returns:
        ``True`` 表示本次攻击链映射应使用 ``smart`` 角色模型。
    """
    if not gate_enabled:
        return True
    if vuln.kev:
        return True
    return (risk_level or "").strip().lower() in SMART_RISK_LEVELS

FALLBACK_BY_CWE: Mapping[str, tuple[str, str, str, str]] = {
    "CWE-22": ("T1190", "initial-access", "Exploitation", "利用路径穿越读取/写入任意文件"),
    "CWE-77": ("T1059", "execution", "Exploitation", "注入命令并执行（命令注入）"),
    "CWE-78": ("T1059", "execution", "Exploitation", "OS 命令注入执行"),
    "CWE-79": ("T1059.007", "execution", "Exploitation", "跨站脚本在受害端执行脚本"),
    "CWE-89": ("T1190", "initial-access", "Exploitation", "SQL 注入进入数据库"),
    "CWE-94": ("T1059", "execution", "Exploitation", "代码注入执行任意代码"),
    "CWE-119": ("T1203", "execution", "Exploitation", "内存破坏触发代码执行"),
    "CWE-120": ("T1203", "execution", "Exploitation", "缓冲区溢出触发代码执行"),
    "CWE-125": ("T1005", "collection", "Exploitation", "越界读取泄露内存数据"),
    "CWE-190": ("T1203", "execution", "Exploitation", "整数溢出导致内存破坏"),
    "CWE-287": ("T1078", "initial-access", "Exploitation", "认证不当导致身份冒用"),
    "CWE-306": ("T1078", "initial-access", "Exploitation", "缺失认证直接访问敏感功能"),
    "CWE-352": ("T1190", "initial-access", "Exploitation", "CSRF 借用户身份发起请求"),
    "CWE-400": ("T1499", "impact", "Actions-on-Objective", "资源耗尽导致拒绝服务"),
    "CWE-502": ("T1190", "initial-access", "Exploitation", "反序列化触发任意代码执行"),
    "CWE-798": ("T1078.004", "initial-access", "Exploitation", "硬编码凭据可被复用"),
    "CWE-918": ("T1090", "command-and-control", "Exploitation", "服务端请求伪造作为跳板"),
    "CWE-1321": ("T1190", "initial-access", "Exploitation", "原型污染篡改运行时对象"),
    "CWE-1426": ("T1195", "initial-access", "Delivery", "提示注入污染模型输入/工具调用"),
}
"""CWE → ATT&CK 兜底映射（确定性，离线可用；LLM 不可用时使用）。"""

SYSTEM_PROMPT: str = (
    "你是攻击链分析专家。根据漏洞的 CWE、标题与描述，把攻击者路径映射为 MITRE ATT&CK 企业技术序列，"
    "只输出 JSON 对象（steps / entry_vector / privileges_required），不要输出解释文字或 Markdown。"
    "technique_id 必须是形如 T1190 或 T1059.004 的真实技术 ID；"
    "tactic 用连字符小写形式（如 initial-access / execution / privilege-escalation）；"
    "preconditions 为字符串数组；privileges_required 取值 none / low / high / unknown 之一。"
)
"""映射提示词（含 ``json`` 字样以兼容 ``json_mode``）。"""

TACTIC_ALIASES: dict[str, str] = {
    "initial access": "initial-access",
    "resource development": "resource-development",
    "privilege escalation": "privilege-escalation",
    "defense evasion": "defense-evasion",
    "credential access": "credential-access",
    "lateral movement": "lateral-movement",
    "command and control": "command-and-control",
    "execution": "execution",
    "persistence": "persistence",
    "discovery": "discovery",
    "collection": "collection",
    "exfiltration": "exfiltration",
    "impact": "impact",
    "reconnaissance": "reconnaissance",
}
"""战术显示名 → 连字符名（LLM 常返回 ``Initial Access``）。"""

PRIVILEGE_KEYWORDS: tuple[tuple[tuple[str, ...], str], ...] = (
    (("none", "unauth", "unauthenticated", "无需", "未认证", "无", "未授权"), "none"),
    (("low", "低权", "普通用户", "user"), "low"),
    (("high", "admin", "root", "管理员", "高权", "system"), "high"),
)
"""权限自由文本 → 字面量的关键词优先级（先匹配先命中）。"""


def normalize_tactic(value: str) -> str:
    """归一化战术名（纯函数）。

    Args:
        value: 战术名（``Initial Access`` / ``initial-access`` / ``INITIAL_ACCESS``）。

    Returns:
        连字符小写战术名（可能不在白名单内，交由 :func:`is_valid_step` 判定）。
    """
    cleaned = value.strip().lower().replace("_", " ").replace("-", " ")
    cleaned = " ".join(cleaned.split())
    if cleaned in TACTIC_ALIASES:
        return TACTIC_ALIASES[cleaned]
    return cleaned.replace(" ", "-")


def normalize_privileges(value: str) -> str:
    """归一化 ``privileges_required``（纯函数）。

    Args:
        value: 自由文本（``None (unauthenticated)`` / ``root`` / ``无``）。

    Returns:
        ``none`` / ``low`` / ``high`` / ``unknown`` 之一。
    """
    text = (value or "").strip().lower()
    for keywords, literal in PRIVILEGE_KEYWORDS:
        if any(keyword in text for keyword in keywords):
            return literal
    return "unknown"


def normalize_preconditions(value: str | list[str]) -> list[str]:
    """归一化前置条件（纯函数）。

    Args:
        value: 字符串（按 ``；``/``;``/换行切分）或字符串列表。

    Returns:
        去空白后的非空字符串列表。
    """
    raw = [value] if isinstance(value, str) else list(value)
    items: list[str] = []
    for chunk in raw:
        for part in re.split(r"[;\n；]", str(chunk)):
            cleaned = part.strip()
            if cleaned:
                items.append(cleaned)
    return items


def to_attack_chain(draft: AttackChainDraft) -> AttackChain:
    """把 LLM 草稿归一化为冻结模型 ``AttackChain``（纯函数）。

    归一化内容：战术名 slug 化、前置条件字符串→列表、权限文本→字面量、``order`` 重排、
    技术 ID 大写。非法步骤保留（由 :func:`sanitize_chain` 再按白名单剔除），
    以保证「哪些步骤被判非法」可被测试与日志观察。

    Args:
        draft: LLM 产出的攻击链草稿。

    Returns:
        :class:`~aisec_intel.models.enriched_vuln.AttackChain`。
    """
    steps = [
        AttackChainStep(
            order=index,
            technique_id=item.technique_id.strip().upper(),
            tactic=normalize_tactic(item.tactic),
            stage=item.stage.strip() or "Exploitation",
            description=item.description.strip(),
            preconditions=normalize_preconditions(item.preconditions),
        )
        for index, item in enumerate(draft.steps, start=1)
    ]
    return AttackChain(
        steps=steps,
        entry_vector=(draft.entry_vector or None),
        privileges_required=normalize_privileges(draft.privileges_required),  # type: ignore[arg-type]
    )


def build_prompt(vuln: UnifiedVuln) -> str:
    """构造 ATT&CK 映射提示（确定性拼装）。

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
            f"描述：{vuln.description[:1000]}",
            "",
            "输出攻击链：1~4 步，每步给出 order / technique_id / tactic / stage / description / preconditions。",
        ]
    )


def is_valid_step(step: AttackChainStep) -> bool:
    """校验单步是否合法（纯函数）。

    Args:
        step: 攻击链步骤。

    Returns:
        ``technique_id`` 合法且 ``tactic`` 在白名单内时返回 ``True``。
    """
    return bool(TECHNIQUE_PATTERN.match(step.technique_id.strip().upper())) and step.tactic.strip().lower() in TACTICS


def sanitize_chain(chain: AttackChain) -> AttackChain:
    """剔除非法步骤并重排顺序（纯函数）。

    Args:
        chain: LLM 产出的攻击链。

    Returns:
        清洗后的攻击链（保留前 :data:`MAX_STEPS` 条合法步骤，``order`` 从 1 重排）。
    """
    valid = [step for step in chain.steps if is_valid_step(step)][:MAX_STEPS]
    renumbered = [
        AttackChainStep(
            order=index,
            technique_id=step.technique_id.strip().upper(),
            tactic=step.tactic.strip().lower(),
            stage=step.stage,
            description=step.description,
            preconditions=list(step.preconditions),
        )
        for index, step in enumerate(valid, start=1)
    ]
    return AttackChain(
        steps=renumbered,
        entry_vector=chain.entry_vector,
        privileges_required=chain.privileges_required,
    )


def fallback_chain(vuln: UnifiedVuln) -> AttackChain | None:
    """按 CWE 兜底生成攻击链（纯函数，离线可用）。

    Args:
        vuln: 漏洞实体。

    Returns:
        攻击链；CWE 未登记在兜底表时返回 ``None``。
    """
    steps: list[AttackChainStep] = []
    for cwe in vuln.cwe_ids:
        mapped = FALLBACK_BY_CWE.get(cwe.strip().upper())
        if mapped is None:
            continue
        technique_id, tactic, stage, description = mapped
        steps.append(
            AttackChainStep(
                order=len(steps) + 1,
                technique_id=technique_id,
                tactic=tactic,
                stage=stage,
                description=f"{description}（依据 {cwe}）",
                preconditions=["目标可达", "组件版本在受影响区间"],
            )
        )
    if not steps:
        return None
    return AttackChain(steps=steps, entry_vector=vuln.title or "通过网络接口触达", privileges_required="none")


class ATTACKMapperAgent:
    """ATT&CK 映射节点（可调用对象，供 LangGraph 直接注册）。

    Attributes:
        max_steps: 攻击链步数上限。
    """

    def __init__(
        self,
        *,
        structured_llm: Any | None = None,
        fast_llm: Any | None = None,
        max_steps: int = MAX_STEPS,
        model_tag: str = MODEL_TAG_OFFLINE,
        fast_model_tag: str | None = None,
        allow_fallback: bool = True,
        smart_gate: bool = True,
    ) -> None:
        """初始化节点。

        Args:
            structured_llm: ``provider.structured(AttackChainDraft, role="smart")``（推理模型）；
                ``None`` 时走兜底表。
            fast_llm: ``provider.structured(AttackChainDraft, role="fast")``（轻量模型，Day9 门控）；
                ``None`` 时门控退化为「始终用 ``structured_llm``」。
            max_steps: 步数上限。
            model_tag: ``smart`` 模型标识（写入轨迹 ``model_used``）。
            fast_model_tag: ``fast`` 模型标识；``None`` 时回退为 ``model_tag``（避免误标模型来源）。
            allow_fallback: LLM 失败 / 不可用时是否使用 CWE 兜底表。
            smart_gate: ``True``（默认，受 ``LLM_SMART_GATE`` 控制）时按 :func:`needs_smart_model`
                门控模型选择；``False`` 时无条件使用 ``structured_llm``（P5 行为，便于对照实验）。
        """
        self._llm = structured_llm
        self._fast_llm = fast_llm
        self._max_steps = max(1, max_steps)
        self._model_tag = model_tag
        self._fast_model_tag = fast_model_tag or model_tag
        self._allow_fallback = allow_fallback
        self._smart_gate = smart_gate

    async def __call__(self, state: EnrichmentState) -> dict[str, Any]:
        """映射攻击链并返回状态增量。

        Args:
            state: 富化图状态。

        Returns:
            含 ``attack_chain`` / ``agent_steps`` / ``errors`` 的增量字典。
        """
        started = time.perf_counter()
        vuln = state["unified_vuln"]
        errors: list[str] = []
        chain: AttackChain | None = None
        digest = "skipped"
        tags: list[str] = []

        # Day9 门控：先用确定性风险公式评分（不调用 LLM），再决定用推理模型还是轻量模型。
        risk = score_risk(vuln, state.get("exploits") or [], inferred_cvss=state.get("cvss_inferred") or ())
        use_smart = needs_smart_model(vuln, risk_level=risk.level, gate_enabled=self._smart_gate)
        llm = self._llm if use_smart or self._fast_llm is None else self._fast_llm
        model_tag = self._model_tag if llm is self._llm else self._fast_model_tag

        if llm is not None:
            from langchain_core.messages import HumanMessage, SystemMessage

            messages = [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=build_prompt(vuln))]
            try:
                draft: AttackChainDraft = await invoke_structured(llm, AttackChainDraft, messages)
            except StructuredOutputError as exc:
                errors.append(f"{AGENT_NAME}: 结构化输出失败（{exc}）")
                digest = "err:structured"
            else:
                cleaned = sanitize_chain(to_attack_chain(draft))
                dropped = len(draft.steps) - len(cleaned.steps)
                if cleaned.steps:
                    chain = cleaned
                    tags.append(model_tag)
                    role = "smart" if llm is self._llm else "fast"
                    digest = (
                        f"gate={role} risk={risk.level} steps={len(cleaned.steps)} "
                        f"dropped={dropped} entry={cleaned.entry_vector or '-'}"
                    )
                else:
                    errors.append(f"{AGENT_NAME}: LLM 产出的步骤全部非法（technique_id/tactic 校验失败）")
                    digest = "err:invalid-steps"

        if chain is None and self._allow_fallback:
            chain = fallback_chain(vuln)
            if chain is not None:
                tags.append(MODEL_TAG_OFFLINE)
                digest = f"fallback steps={len(chain.steps)} cwe={','.join(vuln.cwe_ids) or '-'}"
            elif not errors:
                errors.append(f"{AGENT_NAME}: 无法映射 ATT&CK（无 LLM 且 CWE 未登记兜底表）")

        used_llm = bool(chain is not None and tags and tags[0] != MODEL_TAG_OFFLINE)
        step_confidence = 0.75 if used_llm else (0.4 if chain is not None else 0.0)
        step = AgentStep(
            agent=AGENT_NAME,
            round=int(state.get("round", 0)),
            confidence=round(step_confidence, 3),
            latency_ms=int((time.perf_counter() - started) * 1000),
            model_used="+".join(tags) if tags else MODEL_TAG_OFFLINE,
            output_digest=digest[:180],
            error=errors[0] if errors else None,
        )
        return {"attack_chain": chain, "agent_steps": [step], "errors": errors}

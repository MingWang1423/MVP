"""提示词注入防护与 LLM 输出校验（Day18 任务 1/2）。

四道防线（与 §3.2 结构化输出闸门互补）：

============  ==========================================================================
① 输入清洗      Unicode NFKC 归一 → 去控制字符 / 零宽字符 → 剥离聊天模板标记 → 截断长度
② 注入检测     28 条规则（中英双语 + 模板标记 + 编码绕过 + 边界伪造），命中即拒绝并留痕
③ 输出校验      强制 Pydantic 二次校验（不接受自由文本 / 未知字段），失败抛
               :class:`OutputValidationError`（由富化层转为 degraded）
④ 全链路留痕    命中写结构化日志 ``security.injection_blocked`` + 指标
               ``aisec_security_blocks_total{rule,severity}``
============  ==========================================================================

使用约定：

- **严格模式**（用户输入 / API 请求 / CLI）：:func:`guard_input` / :func:`assert_safe_query`
  —— 命中 high（默认含 medium）即拒绝并留痕；
- **软清洗**（把外部文本拼进 LLM 提示词前）：:func:`sanitize_for_llm`
  —— 只做清洗（不抛错），保证「外部内容永不携带可执行的提示词控制标记」；
- **输出侧**：:func:`validate_llm_output` —— 任何 LLM 结果都必须过一遍 Pydantic。

设计原则：
    1. 纯函数优先（检测 / 清洗不依赖全局状态，便于单测与离线复现）；
    2. 不引入第三方依赖（无 jailbreak 分类模型 / 无外部规则库），保证 Docker 镜像与断网可用；
    3. 命中即留痕（日志 + 指标），但**不打印完整恶意文本**（截断 120 字符，避免日志注入）。
"""

from __future__ import annotations

import json
import logging
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Literal, TypeVar

from pydantic import BaseModel, ValidationError

from aisec_intel.logging_config import get_logger, log_event
from aisec_intel.services.metrics_service import M_SECURITY_BLOCKS, METRICS

logger = get_logger(__name__)

Severity = Literal["high", "medium"]
"""命中严重度：``high`` 一票否决；``medium`` 在严格模式下同样拒绝。"""

MAX_QUERY_CHARS: int = 500
"""用户查询长度上限（Day18 任务 2 硬性要求）。"""

MAX_PROMPT_CHARS: int = 4000
"""单段外部文本拼入提示词时的长度上限（与向量索引文本上限同量级）。"""

EXCERPT_CHARS: int = 120
"""命中片段在日志 / 响应中的截断长度（避免日志注入与隐私泄露）。"""

CONTROL_CHARS_PATTERN: re.Pattern[str] = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
"""控制字符（保留 ``\\t`` / ``\\n`` / ``\\r``）。"""

ZERO_WIDTH_PATTERN: re.Pattern[str] = re.compile(r"[\u200b-\u200f\u2060-\u2064\ufeff\u202a-\u202e]")
"""零宽 / 双向控制字符（常见的提示词夹带与视觉伪装手段）。"""

CHAT_TEMPLATE_PATTERN: re.Pattern[str] = re.compile(
    r"<\|(?:im_start|im_end|system|user|assistant|endoftext|start_header_id|end_header_id|begin_of_text)"
    r"(?:\|[^>]*)?\|>"
    r"|\[/?INST\]|<<\s*/?SYS\s*>>|</?s>",
    re.IGNORECASE,
)
"""聊天模板 / 特殊标记（ChatML / Llama / Mistral 风格）。"""

ROLE_LINE_PATTERN: re.Pattern[str] = re.compile(
    r"(?im)^[ \t]*(?:#{2,4}[ \t]*)?(?:system|assistant|developer|系统|助手)[ \t]*[:：]"
)
"""行首角色标记（``system:`` / ``## assistant:`` / 中文角色）—— 伪造对话角色。"""

ROLE_HEADER_PATTERN: re.Pattern[str] = re.compile(r"(?im)^[ \t]*#{2,4}[ \t]*(?:system|instruction|override)\b")
"""Markdown 标题式角色覆盖（``### System`` / ``## Instruction``）。"""

TModel = TypeVar("TModel", bound=BaseModel)


class PromptInjectionError(ValueError):
    """检测到提示词注入：调用方应拒绝该输入（API 返回 4xx / CLI 打印拦截信息）。"""

    def __init__(self, verdict: GuardVerdict) -> None:
        """构造异常。

        Args:
            verdict: 触发拒绝的守卫结论。
        """
        self.verdict = verdict
        rules = ", ".join(verdict.rule_names) or "empty_input"
        super().__init__(f"输入被安全策略拦截（{rules}）：{verdict.excerpt()}")


class OutputValidationError(ValueError):
    """LLM 输出未通过结构化校验（调用方须标记 degraded，不得写脏数据）。"""


_CORE_RULES: tuple[tuple[str, Severity, re.Pattern[str]], ...] = (
    # ---------- 指令覆盖（英文 / 中文）----------
    (
        "instruction_override_en",
        "high",
        re.compile(
            r"\b(?:ignore|disregard|forget|skip|override|bypass)\b[^.\n]{0,40}"
            r"\b(?:previous|prior|above|earlier|all|any)\b[^.\n]{0,24}"
            r"\b(?:instruction|prompt|rule|direction|message|constraint)s?\b",
            re.IGNORECASE,
        ),
    ),
    (
        "instruction_override_zh",
        "high",
        re.compile(
            r"(?:忽略|无视|忘记|跳过|覆盖|摆脱)[^。\n]{0,24}"
            r"(?:以上|之前|先前|上面|所有|全部|任何)?[^。\n]{0,12}"
            r"(?:指令|提示|规则|要求|设定|限制)"
        ),
    ),
    (
        "new_instructions",
        "high",
        re.compile(
            r"\bnew\s+(?:instructions?|rules?|task)\s*[:：]"
            r"|\bupdated\s+instructions?\b"
            r"|(?:新的|以下是新的|重新设定)(?:指令|规则|任务)",
            re.IGNORECASE,
        ),
    ),
    # ---------- 角色 / 模板标记伪造 ----------
    ("chat_template_token", "high", CHAT_TEMPLATE_PATTERN),
    ("llama_inst_tag", "high", re.compile(r"\[/?INST\]|<<\s*/?SYS\s*>>", re.IGNORECASE)),
    ("role_line_marker", "high", ROLE_LINE_PATTERN),
    ("role_header_markdown", "high", ROLE_HEADER_PATTERN),
    (
        "prompt_boundary_spoof",
        "high",
        re.compile(
            r"(?im)^[ \t]*(?:end|beginning|start)\s+of\s+(?:system|user|assistant)\s+"
            r"(?:prompt|message|input|turn)"
        ),
    ),
    # ---------- 越狱 / 人格劫持 ----------
    (
        "persona_jailbreak",
        "high",
        re.compile(
            r"\b(?:dan\s*mode|do anything now|jailbreak|developer mode|unrestricted mode"
            r"|no restrictions|no filters)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "jailbreak_zh",
        "high",
        re.compile(r"(?:越狱|开发者模式|无限制模式|不受(?:任何)?限制|解除(?:所有)?限制|跳出(?:你的)?限制)"),
    ),
    (
        "you_are_now",
        "medium",
        re.compile(
            r"\b(?:you are now|from now on[, ]+you (?:are|will|must)|act as if you (?:are|were)"
            r"|pretend (?:that )?you(?:'re| are))\b",
            re.IGNORECASE,
        ),
    ),
    (
        "role_play_hijack",
        "medium",
        re.compile(r"\b(?:pretend|imagine|simulate)\b[^.\n]{0,20}\b(?:you|to be)\b", re.IGNORECASE),
    ),
    # ---------- 系统提示词套取 ----------
    (
        "prompt_leak_en",
        "high",
        re.compile(
            r"\b(?:reveal|show|print|repeat|echo|dump|disclose|tell me)\b[^.\n]{0,30}\b"
            r"(?:system prompt|system message|initial instruction|your instructions?"
            r"|the prompt above|words above|everything above)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "prompt_leak_zh",
        "high",
        re.compile(r"(?:泄露|透露|输出|展示|打印|重复|复述)[^。\n]{0,12}(?:系统提示词|系统提示|系统指令|初始指令|上面的指令|之前的指令)"),
    ),
    (
        "repeat_words_above",
        "high",
        re.compile(
            r"\b(?:repeat|echo|copy)\b[^.\n]{0,20}\b(?:the\s+)?(?:words|text|content|everything|prompt)\b"
            r"[^.\n]{0,20}\babove\b",
            re.IGNORECASE,
        ),
    ),
)

_EXTENDED_RULES: tuple[tuple[str, Severity, re.Pattern[str]], ...] = (
    # ---------- 安全机制绕过 ----------
    (
        "bypass_safety",
        "high",
        re.compile(
            r"\b(?:bypass|disable|turn off|evade|ignore)\b[^.\n]{0,25}\b(?:safety|guardrail|guard rails?"
            r"|filter|filtering|restriction|policy|moderation|alignment)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "bypass_safety_zh",
        "high",
        re.compile(r"(?:绕过|关闭|禁用|无视)[^。\n]{0,12}(?:审查|安全|过滤|限制|策略|风控)"),
    ),
    (
        "unfiltered_output",
        "medium",
        re.compile(
            r"\b(?:respond|answer|reply|write)\b[^.\n]{0,20}\b(?:without|ignoring|regardless of)\b"
            r"[^.\n]{0,20}\b(?:restriction|filter|policy|ethic|rule)s?\b",
            re.IGNORECASE,
        ),
    ),
    (
        "do_not_mention",
        "medium",
        re.compile(
            r"\b(?:do not|don't)\b[^.\n]{0,15}\b(?:mention|tell|reveal|disclose)\b[^.\n]{0,25}"
            r"\b(?:instruction|prompt|rule|user)s?\b"
            r"|(?:不要|不得)(?:提及|告诉|透露)[^。\n]{0,15}(?:指令|提示|用户)",
            re.IGNORECASE,
        ),
    ),
    # ---------- 编码 / 变量走私 ----------
    (
        "encoding_evasion",
        "medium",
        re.compile(
            r"\b(?:base64|rot13|hex(?:adecimal)?|base32|url[- ]?encoded?)\b[^.\n]{0,30}"
            r"\b(?:decode|decoding|解码)\b[^.\n]{0,30}\b(?:then|and|并|然后)\b[^.\n]{0,20}"
            r"\b(?:run|execute|follow|obey|执行|运行|遵守)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "template_variable_smuggling",
        "medium",
        re.compile(
            r"\{\{[^}]{0,30}(?:system|prompt|instruction)[^}]{0,30}\}\}"
            r"|\$\{[^}]{0,30}(?:system|prompt|instruction)[^}]{0,30}\}"
        ),
    ),
    (
        "json_field_injection",
        "medium",
        re.compile(r"""["'](?:tool_calls?|function_call|system_prompt|role)["']\s*:"""),
    ),
    ("zero_width_obfuscation", "high", ZERO_WIDTH_PATTERN),
    # ---------- 命令 / 注入类载荷 ----------
    (
        "shell_payload",
        "high",
        re.compile(
            r"\brm\s+-rf\b"
            r"|\bcurl\b[^|\n]{0,80}\|\s*(?:ba|z|k)?sh\b"
            r"|\bsubprocess\.(?:run|call|Popen)\b"
            r"|\bos\.system\s*\(",
            re.IGNORECASE,
        ),
    ),
    (
        "sql_payload",
        "medium",
        re.compile(r"(?i)\b(?:drop\s+table|truncate\s+table|delete\s+from|insert\s+into|update\s+\w+\s+set)\b"),
    ),
    ("cypher_payload", "medium", re.compile(r"(?i)\b(?:detach\s+delete|drop\s+constraint|create\s+\(|merge\s+\()")),
    (
        "tool_abuse",
        "high",
        re.compile(
            r"\b(?:call|invoke|execute|use)\b[^.\n]{0,20}\b(?:the\s+)?(?:tool|function)\b[^.\n]{0,30}"
            r"\b(?:delete|drop|truncate|exfiltrate|leak|write)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "delimiter_override",
        "medium",
        re.compile(
            r"(?m)^[ \t]*(?:-{3,}|={3,}|<{3,}|>{3,})[ \t]*"
            r"(?:end|begin|new|system|user|context|输入结束|系统提示)"
        ),
    ),
)

INJECTION_RULES: tuple[tuple[str, Severity, re.Pattern[str]], ...] = _CORE_RULES + _EXTENDED_RULES
"""注入检测规则表：``(规则名, 严重度, 正则)``，共 ``len(INJECTION_RULES)`` 条。

规则名会进入日志与指标标签（便于统计「哪种攻击最常见」），因此保持稳定的英文小写命名；
``high`` 一票否决，``medium`` 在严格模式下同样拒绝（软清洗路径不受影响）。
"""



@dataclass(frozen=True, slots=True)
class InjectionFinding:
    """一条注入命中记录。

    Attributes:
        rule: 规则名（见 :data:`INJECTION_RULES`）。
        severity: 严重度。
        excerpt: 命中片段（截断 :data:`EXCERPT_CHARS` 字符）。
    """

    rule: str
    severity: Severity
    excerpt: str

    def as_dict(self) -> dict[str, str]:
        """转换为可 JSON 序列化的字典。

        Returns:
            含 ``rule`` / ``severity`` / ``excerpt`` 的字典。
        """
        return {"rule": self.rule, "severity": self.severity, "excerpt": self.excerpt}


@dataclass(frozen=True, slots=True)
class GuardVerdict:
    """输入守卫结论。

    Attributes:
        allowed: 是否放行（``False`` 表示命中拦截规则或清洗后为空）。
        text: 清洗后的文本（已剥离控制字符 / 零宽字符 / 模板标记并截断）。
        findings: 命中的注入规则列表。
        original_chars: 原始输入长度。
        truncated: 是否因超长被截断。
    """

    allowed: bool
    text: str
    findings: tuple[InjectionFinding, ...] = field(default_factory=tuple)
    original_chars: int = 0
    truncated: bool = False

    @property
    def rule_names(self) -> tuple[str, ...]:
        """命中规则名（去重保序）。"""
        seen: list[str] = []
        for finding in self.findings:
            if finding.rule not in seen:
                seen.append(finding.rule)
        return tuple(seen)

    def excerpt(self) -> str:
        """返回用于提示的首个命中片段（无命中时返回清洗后文本前缀）。

        Returns:
            截断后的文本片段。
        """
        if self.findings:
            return self.findings[0].excerpt
        return self.text[:EXCERPT_CHARS]

    def as_dict(self) -> dict[str, Any]:
        """转换为可 JSON 序列化的字典（日志 / API 响应共用）。

        Returns:
            含 ``allowed`` / ``rules`` / ``original_chars`` / ``truncated`` 的字典。
        """
        return {
            "allowed": self.allowed,
            "rules": list(self.rule_names),
            "original_chars": self.original_chars,
            "truncated": self.truncated,
        }


def strip_control_chars(text: str) -> str:
    """删除控制字符（保留制表符与换行，纯函数）。

    Args:
        text: 原始文本。

    Returns:
        去除控制字符后的文本（NUL / ESC / DEL 等一律删除）。
    """
    return CONTROL_CHARS_PATTERN.sub("", text)


def strip_chat_markup(text: str) -> str:
    """剥离聊天模板标记与行首角色标记（纯函数）。

    Args:
        text: 原始文本。

    Returns:
        去掉 ``<|im_start|>`` / ``[INST]`` / ``<<SYS>>`` / 行首 ``system:`` 后的文本。
    """
    without_tokens = CHAT_TEMPLATE_PATTERN.sub(" ", text)
    without_role_headers = ROLE_LINE_PATTERN.sub(" ", without_tokens)
    return ROLE_HEADER_PATTERN.sub(" ", without_role_headers)


def normalize_text(text: str, *, max_chars: int | None = None) -> tuple[str, bool]:
    """规范化文本：NFKC 归一 → 去零宽 / 控制字符 → 空白规整 → 截断（纯函数）。

    Args:
        text: 原始文本（``None`` 视为空串）。
        max_chars: 字符上限；``None`` 或 ``<=0`` 表示不截断。

    Returns:
        ``(规范化文本, 是否被截断)``。
    """
    normalized = unicodedata.normalize("NFKC", text or "")
    normalized = ZERO_WIDTH_PATTERN.sub("", normalized)
    normalized = strip_control_chars(normalized)
    # 折叠连续空格与 3 个以上换行（保留段落结构），避免「超长空白」撑爆 token
    normalized = re.sub(r"[ \t\u3000]{2,}", " ", normalized)
    normalized = re.sub(r"\n{3,}", "\n\n", normalized).strip()
    if max_chars is not None and max_chars > 0 and len(normalized) > max_chars:
        return normalized[:max_chars], True
    return normalized, False


def detect_injection(text: str) -> list[InjectionFinding]:
    """检测提示词注入模式（纯函数，不抛异常、不写日志）。

    Args:
        text: 待检测文本（建议先经 :func:`normalize_text`）。

    Returns:
        命中列表（按 :data:`INJECTION_RULES` 顺序，同一规则只报一次）。
    """
    if not text or not text.strip():
        return []
    cleaned = strip_chat_markup(text)
    findings: list[InjectionFinding] = []
    for rule, severity, pattern in INJECTION_RULES:
        match = pattern.search(text) or pattern.search(cleaned)
        if match is None:
            continue
        findings.append(
            InjectionFinding(rule=rule, severity=severity, excerpt=match.group(0).strip()[:EXCERPT_CHARS])
        )
    return findings



def _record_findings(findings: tuple[InjectionFinding, ...], *, scope: str) -> None:
    """把命中写入日志与指标（旁路：自身异常一律吞掉）。

    Args:
        findings: 命中列表。
        scope: 触发场景（``api`` / ``cli`` / ``qa`` / ``enrich``）。
    """
    if not findings:
        return
    try:
        for finding in findings:
            METRICS.inc(M_SECURITY_BLOCKS, {"rule": finding.rule, "severity": finding.severity})
        log_event(
            logger,
            "security.injection_blocked",
            level=logging.WARNING,
            message=f"[安全] 拦截提示词注入：{', '.join(item.rule for item in findings)}",
            scope=scope,
            rules=[item.rule for item in findings],
            severities=sorted({item.severity for item in findings}),
            excerpt=findings[0].excerpt,
        )
    except Exception as exc:  # noqa: BLE001 - 安全留痕是旁路，绝不阻断主流程
        logger.warning(f"安全事件留痕失败（已忽略）：{type(exc).__name__}: {exc}")


def guard_input(
    text: str,
    *,
    max_chars: int = MAX_QUERY_CHARS,
    block_on_medium: bool = True,
    scope: str = "unknown",
) -> GuardVerdict:
    """严格守卫用户输入：清洗 + 注入检测（命中即 ``allowed=False`` 并留痕）。

    Args:
        text: 用户输入（问题 / 查询）。
        max_chars: 长度上限（默认 :data:`MAX_QUERY_CHARS`）。
        block_on_medium: ``True`` 时 ``medium`` 级命中同样拦截。
        scope: 触发场景（写入日志 ``scope`` 字段）。

    Returns:
        :class:`GuardVerdict`（``text`` 为清洗后文本，可直接使用）。
    """
    normalized, truncated = normalize_text(text, max_chars=max_chars)
    cleaned = strip_chat_markup(normalized)
    raw_findings = detect_injection(text)
    for extra in detect_injection(cleaned):
        if extra not in raw_findings:
            raw_findings.append(extra)
    findings = tuple(raw_findings)
    blocking: frozenset[str] = frozenset({"high", "medium"}) if block_on_medium else frozenset({"high"})
    blocked = any(finding.severity in blocking for finding in findings)
    allowed = bool(cleaned.strip()) and not blocked
    verdict = GuardVerdict(
        allowed=allowed,
        text=cleaned,
        findings=findings,
        original_chars=len(text or ""),
        truncated=truncated,
    )
    if not allowed:
        _record_findings(findings, scope=scope)
    return verdict


def assert_safe_query(text: str, *, max_chars: int = MAX_QUERY_CHARS, scope: str = "unknown") -> str:
    """严格守卫并返回可用文本；命中即抛 :class:`PromptInjectionError`。

    Args:
        text: 用户输入。
        max_chars: 长度上限。
        scope: 触发场景（日志用）。

    Returns:
        清洗后的安全文本（已截断到 ``max_chars``）。

    Raises:
        PromptInjectionError: 命中注入规则或清洗后为空。
    """
    verdict = guard_input(text, max_chars=max_chars, scope=scope)
    if not verdict.allowed:
        raise PromptInjectionError(verdict)
    return verdict.text


def sanitize_for_llm(text: str, *, max_chars: int = MAX_PROMPT_CHARS) -> str:
    """软清洗：把外部文本拼进提示词前调用（不判定、不抛错）。

    Args:
        text: 外部文本（CVE 描述 / 论文摘要 / 检索片段 / 用户问题）。
        max_chars: 长度上限（默认 :data:`MAX_PROMPT_CHARS`）。

    Returns:
        清洗后的文本（已剥离控制字符、零宽字符与聊天模板标记；超长截断）。
    """
    normalized, _ = normalize_text(text, max_chars=max_chars)
    return strip_chat_markup(normalized)


def validate_llm_output(payload: Any, schema: type[TModel], *, context: str = "") -> TModel:
    """LLM 输出二次校验（Day18 任务 2）：强制 Pydantic 结构，拒绝自由文本。

    Args:
        payload: LLM 原始输出（``BaseModel`` / ``dict`` / JSON 字符串）。
        schema: 目标 Pydantic 模型类（均开启 ``extra="forbid"``）。
        context: 出错时的上下文标识（如 ``remediation``），仅用于异常信息。

    Returns:
        校验通过的模型实例。

    Raises:
        OutputValidationError: 输出不是合法 JSON、类型不符或含未声明字段。
    """
    label = f"[{context}] " if context else ""
    if isinstance(payload, schema):
        candidate: Any = payload.model_dump()
    elif isinstance(payload, str):
        try:
            candidate = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise OutputValidationError(f"{label}LLM 输出不是合法 JSON：{exc.msg}") from exc
    else:
        candidate = payload
    try:
        return schema.model_validate(candidate)
    except ValidationError as exc:
        raise OutputValidationError(
            f"{label}LLM 输出未通过 {schema.__name__} 校验：{exc.error_count()} 处错误"
        ) from exc





"""CVE 字段抽取与 ID 规范化（PROJECT_PLAN.md §2 normalize 层）。

**纯函数层**：无 IO、无全局状态、禁止 LLM（§0 约束 1）。输入 ``RawItem.raw_text``
或 ``RawItem.payload``，输出与源无关的 :class:`CveFields`。

已支持源形态：
    - NVD API 2.0（``cve`` 包装）
    - OSV.dev（``id`` / ``aliases`` / ``details``）
    - GitHub Advisory GraphQL（``ghsaId`` / ``summary`` / ``identifiers``）
    - CISA KEV（``cveID`` / ``shortDescription`` / ``dateAdded``）
    - FIRST EPSS（``cve`` / ``epss`` / ``percentile`` / ``date``）
    - RSS / 博客源（无 CVE 编号时回退 ``<FEED>:<guid>``）

Note:
    主键列 ``unified_vuln.vuln_id`` 为 ``String(32)``；非 CVE 回退键（如博客 guid 的完整 URL）
    可能超长，由 :func:`normalize_vuln_key` 折叠为确定性短键（Day18 修复：整源写入失败）。
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from aisec_intel.normalize.datetime_utils import parse_datetime

MAX_VULN_ID_CHARS: int = 32
"""``unified_vuln.vuln_id`` 的数据库列宽（``String(32)``）。"""

VULN_ID_SLUG_PATTERN: re.Pattern[str] = re.compile(r"[^0-9A-Za-z_.\-]+")
"""主键中允许保留的字符（其余替换为 ``-``）。"""

NON_CVE_PREFIX_FALLBACK: str = "INTEL"
"""无 CVE 编号且无法从源内 ID 推断前缀时使用的兜底前缀。"""



CVE_ID_PATTERN: re.Pattern[str] = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
"""单个 CVE 编号（``CVE-YYYY-NNNN+``）。"""

CVE_IN_TEXT_PATTERN: re.Pattern[str] = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
"""正文中的 CVE 编号。"""

ALIAS_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bGHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}\b", re.I),
    re.compile(r"\bPYSEC-\d{4}-\d+\b", re.IGNORECASE),
    re.compile(r"\bOSV-\d{4}-\d+\b", re.IGNORECASE),
    re.compile(r"\bCNVD-\d{4}-\d+\b", re.IGNORECASE),
    re.compile(r"\bCWE-\d+\b", re.IGNORECASE),
)
"""跨源别名编号（GHSA / PYSEC / OSV / CNVD / CWE）。"""

_TAG_PATTERN: re.Pattern[str] = re.compile(r"<[^>]+>")
_WS_PATTERN: re.Pattern[str] = re.compile(r"\s+")


def normalize_vuln_key(candidate: str, *, source: str = "") -> str:
    """把源内 ID 折叠为**确定性**主键（纯函数，Day18 修复）。

    规则：
        1. 规范 CVE 编号（``CVE-YYYY-NNNN``）→ 大写原样返回；
        2. 形如 ``GHSA-x`` / ``PYSEC-x`` / ``OSV-x`` 的标识符（无 URL 分隔符且长度合规）
           → **原样保留大小写**（与既有库内数据一致，避免同一公告产生第二行）；
        3. 博客 guid / URL / 超长串 → ``<源前缀大写>-<slug>-<sha256[:10]>``，
           既满足 ``varchar(32)``，又保证「不同文章不会折叠成同一主键」。

    Args:
        candidate: 源内 ID（CVE / GHSA / PYSEC / 博客 guid 等）。
        source: 源标识（用于生成可读前缀；为空时取 :data:`NON_CVE_PREFIX_FALLBACK`）。

    Returns:
        长度不超过 :data:`MAX_VULN_ID_CHARS` 的主键。

    Examples:
        >>> normalize_vuln_key("cve-2024-3400")
        'CVE-2024-3400'
        >>> key = normalize_vuln_key("GITHUB_SECURITY_BLOG:HTTPS://X/?P=1", source="rss_blog")
        >>> key.startswith("RSS_BLOG-") and len(key) <= 32
        True
    """
    text = (candidate or "").strip()
    if not text:
        return ""
    if CVE_ID_PATTERN.match(text):
        return text.upper()

    # ① 形如 GHSA-xxxx / PYSEC-xxxx / OSV-xxxx 的「标识符」：长度合规时原样保留大小写
    is_identifier = not any(marker in text for marker in ("://", "?", "/", ":", " "))
    if is_identifier and len(text) <= MAX_VULN_ID_CHARS:
        return text

    # ② 其余（博客 guid / URL / 超长串）：折叠为 ``<前缀>-<slug>-<sha256[:10]>``（跨源唯一、可追溯）
    prefix = VULN_ID_SLUG_PATTERN.sub("_", source.strip().upper()).strip("_") or NON_CVE_PREFIX_FALLBACK
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:10].upper()
    slug = urlparse(text).path or text
    slug = VULN_ID_SLUG_PATTERN.sub("-", slug).strip("-")
    slug = re.sub(r"-{2,}", "-", slug)
    head_budget = max(1, MAX_VULN_ID_CHARS - len(prefix) - len(digest) - 2)
    head = slug[:head_budget].strip("-")
    return f"{prefix}-{head}-{digest}"[:MAX_VULN_ID_CHARS]



@dataclass(frozen=True, slots=True)
class CveFields:
    """与源无关的漏洞字段集合（L2 内部 DTO）。

    Attributes:
        vuln_id: 规范化主键（CVE 优先，否则使用源内 ID，如 GHSA）。
        aliases: 跨源别名（含 CVE / GHSA / CWE 等编号）。
        title: 标题（摘要）。
        description: 清洗后的描述文本。
        published_at: 发布时间（UTC）。
        modified_at: 最近修改时间（UTC）。
        cwe_ids: CWE 编号列表。
        reference_urls: 参考链接列表。
        epss_score: EPSS 概率（``[0, 1]``）。
        epss_percentile: EPSS 百分位（``[0, 1]``）。
        kev: 是否属于 CISA KEV（已知被利用）。
        lang: 描述语言。
    """

    vuln_id: str
    aliases: tuple[str, ...] = ()
    title: str | None = None
    description: str = ""
    published_at: datetime | None = None
    modified_at: datetime | None = None
    cwe_ids: tuple[str, ...] = ()
    reference_urls: tuple[str, ...] = ()
    epss_score: float | None = None
    epss_percentile: float | None = None
    kev: bool = False
    lang: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


def normalize_cve_id(value: str | None) -> str | None:
    """规范化 CVE 编号（去空格 + 大写），非法时返回 ``None``。

    Args:
        value: 原始编号，如 ``" cve-2024-3400 "``。

    Returns:
        形如 ``CVE-2024-3400`` 的编号；非法输入返回 ``None``。
    """
    if not value:
        return None
    candidate = value.strip().upper()
    return candidate if CVE_ID_PATTERN.match(candidate) else None


def is_cve_id(value: str | None) -> bool:
    """判断字符串是否为合法 CVE 编号。

    Args:
        value: 待判断字符串。

    Returns:
        合法返回 ``True``。
    """
    return normalize_cve_id(value) is not None


def extract_cve_ids(*texts: str | None) -> list[str]:
    """从任意文本中抽取并去重 CVE 编号（保持出现顺序）。

    Args:
        *texts: 待搜索文本（``None`` 会被忽略）。

    Returns:
        规范化后的 CVE 编号列表。
    """
    found: list[str] = []
    seen: set[str] = set()
    for text in texts:
        if not text:
            continue
        for match in CVE_IN_TEXT_PATTERN.findall(text):
            cve_id = match.upper()
            if cve_id not in seen:
                seen.add(cve_id)
                found.append(cve_id)
    return found


def clean_text(text: str | None) -> str:
    """确定性文本清洗：去 HTML 标签、压缩空白、去除首尾空白。

    Note:
        P4 会把该逻辑迁至 ``normalize/text.py``（含语言判定与摘要截取）。

    Args:
        text: 原始文本。

    Returns:
        清洗后的单段文本（``None`` → 空串）。
    """
    if not text:
        return ""
    without_tags = _TAG_PATTERN.sub(" ", text)
    return _WS_PATTERN.sub(" ", without_tags).strip()


def find_aliases(*texts: str | None) -> list[str]:
    """从文本中抽取独立别名编号（GHSA / PYSEC / OSV / CNVD，不含 CVE）。

    Args:
        *texts: 待搜索文本。

    Returns:
        去重后的别名列表（大写，保持顺序）。
    """
    found: list[str] = []
    seen: set[str] = set()
    for text in texts:
        if not text:
            continue
        for pattern in ALIAS_PATTERNS:
            for match in pattern.findall(text):
                alias = match.upper()
                if alias not in seen:
                    seen.add(alias)
                    found.append(alias)
    return found


def parse_payload(raw_text: str) -> dict[str, Any] | None:
    """把 ``raw_text`` 解析为 JSON 对象（失败返回 ``None``）。

    Args:
        raw_text: 保真原文。

    Returns:
        JSON 对象或 ``None``。
    """
    try:
        parsed = json.loads(raw_text)
    except (ValueError, TypeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _first_text(*candidates: Any) -> str | None:
    """返回第一个非空字符串候选（用于兼容不同源的字段命名）。"""
    for candidate in candidates:
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
    return None


def _as_float(value: Any) -> float | None:
    """安全地把值转成 ``float``（失败返回 ``None``）。"""
    try:
        return None if value is None or value == "" else float(value)
    except (TypeError, ValueError):
        return None


def _nvd_fields(payload: dict[str, Any]) -> dict[str, Any]:
    """解析 NVD API 2.0 记录。"""
    cve = payload.get("cve", payload)
    descriptions = cve.get("descriptions") or []
    english = _first_text(*[item.get("value") for item in descriptions if item.get("lang") == "en"])
    cwe_ids = [
        str(node.get("value"))
        for weakness in (cve.get("weaknesses") or [])
        for node in (weakness.get("description") or [])
        if node.get("value")
    ]
    return {
        "vuln_id": normalize_cve_id(cve.get("id")) or str(cve.get("id") or ""),
        "title": None,
        "description": english or _first_text(*[item.get("value") for item in descriptions]) or "",
        "published_at": cve.get("published"),
        "modified_at": cve.get("lastModified"),
        "cwe_ids": cwe_ids,
        "reference_urls": [ref.get("url") for ref in (cve.get("references") or []) if ref.get("url")],
    }


def _osv_fields(payload: dict[str, Any]) -> dict[str, Any]:
    """解析 OSV.dev 记录。"""
    return {
        "vuln_id": str(payload.get("id") or ""),
        "title": _first_text(payload.get("summary")),
        "description": _first_text(payload.get("details"), payload.get("summary")) or "",
        "published_at": payload.get("published"),
        "modified_at": payload.get("modified"),
        "reference_urls": [ref.get("url") for ref in (payload.get("references") or []) if ref.get("url")],
        "aliases": list(payload.get("aliases") or []),
    }


def _ghsa_fields(payload: dict[str, Any]) -> dict[str, Any]:
    """解析 GitHub Advisory GraphQL 节点。"""
    identifiers = [item.get("value") for item in (payload.get("identifiers") or []) if item.get("value")]
    cwes = [node.get("cweId") for node in ((payload.get("cwes") or {}).get("nodes") or []) if node.get("cweId")]
    return {
        "vuln_id": _first_text(payload.get("ghsaId"), *identifiers) or "",
        "title": _first_text(payload.get("summary")),
        "description": _first_text(payload.get("description"), payload.get("summary")) or "",
        "published_at": payload.get("publishedAt"),
        "modified_at": payload.get("updatedAt"),
        "cwe_ids": cwes,
        "reference_urls": [ref.get("url") for ref in (payload.get("references") or []) if ref.get("url")],
        "aliases": identifiers,
    }


def _kev_fields(payload: dict[str, Any]) -> dict[str, Any]:
    """解析 CISA KEV 条目。"""
    return {
        "vuln_id": normalize_cve_id(payload.get("cveID")) or str(payload.get("cveID") or ""),
        "title": _first_text(payload.get("vulnerabilityName")),
        "description": _first_text(payload.get("shortDescription")) or "",
        "published_at": payload.get("dateAdded"),
        "modified_at": payload.get("dateAdded"),
        "cwe_ids": list(payload.get("cwes") or []),
        "reference_urls": [payload["notes"]] if isinstance(payload.get("notes"), str) else [],
        "kev": True,
    }


def _epss_fields(payload: dict[str, Any]) -> dict[str, Any]:
    """解析 FIRST EPSS 行。

    Note:
        EPSS 行的 ``date`` 是**模型评分日期**（「该分数于何日计算」），不是漏洞披露时间，
        因此写入 ``modified_at`` 而非 ``published_at``（Day26 修订，见
        :mod:`aisec_intel.normalize.pipeline` 时间口径）。
    """
    return {
        "vuln_id": normalize_cve_id(payload.get("cve")) or str(payload.get("cve") or ""),
        "description": "",
        "modified_at": payload.get("date"),
        "epss_score": payload.get("epss"),
        "epss_percentile": payload.get("percentile"),
    }


_SOURCE_PARSERS: dict[str, Any] = {
    "nvd": _nvd_fields,
    "osv": _osv_fields,
    "ghsa": _ghsa_fields,
    "kev": _kev_fields,
    "epss": _epss_fields,
}
"""源标识 → 解析函数。"""


def _detect_source(payload: dict[str, Any]) -> str | None:
    """按关键字段推断源（未显式给出 ``source`` 时使用）。"""
    if "ghsaId" in payload:
        return "ghsa"
    if "cveID" in payload or "vulnerabilityName" in payload:
        return "kev"
    if "epss" in payload and "cve" in payload:
        return "epss"
    if "aliases" in payload or "details" in payload:
        return "osv"
    if "cve" in payload or "lastModified" in payload:
        return "nvd"
    return None


def extract_cve_fields(
    raw_text: str,
    *,
    source: str | None = None,
    fallback_id: str | None = None,
    fallback_url: str | None = None,
) -> CveFields:
    """从保真原文中抽取与源无关的漏洞字段。

    Args:
        raw_text: ``RawItem.raw_text``（多为条目级 JSON）。
        source: 源标识；``None`` 时按字段特征自动推断。
        fallback_id: 无法从原文确定主键时的兜底（通常是 ``RawItem.source_id``）。
        fallback_url: 无参考链接时补充的兜底 URL（通常是 ``RawItem.url``）。

    Returns:
        :class:`CveFields`。

    Raises:
        ValueError: 既无法从原文识别主键，也未提供 ``fallback_id``。
    """
    payload = parse_payload(raw_text) or {}
    resolved_source = (source or _detect_source(payload) or "").lower()
    parser = _SOURCE_PARSERS.get(resolved_source)
    parsed: dict[str, Any] = parser(payload) if parser and payload else {}
    if not parsed:
        parsed = {"vuln_id": "", "description": clean_text(raw_text)}

    vuln_id = _first_text(parsed.get("vuln_id"), normalize_cve_id(fallback_id), fallback_id)
    if not vuln_id:
        raise ValueError(f"无法确定 vuln_id（source={source!r}，fallback_id={fallback_id!r}）")
    vuln_id = normalize_vuln_key(vuln_id, source=resolved_source)

    description = clean_text(parsed.get("description"))
    title = clean_text(parsed.get("title")) or None

    aliases: list[str] = []
    candidates: list[Any] = [
        *extract_cve_ids(vuln_id, description, title),
        *(parsed.get("aliases") or []),
        *find_aliases(vuln_id, description, title, raw_text),
    ]
    if fallback_id:
        candidates.append(fallback_id)
    for alias in candidates:
        candidate = str(alias).strip().upper()
        if candidate and candidate != vuln_id.upper() and candidate not in aliases:
            aliases.append(candidate)

    cwe_ids: list[str] = []
    for cwe in parsed.get("cwe_ids") or []:
        cleaned = str(cwe).strip().upper()
        if cleaned.startswith("CWE-") and cleaned not in cwe_ids:
            cwe_ids.append(cleaned)

    urls = [str(url) for url in (parsed.get("reference_urls") or []) if url]
    if fallback_url and fallback_url not in urls:
        urls.append(fallback_url)

    return CveFields(
        vuln_id=vuln_id,
        aliases=tuple(aliases),
        title=title,
        description=description,
        published_at=parse_datetime(parsed.get("published_at")),
        modified_at=parse_datetime(parsed.get("modified_at")),
        cwe_ids=tuple(cwe_ids),
        reference_urls=tuple(dict.fromkeys(urls)),
        epss_score=_as_float(parsed.get("epss_score")),
        epss_percentile=_as_float(parsed.get("epss_percentile")),
        kev=bool(parsed.get("kev", False)),
        lang="en" if description and description.isascii() else None,
    )

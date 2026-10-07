"""归一化流水线（PROJECT_PLAN.md §2 / §5.3）：``RawItem`` → ``UnifiedVuln``。

**纯函数**：给定相同输入必得相同输出（``normalized_at`` 可显式注入以保持可复现）；
无 IO、无全局状态、禁止 LLM（§0 约束 1 / 5）。

职责边界（§10.2 不变式 4）：本层只做**事实抽取与规范化**，不做任何推断补全
（如“可能受影响的资产”“可能的攻击链”属于 L3 富化层）。

时间口径（Day26 修订，**禁止把入库时间当成发布时间**）：

- ``published_at`` = **源侧真实发布时间**：NVD ``cve.published``、OSV ``published``、
  GHSA ``publishedAt``、KEV ``dateAdded``、RSS feed ``published``、其他源按通用键匹配
  （见 :data:`PUBLISHED_AT_FALLBACK_PATHS`）；源未提供时为 ``None``（前端展示 ``—``），
  **绝不以 ``normalized_at`` / ``fetched_at`` 兜底**（否则「入库时间」会冒充「发布时间」）。
- ``modified_at`` = 源侧最近修改时间；源未给时回退源侧日期（EPSS 行的模型日期落在该字段）。
- ``normalized_at`` = 归一化 / 入库时间，独立字段，仅供「入库时间」类展示与排序口径使用。
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from datetime import date, datetime
from typing import Any

from aisec_intel.models.base import utc_now
from aisec_intel.models.raw_item import RawItem
from aisec_intel.models.unified_vuln import CpeMatch, Reference, UnifiedVuln
from aisec_intel.normalize.cve import CveFields, extract_cve_fields, parse_payload
from aisec_intel.normalize.cvss import extract_cvss_vectors, severity_from_vectors
from aisec_intel.normalize.datetime_utils import parse_datetime

CPE23_PATTERN: re.Pattern[str] = re.compile(
    r"^cpe:2\.3:(?P<part>[aho]):(?P<vendor>[^:]*):(?P<product>[^:]*):(?P<version>[^:]*)"
)
"""CPE 2.3 URI 绑定格式的前四段（part / vendor / product / version）。"""

KEV_SOURCE: str = "kev"
"""CISA KEV 源标识（该源的数据天然代表“已知被利用”）。"""

ECOSYSTEM_ALIASES: dict[str, str] = {
    "PIP": "PyPI",
    "PYPI": "PyPI",
    "NPM": "npm",
    "RUBYGEMS": "RubyGems",
    "GO": "Go",
    "MAVEN": "Maven",
    "NUGET": "NuGet",
    "COMPOSER": "Packagist",
    "CARGO": "crates.io",
    "RUST": "crates.io",
}
"""生态名规范化映射：GHSA（``PIP``/``NPM``）→ OSV（``PyPI``/``npm``）命名。

跨源对齐是归一化的职责（非推断）：同一包在 NPM 与 GitHub 两套标注下应落到同一实体。
"""


def canonical_ecosystem(name: str) -> str:
    """把生态名规范化为统一写法（未知值原样返回）。

    Args:
        name: 原始生态名，如 ``PIP`` / ``PyPI``。

    Returns:
        规范化后的生态名，如 ``PyPI``。
    """
    cleaned = name.strip()
    return ECOSYSTEM_ALIASES.get(cleaned.upper(), cleaned)

_PATCH_HINTS: tuple[str, ...] = ("patch", "commit", "advisory", "release")
_EXPLOIT_HINTS: tuple[str, ...] = ("exploit", "poc", "metasploit")

UNBOUNDED_RANGE: str = "*"
"""版本区间两端皆无界时的占位（表示「产品级受影响，源侧未给区间」）。"""


def render_version_range(match: CpeMatch) -> str:
    """把一条 CPE 区间渲染为可读的版本区间表达式（纯函数，语义与字段一一对应）。

    规则：
        - ``version_start_incl`` 与 ``version_end_incl`` 相同且非空 → 精确版本 ``==1.2.3``；
        - 常规区间 → ``>=10.2.0, <10.2.9``（终点按包含性选择 ``<=`` / ``<``）；
        - 仅一端有界 → 只输出该端；
        - 两端皆空 → :data:`UNBOUNDED_RANGE`（``*``）。

    Args:
        match: 单条 CPE 匹配。

    Returns:
        版本区间表达式，如 ``">=10.2.0, <10.2.9-h1"``。
    """
    if (
        match.version_start_incl
        and match.version_start_incl == match.version_end_incl
        and not match.version_end_excl
    ):
        return f"=={match.version_start_incl}"

    parts: list[str] = []
    if match.version_start_incl:
        parts.append(f">={match.version_start_incl}")
    elif match.version_start_excl:
        parts.append(f">{match.version_start_excl}")
    if match.version_end_excl:
        parts.append(f"<{match.version_end_excl}")
    elif match.version_end_incl:
        parts.append(f"<={match.version_end_incl}")
    return ", ".join(parts) if parts else UNBOUNDED_RANGE


def affected_versions_from_cpes(matches: Sequence[CpeMatch]) -> list[str]:
    """把 ``cpe_matches`` 渲染为受影响版本清单（供应商:产品 + 区间）。

    AssetMapper / Remediation Agent 需要「人类可读的受影响版本」，此函数是
    **确定性派生**（不引入任何推断，§10.2 不变式 4）：输入相同必得相同输出。

    Args:
        matches: CPE 匹配列表。

    Returns:
        去重保序的字符串列表，如 ``["paloaltonetworks:pan-os >=10.2.0, <10.2.9-h1"]``。
    """
    rendered: list[str] = []
    seen: set[str] = set()
    for match in matches:
        label = f"{match.vendor}:{match.product} {render_version_range(match)}"
        if label not in seen:
            seen.add(label)
            rendered.append(label)
    return rendered


def parse_cpe23(criteria: str, *, version_end_excl: str | None = None) -> CpeMatch | None:
    """把 CPE 2.3 字符串解析为 :class:`CpeMatch`。

    Note:
        契约中的 ``CpeMatch`` 只表达版本区间；当 CPE 携带**精确版本**时，
        按 ``[version, version]`` 区间表达（P4 的 ``normalize/cpe.py`` 会补齐更严谨的区间语义）。

    Args:
        criteria: 形如 ``cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*``。
        version_end_excl: 外部提供的“首个修复版本”（NVD 的 ``versionEndExcluding``）。

    Returns:
        ``CpeMatch``；无法解析时返回 ``None``。
    """
    match = CPE23_PATTERN.match(criteria.strip())
    if not match:
        return None
    vendor = match.group("vendor")
    product = match.group("product")
    version = match.group("version")
    if vendor in {"", "*"} or product in {"", "*"}:
        return None
    if version in {"", "*", "-"}:
        return CpeMatch(vendor=vendor, product=product, version_end_excl=version_end_excl, vulnerable=True)
    return CpeMatch(
        vendor=vendor,
        product=product,
        version_start_incl=version,
        version_end_incl=version,
        vulnerable=True,
    )


def extract_cpe_matches(payload: dict[str, Any]) -> list[CpeMatch]:
    """从 NVD ``configurations`` 中抽取 CPE 匹配条目（去重、保序）。

    Args:
        payload: 源侧 JSON 对象。

    Returns:
        ``CpeMatch`` 列表。
    """
    matches: list[CpeMatch] = []
    seen: set[tuple[str, str, str | None]] = set()
    for node in _iter_nvd_nodes(payload):
        for entry in node.get("cpeMatch") or []:
            if not isinstance(entry, dict) or not entry.get("vulnerable", True):
                continue
            parsed = parse_cpe23(
                str(entry.get("criteria") or ""),
                version_end_excl=entry.get("versionEndExcluding"),
            )
            if parsed is None:
                continue
            key = (parsed.vendor, parsed.product, parsed.version_end_excl)
            if key not in seen:
                seen.add(key)
                matches.append(parsed)
    return matches


def _iter_nvd_nodes(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """递归收集 NVD ``configurations[].nodes[]``（含嵌套 ``nodes``）。

    Note:
        ``payload["cve"]`` 在 NVD 中是对象，但在 EPSS 等源中是**字符串**（CVE 编号），
        因此必须先判类型再取 ``configurations``。
    """
    collected: list[dict[str, Any]] = []
    cve = payload.get("cve")
    root = cve if isinstance(cve, dict) else payload
    stack: list[Any] = list(root.get("configurations") or [])
    while stack:
        item = stack.pop()
        if not isinstance(item, dict):
            continue
        if isinstance(item.get("nodes"), list):
            stack.extend(item["nodes"])
        if "cpeMatch" in item:
            collected.append(item)
    return collected


def extract_ecosystem_packages(payload: dict[str, Any]) -> list[str]:
    """从 OSV/GHSA 载荷中抽取 ``生态:包名`` 标识（去重、保序）。

    Args:
        payload: 源侧 JSON 对象。

    Returns:
        形如 ``PyPI:vllm`` 的标识列表。
    """
    packages: list[str] = []
    seen: set[str] = set()

    for affected in payload.get("affected") or []:
        package = affected.get("package") if isinstance(affected, dict) else None
        if isinstance(package, dict):
            ecosystem = canonical_ecosystem(str(package.get("ecosystem") or ""))
            name = str(package.get("name") or "").strip()
            if ecosystem and name:
                key = f"{ecosystem}:{name}"
                if key not in seen:
                    seen.add(key)
                    packages.append(key)

    vulnerabilities = payload.get("vulnerabilities")
    nodes = vulnerabilities.get("nodes") if isinstance(vulnerabilities, dict) else None
    for node in nodes or []:
        package = node.get("package") if isinstance(node, dict) else None
        if isinstance(package, dict):
            ecosystem = canonical_ecosystem(str(package.get("ecosystem") or ""))
            name = str(package.get("name") or "").strip()
            if ecosystem and name:
                key = f"{ecosystem}:{name}"
                if key not in seen:
                    seen.add(key)
                    packages.append(key)
    return packages


def build_references(fields: CveFields, *, source: str) -> list[Reference]:
    """把参考链接转换为契约模型（标签为确定性启发式判定）。

    Args:
        fields: L2 抽取出的字段集合。
        source: 源标识（写入 ``Reference.source``）。

    Returns:
        ``Reference`` 列表。
    """
    references: list[Reference] = []
    for url in fields.reference_urls:
        lowered = url.lower()
        tags: list[str] = []
        if any(hint in lowered for hint in _PATCH_HINTS):
            tags.append("patch")
        if any(hint in lowered for hint in _EXPLOIT_HINTS):
            tags.append("exploit")
        references.append(Reference(url=url, source=source, tags=tags))
    return references


PUBLISHED_AT_SOURCE_PATHS: dict[str, tuple[str, ...]] = {
    "nvd": ("cve.published", "published"),
    "osv": ("published",),
    "ghsa": ("publishedAt",),
    "vendor_github": ("advisory.publishedAt", "publishedAt"),
    "kev": ("dateAdded",),
    "rss_blog": ("published", "pubDate", "updated"),
}
"""源标识 → 发布时间字段路径（按优先级排列；``a.b`` 表示嵌套一层，如 NVD 的 ``cve.published``）。"""

PUBLISHED_AT_FALLBACK_PATHS: tuple[str, ...] = (
    "published",
    "publishedAt",
    "published_at",
    "publication_date",
    "datePublished",
    "pubDate",
    "dateAdded",
    "advisory.publishedAt",
)
"""源特有路径未命中 / 未知源时依次尝试的通用发布时间字段（按优先级排列）。"""

NO_PUBLISHED_AT_SOURCES: frozenset[str] = frozenset({"epss"})
"""不提供**漏洞披露时间**的源。

EPSS 行只有模型评分日期（``date``，表示「该分数于何日计算」），把它当作发布时间会让
「老漏洞」显示成近期披露，因此该源恒返回 ``None``；日期信息仍由 ``modified_at`` 承载。
"""


def lookup_field(payload: dict[str, Any], path: str) -> Any:
    """按 ``a.b`` 路径逐层取值（纯函数，任一层缺失即返回 ``None``）。

    Args:
        payload: 已解析的 JSON 对象。
        path: 点分路径，如 ``cve.published``。

    Returns:
        命中的原始值；未命中返回 ``None``。
    """
    current: Any = payload
    for key in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(key)
        if current is None:
            return None
    return current


def _as_datetime(value: Any) -> datetime | None:
    """把 JSON 值安全地转成 UTC ``datetime``（非时间类型 / 非法值返回 ``None``）。

    Args:
        value: JSON 中的任意值。

    Returns:
        UTC ``datetime``；无法解析时返回 ``None``。
    """
    if isinstance(value, bool) or not isinstance(value, datetime | date | str | int | float):
        return None
    return parse_datetime(value)


def extract_published_at(raw: RawItem, *, source: str | None = None) -> datetime | None:
    """抽取「源侧真实发布时间」（纯函数，**绝不以入库时间兜底**）。

    取值优先级：

    1. 源特有字段（:data:`PUBLISHED_AT_SOURCE_PATHS`，如 NVD ``cve.published`` /
       KEV ``dateAdded`` / GHSA ``publishedAt``）；
    2. 通用字段（:data:`PUBLISHED_AT_FALLBACK_PATHS`）；
    3. 采集件上的 ``raw.published_at`` —— 由连接器从源字段映射而来，仍是**源侧**时间；
    4. 全部未命中 → ``None``（**不返回** ``raw.fetched_at`` / ``UnifiedVuln.normalized_at``）。

    Note:
        ``epss`` 属于 :data:`NO_PUBLISHED_AT_SOURCES`，其 ``date`` 是模型评分日期而非披露
        时间，故恒返回 ``None``。

    Args:
        raw: L1 采集件（``raw_text`` 为条目级 JSON）。
        source: 源标识；``None`` 时取 ``raw.source``。

    Returns:
        源侧发布时间（UTC）；源未提供时为 ``None``。

    Examples:
        >>> import json
        >>> from datetime import UTC, datetime
        >>> from aisec_intel.models.raw_item import RawItem
        >>> raw = RawItem(
        ...     trace_id="t", source="nvd", source_id="CVE-2024-3400", url="u",
        ...     raw_text=json.dumps({"cve": {"id": "CVE-2024-3400", "published": "2024-04-12T00:00:00.000Z"}}),
        ...     fetched_at=datetime(2026, 1, 1, tzinfo=UTC), sha256="a" * 64,
        ... )
        >>> extract_published_at(raw).isoformat()
        '2024-04-12T00:00:00+00:00'
    """
    resolved = (source or raw.source or "").strip().lower()
    if resolved in NO_PUBLISHED_AT_SOURCES:
        return None
    payload = parse_payload(raw.raw_text) or {}
    for path in (*PUBLISHED_AT_SOURCE_PATHS.get(resolved, ()), *PUBLISHED_AT_FALLBACK_PATHS):
        published = _as_datetime(lookup_field(payload, path))
        if published is not None:
            return published
    return parse_datetime(raw.published_at)


def build_unified_vuln(raw: RawItem, *, normalized_at: datetime | None = None) -> UnifiedVuln:
    """把采集件归一化为统一漏洞实体（纯函数）。

    时间字段口径见模块 docstring：``published_at`` 只取**源侧发布时间**
    （:func:`extract_published_at`），源未提供时为 ``None``，**不用** ``normalized_at`` 兜底；
    ``normalized_at`` 单独记录归一化 / 入库时间。

    Args:
        raw: L1 采集输出。
        normalized_at: 归一化时间（UTC）；显式注入以获得可复现输出（默认取当前时间）。

    Returns:
        ``UnifiedVuln``（事实层，无推断结论）。

    Raises:
        ValueError: 无法从 ``raw`` 中确定 ``vuln_id``（既非规范 ID 也无 ``source_id``）。
    """
    payload = parse_payload(raw.raw_text) or {}
    fields = extract_cve_fields(
        raw.raw_text,
        source=raw.source,
        fallback_id=raw.source_id,
        fallback_url=raw.url,
    )
    # 发布时间：只信源侧字段（NVD cve.published / KEV dateAdded / GHSA publishedAt …）；
    # 源未给出时保持 None，绝不回退 normalized_at（Day26 修订，见模块 docstring 时间口径）。
    published_at = extract_published_at(raw, source=raw.source)
    description = fields.description or fields.title or raw.source_id
    cvss = extract_cvss_vectors(payload)
    cpe_matches = extract_cpe_matches(payload)
    return UnifiedVuln(
        vuln_id=fields.vuln_id,
        aliases=list(fields.aliases),
        trace_ids=[raw.trace_id],
        title=fields.title or raw.title,
        description=description,
        lang=fields.lang or raw.lang,
        cvss=cvss,
        # 派生字段：确定性推导（最高严重度 / 受影响版本清单），不做任何推断补全
        severity=severity_from_vectors(cvss),
        cwe_ids=list(fields.cwe_ids),
        cpe_matches=cpe_matches,
        affected_versions=affected_versions_from_cpes(cpe_matches),
        ecosystem_packages=extract_ecosystem_packages(payload),
        references=build_references(fields, source=raw.source),
        kev=fields.kev or raw.source == KEV_SOURCE,
        epss_score=fields.epss_score,
        epss_percentile=fields.epss_percentile,
        published_at=published_at,
        # 修改时间：源侧 lastModified 优先；缺省回退源侧日期（EPSS 的模型日期走这里）
        modified_at=fields.modified_at or published_at or parse_datetime(raw.published_at),
        sources=[raw.source],
        normalized_at=normalized_at or utc_now(),
    )
    description = fields.description or fields.title or raw.source_id
    cvss = extract_cvss_vectors(payload)
    cpe_matches = extract_cpe_matches(payload)
    return UnifiedVuln(
        vuln_id=fields.vuln_id,
        aliases=list(fields.aliases),
        trace_ids=[raw.trace_id],
        title=fields.title or raw.title,
        description=description,
        lang=fields.lang or raw.lang,
        cvss=cvss,
        # 派生字段：确定性推导（最高严重度 / 受影响版本清单），不做任何推断补全
        severity=severity_from_vectors(cvss),
        cwe_ids=list(fields.cwe_ids),
        cpe_matches=cpe_matches,
        affected_versions=affected_versions_from_cpes(cpe_matches),
        ecosystem_packages=extract_ecosystem_packages(payload),
        references=build_references(fields, source=raw.source),
        kev=fields.kev or raw.source == KEV_SOURCE,
        epss_score=fields.epss_score,
        epss_percentile=fields.epss_percentile,
        published_at=published_at,
        modified_at=fields.modified_at or published_at,
        sources=[raw.source],
        normalized_at=normalized_at or utc_now(),
    )


def build_many(raw_items: list[RawItem], *, normalized_at: datetime | None = None) -> list[UnifiedVuln]:
    """批量归一化（逐条调用 :func:`build_unified_vuln`，失败的条目被跳过）。

    Args:
        raw_items: 采集件列表。
        normalized_at: 归一化时间（UTC）。

    Returns:
        成功归一化的 ``UnifiedVuln`` 列表（顺序与输入一致）。
    """
    results: list[UnifiedVuln] = []
    for raw in raw_items:
        try:
            results.append(build_unified_vuln(raw, normalized_at=normalized_at))
        except ValueError:
            continue
    return results

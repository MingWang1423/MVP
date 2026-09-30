"""归一化流水线（PROJECT_PLAN.md §2 / §5.3）：``RawItem`` → ``UnifiedVuln``。

**纯函数**：给定相同输入必得相同输出（``normalized_at`` 可显式注入以保持可复现）；
无 IO、无全局状态、禁止 LLM（§0 约束 1 / 5）。

职责边界（§10.2 不变式 4）：本层只做**事实抽取与规范化**，不做任何推断补全
（如“可能受影响的资产”“可能的攻击链”属于 L3 富化层）。
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from aisec_intel.models.base import utc_now
from aisec_intel.models.raw_item import RawItem
from aisec_intel.models.unified_vuln import CpeMatch, Reference, UnifiedVuln
from aisec_intel.normalize.cve import CveFields, extract_cve_fields, parse_payload
from aisec_intel.normalize.cvss import extract_cvss_vectors

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


def build_unified_vuln(raw: RawItem, *, normalized_at: datetime | None = None) -> UnifiedVuln:
    """把采集件归一化为统一漏洞实体（纯函数）。

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
    published_at = fields.published_at or raw.published_at
    description = fields.description or fields.title or raw.source_id
    return UnifiedVuln(
        vuln_id=fields.vuln_id,
        aliases=list(fields.aliases),
        trace_ids=[raw.trace_id],
        title=fields.title or raw.title,
        description=description,
        lang=fields.lang or raw.lang,
        cvss=extract_cvss_vectors(payload),
        cwe_ids=list(fields.cwe_ids),
        cpe_matches=extract_cpe_matches(payload),
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

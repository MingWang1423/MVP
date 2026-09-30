"""跨源去重与合并（PROJECT_PLAN.md §5.4 `normalize/dedupe.py`）。

**纯函数层**：无 IO、无全局状态、禁止 LLM（§0 约束 1）。

策略（两层）：
    1. **主键精确匹配**：以规范化 CVE 编号（含别名并集）为主键合并——NVD / OSV / GHSA / KEV / EPSS
       对同一 CVE 的记录必然落到同一组；
    2. **SimHash 近似匹配（辅助）**：对没有 CVE 主键（或主键不同的）条目，
       用「标题 + 描述」的 64 位 SimHash 做汉明距离聚类，距离 ≤ 阈值即视为同一漏洞。

合并规则（确定性，不引入推断）：
    - ``aliases`` / ``cwe_ids`` / ``ecosystem_packages`` / ``sources`` / ``trace_ids`` / ``references`` 取**并集**；
    - ``cvss`` 取并集后按 (version, vector) 去重、按版本升序；
    - ``description`` 取**最长**者（信息量最大）；``title`` 取首个非空；
    - ``published_at`` 取最早、``modified_at`` 取最晚；
    - ``kev`` / ``epss_score`` / ``epss_percentile`` 取「任一非空 / 任一为真」；
    - ``cpe_matches`` 取并集（按 vendor/product/区间去重）。
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Sequence
from urllib.parse import urlsplit, urlunsplit

from aisec_intel.models.unified_vuln import Reference, UnifiedVuln
from aisec_intel.normalize.cve import normalize_cve_id

DEFAULT_SIMHASH_BITS: int = 64
"""SimHash 位宽。"""

DEFAULT_HAMMING_THRESHOLD: int = 15
"""汉明距离阈值（64 位）。

定标依据（实测，见 ``tests/unit/test_normalize_dedupe.py``）：
    - 近重复文本（相差 1~2 个词）距离 **7~13**；
    - 不相关文本距离 **25~34**。
故取 15 作为分界（≈23% 位差异），并**仅用于无 CVE 主键的条目**（减少误合并风险）。
"""

_TOKEN_PATTERN: re.Pattern[str] = re.compile(r"[a-z0-9]+")
"""分词：仅保留小写字母与数字（跨源描述文本的基础归一）。"""

_CVE_ALIAS_PATTERN: re.Pattern[str] = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

TRACKING_QUERY_PREFIXES: tuple[str, ...] = ("utm_", "ref", "source", "fbclid", "gclid")
"""URL 中的跟踪参数（去重键计算时剔除）。"""


def tokenize(text: str) -> list[str]:
    """把文本切成小写词元。

    Args:
        text: 任意文本。

    Returns:
        词元列表（可能为空）。
    """
    return _TOKEN_PATTERN.findall(text.lower())


def simhash(text: str, *, bits: int = DEFAULT_SIMHASH_BITS) -> int:
    """计算文本的 SimHash（确定性）。

    Args:
        text: 待计算文本。
        bits: 位宽（默认 64）。

    Returns:
        ``bits`` 位整数指纹；无词元时返回 ``0``。
    """
    tokens = tokenize(text)
    if not tokens:
        return 0
    weights = [0] * bits
    for token in tokens:
        digest = hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest()
        value = int.from_bytes(digest, "big")
        for index in range(bits):
            weights[index] += 1 if (value >> index) & 1 else -1
    fingerprint = 0
    for index, weight in enumerate(weights):
        if weight > 0:
            fingerprint |= 1 << index
    return fingerprint


def hamming_distance(left: int, right: int) -> int:
    """计算两个指纹的汉明距离。

    Args:
        left: 指纹 A。
        right: 指纹 B。

    Returns:
        不同位的个数。
    """
    return bin(left ^ right).count("1")


def normalize_url(url: str | None) -> str | None:
    """规范化 URL（去查询串/片段/末尾斜杠，host 小写），作为去重键。

    Args:
        url: 原始 URL。

    Returns:
        规范化后的 URL；输入为空时返回 ``None``。
    """
    if not url or not url.strip():
        return None
    parts = urlsplit(url.strip())
    path = parts.path.rstrip("/")
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), path, "", ""))


def dedupe_urls(urls: Iterable[str]) -> list[str]:
    """URL 去重（按规范化键，保留首次出现顺序）。

    Args:
        urls: 原始 URL 序列。

    Returns:
        去重后的原始 URL 列表。
    """
    seen: set[str] = set()
    result: list[str] = []
    for url in urls:
        key = normalize_url(url)
        if key and key not in seen:
            seen.add(key)
            result.append(url)
    return result


def primary_key(vuln: UnifiedVuln) -> str:
    """返回用于精确匹配的主键：优先 CVE 编号，否则使用规范化的 ``vuln_id``。

    Args:
        vuln: 归一化实体。

    Returns:
        大写主键（如 ``CVE-2024-3400``）。
    """
    cve = normalize_cve_id(vuln.vuln_id)
    if cve:
        return cve
    for alias in vuln.aliases:
        cve = normalize_cve_id(alias)
        if cve:
            return cve
    return vuln.vuln_id.strip().upper()


def similarity_fingerprint(vuln: UnifiedVuln) -> int:
    """计算「标题 + 描述」的 SimHash 指纹。

    Args:
        vuln: 归一化实体。

    Returns:
        64 位指纹。
    """
    return simhash(f"{vuln.title or ''} {vuln.description}")


def _dedupe_by_key(items: Iterable[object], key_func: object) -> list[object]:
    """按 ``key_func`` 去重（保留首次出现顺序）。

    Args:
        items: 待去重序列。
        key_func: 可调用对象，接受元素返回可哈希键。

    Returns:
        去重后的列表。
    """
    seen: set[object] = set()
    result: list[object] = []
    for item in items:
        key = key_func(item)  # type: ignore[operator]
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


def _merge_similar(vulns: Sequence[UnifiedVuln], *, threshold: int) -> list[UnifiedVuln]:
    """对**无 CVE 主键**的条目按 SimHash 聚类合并。

    Args:
        vulns: 已按主键精确合并后的条目。
        threshold: 汉明距离阈值。

    Returns:
        合并后的条目列表。
    """
    keyed = [vuln for vuln in vulns if normalize_cve_id(primary_key(vuln))]
    fuzzy = [vuln for vuln in vulns if not normalize_cve_id(primary_key(vuln))]
    clusters: list[list[UnifiedVuln]] = []
    for vuln in sorted(fuzzy, key=lambda item: item.vuln_id):
        fingerprint = similarity_fingerprint(vuln)
        for cluster in clusters:
            if hamming_distance(fingerprint, similarity_fingerprint(cluster[0])) <= threshold:
                cluster.append(vuln)
                break
        else:
            clusters.append([vuln])
    return [*keyed, *[merge_group(cluster) for cluster in clusters]]


def merge_unified_vulns(
    vulns: Iterable[UnifiedVuln],
    *,
    simhash_threshold: int = DEFAULT_HAMMING_THRESHOLD,
    use_similarity: bool = True,
) -> list[UnifiedVuln]:
    """跨源去重与合并（本项目的主入口）。

    先按 :func:`primary_key`（CVE 优先）精确合并，再用 :func:`similarity_fingerprint`
    对无 CVE 主键的条目做近似聚类；``sources`` / ``trace_ids`` 记录全部来源。

    Args:
        vulns: 待合并的 ``UnifiedVuln`` 序列（可来自 NVD / OSV / GHSA / KEV / EPSS）。
        simhash_threshold: SimHash 汉明距离阈值。
        use_similarity: ``False`` 时只做精确匹配（快速模式）。

    Returns:
        合并后的 ``UnifiedVuln`` 列表（按 ``vuln_id`` 升序，输出确定）。
    """
    grouped: dict[str, list[UnifiedVuln]] = {}
    for vuln in vulns:
        grouped.setdefault(primary_key(vuln), []).append(vuln)
    merged = [merge_group(group) for group in grouped.values()]
    if use_similarity:
        merged = _merge_similar(merged, threshold=simhash_threshold)
    return sorted(merged, key=lambda item: item.vuln_id)


def _canonical_id(vulns: Sequence[UnifiedVuln]) -> str | None:
    """在组内寻找规范化后的 CVE 主键（优先 ``vuln_id``，其次别名）。

    Args:
        vulns: 同一漏洞组的条目（顺序有意义：最早发布在前）。

    Returns:
        CVE 编号；组内没有 CVE 时返回 ``None``。
    """
    for vuln in vulns:
        cve = normalize_cve_id(vuln.vuln_id)
        if cve:
            return cve
    for vuln in vulns:
        for alias in vuln.aliases:
            cve = normalize_cve_id(alias)
            if cve:
                return cve
    return None


def _reference_source(vulns: Sequence[UnifiedVuln], url: str, fallback: str) -> str:
    """返回该 URL 首次出现的来源标识（找不到时用 ``fallback``）。

    Args:
        vulns: 参与合并的条目。
        url: 原始 URL。
        fallback: 兜底来源标识。

    Returns:
        来源标识。
    """
    key = normalize_url(url)
    for vuln in vulns:
        for ref in vuln.references:
            if normalize_url(ref.url) == key:
                return ref.source
    return fallback


def _reference_tags(vulns: Sequence[UnifiedVuln], url: str) -> list[str]:
    """收集同一 URL 在各源上的全部标签（去重保序）。

    Args:
        vulns: 参与合并的条目。
        url: 原始 URL。

    Returns:
        标签列表。
    """
    key = normalize_url(url)
    tags = [
        tag for vuln in vulns for ref in vuln.references if normalize_url(ref.url) == key for tag in ref.tags
    ]
    return [str(tag) for tag in _dedupe_by_key(tags, str)]


def merge_group(vulns: Sequence[UnifiedVuln]) -> UnifiedVuln:
    """把同一漏洞的多源记录合并为一条（确定性）。

    Args:
        vulns: 同一主键下的多条 ``UnifiedVuln``（至少 1 条）。

    Returns:
        合并后的 ``UnifiedVuln``。

    Raises:
        ValueError: 传入空序列。
    """
    if not vulns:
        raise ValueError("merge_group 需要至少一条记录")
    ordered = sorted(vulns, key=lambda item: (item.published_at is None, item.published_at, item.vuln_id))
    primary = ordered[0]

    # 规范主键：优先组内出现的 CVE 编号（其余 GHSA/OSV 编号降为别名），
    # 保证「同一 CVE 的多源记录」在图谱/API 中落到同一个 vuln_id（§10 契约语义）。
    canonical_id = _canonical_id(ordered) or primary.vuln_id
    alias_pool: list[str] = [
        *(alias for vuln in ordered for alias in vuln.aliases),
        *(vuln.vuln_id for vuln in ordered),
    ]
    aliases = [
        str(alias)
        for alias in _dedupe_by_key(alias_pool, str.upper)
        if str(alias).upper() != canonical_id.upper()
    ]
    cvss_pairs: list[tuple[str, str, UnifiedVuln]] = []
    for vuln in ordered:
        for vector in vuln.cvss:
            cvss_pairs.append((vector.version, vector.vector, vuln))
    seen_vectors: set[tuple[str, str]] = set()
    merged_cvss = []
    for version, vector, owner in cvss_pairs:
        if (version, vector) in seen_vectors:
            continue
        seen_vectors.add((version, vector))
        merged_cvss.append(next(item for item in owner.cvss if item.vector == vector))
    merged_cvss.sort(key=lambda item: item.version)

    cpe_matches = _dedupe_by_key(
        [match for vuln in ordered for match in vuln.cpe_matches],
        lambda match: (match.vendor, match.product, match.version_end_excl, match.version_start_incl),
    )
    references = [
        Reference(
            url=url,
            source=_reference_source(ordered, url, primary.sources[0] if primary.sources else "unknown"),
            tags=_reference_tags(ordered, url),
        )
        for url in dedupe_urls([ref.url for vuln in ordered for ref in vuln.references])
    ]

    descriptions = sorted([vuln.description for vuln in ordered if vuln.description], key=len, reverse=True)
    titles = [vuln.title for vuln in ordered if vuln.title]
    published = [vuln.published_at for vuln in ordered if vuln.published_at]
    modified = [vuln.modified_at for vuln in ordered if vuln.modified_at]
    epss_scores = [vuln.epss_score for vuln in ordered if vuln.epss_score is not None]
    epss_percentiles = [vuln.epss_percentile for vuln in ordered if vuln.epss_percentile is not None]

    return UnifiedVuln(
        schema_version=primary.schema_version,
        vuln_id=canonical_id,
        aliases=aliases,
        trace_ids=[trace for trace in _dedupe_by_key([t for vuln in ordered for t in vuln.trace_ids], str)],
        title=titles[0] if titles else primary.title,
        description=descriptions[0] if descriptions else primary.description,
        lang=primary.lang,
        cvss=merged_cvss,
        cwe_ids=[str(cwe) for cwe in _dedupe_by_key([cwe for vuln in ordered for cwe in vuln.cwe_ids], str.upper)],
        cpe_matches=[match for match in cpe_matches],
        ecosystem_packages=[
            str(pkg) for pkg in _dedupe_by_key([pkg for vuln in ordered for pkg in vuln.ecosystem_packages], str)
        ],
        references=references,
        kev=any(vuln.kev for vuln in ordered),
        epss_score=max(epss_scores) if epss_scores else None,
        epss_percentile=max(epss_percentiles) if epss_percentiles else None,
        published_at=min(published) if published else None,
        modified_at=max(modified) if modified else None,
        sources=sorted({source for vuln in ordered for source in vuln.sources}),
        normalized_at=max(vuln.normalized_at for vuln in ordered),
    )

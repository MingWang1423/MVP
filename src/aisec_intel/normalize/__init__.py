"""L2 归一化层（PROJECT_PLAN.md §2）：**纯函数，禁止 LLM**。

对外主入口：

- :func:`build_unified_vuln`：``RawItem`` → ``UnifiedVuln``（单条）
- :func:`build_many`：批量归一化（跳过无法确定主键的条目）

子模块职责：
    - ``cve``：跨源字段抽取（NVD / OSV / GHSA / KEV / EPSS）与 CVE 编号规范化
    - ``cvss``：CVSS v2/v3.0/v3.1 向量解析与基础分计算（v4.0 需源侧给分）
    - ``datetime_utils``：时间统一为 UTC
    - ``pipeline``：纯函数组合与去重
"""

from __future__ import annotations

from aisec_intel.normalize.cve import (
    CveFields,
    clean_text,
    extract_cve_fields,
    extract_cve_ids,
    is_cve_id,
    normalize_cve_id,
    parse_payload,
)
from aisec_intel.normalize.cvss import (
    extract_cvss_vectors,
    parse_cvss_vector,
    parse_vector_metrics,
    score_v2,
    score_v3,
    severity_from_score,
)
from aisec_intel.normalize.datetime_utils import (
    days_ago,
    ensure_utc,
    isoformat_z,
    parse_datetime,
    to_date_str,
)
from aisec_intel.normalize.dedupe import (
    dedupe_urls,
    hamming_distance,
    merge_group,
    merge_unified_vulns,
    normalize_url,
    primary_key,
    simhash,
    similarity_fingerprint,
    tokenize,
)
from aisec_intel.normalize.pipeline import (
    build_many,
    build_references,
    build_unified_vuln,
    canonical_ecosystem,
    extract_cpe_matches,
    extract_ecosystem_packages,
    parse_cpe23,
)

__all__ = [
    "CveFields",
    "build_many",
    "build_references",
    "build_unified_vuln",
    "canonical_ecosystem",
    "clean_text",
    "days_ago",
    "dedupe_urls",
    "ensure_utc",
    "extract_cpe_matches",
    "extract_cve_fields",
    "extract_cve_ids",
    "extract_cvss_vectors",
    "extract_ecosystem_packages",
    "hamming_distance",
    "is_cve_id",
    "isoformat_z",
    "merge_group",
    "merge_unified_vulns",
    "normalize_cve_id",
    "normalize_url",
    "parse_cpe23",
    "parse_cvss_vector",
    "parse_datetime",
    "parse_payload",
    "parse_vector_metrics",
    "primary_key",
    "score_v2",
    "score_v3",
    "severity_from_score",
    "simhash",
    "similarity_fingerprint",
    "to_date_str",
    "tokenize",
]


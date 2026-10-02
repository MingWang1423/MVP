"""向量索引文本渲染（Day10 P6 收尾，配合 ``storage/vector_store.py``）。

**纯函数层**：无 IO、无全局状态、**禁止 LLM**（§0 约束 1）。职责是把结构化实体渲染成
「可向量化、可引用、可人工核对」的稳定文本与元数据，保证：

1. **可复现**：同一实体每次渲染结果完全一致（无时间戳、无随机、无模型参与）；
2. **可引用**：文本自带主键（``CVE-xxxx`` / ``paper_id``），命中结果能直接回溯到 PG 行；
3. **可过滤**：元数据只放扁平标量（``cve_id`` / ``source`` / ``published_at``），
   与 Chroma 的 ``where`` 过滤器兼容（Chroma 不接受 ``None`` 与嵌套结构）。

三个集合对应三类文本：

=================================  ==============================  ==============================================
集合                                 来源                            渲染口径
=================================  ==============================  ==============================================
``vuln_descriptions``              ``unified_vuln``                编号 + 标题 + CWE + 严重度 + 版本 + 描述（事实层）
``paper_abstracts``                ``raw_item``（论文源）            标题 + 摘要（复用 ``normalize.papers.paper_text``）
``remediation_texts``              ``enriched_vuln``               维度⑦修复结论 + 版本 + 官方补丁 + 资产 + 风险级别
=================================  ==============================  ==============================================

Note:
    ``remediation_texts`` 自 Day17 起**同时包含**两处已落库的处置线索：
    ① 富化维度⑦ 的 ``remediation_json``（LLM 摘要 / 修复版本 / 缓解措施 / 白名单补丁链接，
    已由迁移 ``0007_enriched_remediation`` 落库）；② 由事实层确定的 ``affected_versions`` /
    ``references(patch)`` / ``affected_assets`` / ``risk_level``。
    两者都**可引用回溯**，问答层引用它们不构成编造。
"""

from __future__ import annotations

from aisec_intel.models.base import iso_z
from aisec_intel.models.enriched_vuln import EnrichedVuln
from aisec_intel.models.unified_vuln import UnifiedVuln

MAX_INDEX_CHARS: int = 4000
"""单条向量文本的字符上限（超过即截断；避免超出嵌入模型最大输入长度白白损失算力）。"""

PATCH_TAGS: frozenset[str] = frozenset(
    {"patch", "vendor-advisory", "vendor_advisory", "fix", "release-notes", "mitigation"}
)
"""``Reference.tags`` 中表示「补丁 / 厂商公告 / 缓解」的标签（大小写不敏感）。"""

MAX_REFERENCES: int = 5
"""单条修复文本最多引用的链接数。"""


def clipped(text: str, *, limit: int = MAX_INDEX_CHARS) -> str:
    """按上限截断文本（纯函数）。

    Args:
        text: 原始文本。
        limit: 字符上限（``<=0`` 时回退到 :data:`MAX_INDEX_CHARS`）。

    Returns:
        截断后的文本。
    """
    cap = limit if limit > 0 else MAX_INDEX_CHARS
    return text if len(text) <= cap else text[:cap]


def patch_references(vuln: UnifiedVuln, *, limit: int = MAX_REFERENCES) -> list[str]:
    """挑出「补丁 / 厂商公告 / 缓解」类参考链接（纯函数）。

    判定顺序：``Reference.tags`` 命中 :data:`PATCH_TAGS`；若没有任何 patch 类标签，
    则回退为「URL 含 ``patch`` / ``advisory`` / ``security``」的启发式匹配（确定性规则，非 LLM）。

    Args:
        vuln: 漏洞实体。
        limit: 返回条数上限。

    Returns:
        去重保序的 URL 列表。
    """
    with_tags: list[str] = []
    heuristics: list[str] = []
    for reference in vuln.references:
        lowered = reference.url.lower()
        if any(tag.strip().lower() in PATCH_TAGS for tag in reference.tags):
            with_tags.append(reference.url)
        elif any(keyword in lowered for keyword in ("patch", "advisory", "security")):
            heuristics.append(reference.url)
    seen: set[str] = set()
    unique = [url for url in (with_tags or heuristics) if not (url in seen or seen.add(url))]
    return unique[: max(0, limit)]


def render_vuln_text(vuln: UnifiedVuln) -> str:
    r"""渲染漏洞描述的向量文本（事实层口径，确定性）。

    Args:
        vuln: L2 归一化实体。

    Returns:
        形如 ``CVE-2024-3400 PAN-OS Command Injection Vulnerability\\nCWE: CWE-78 | ...\\n<描述>`` 的文本。
    """
    header = f"{vuln.vuln_id} {vuln.title or ''}".strip()
    facts: list[str] = []
    if vuln.cwe_ids:
        facts.append(f"CWE: {', '.join(vuln.cwe_ids)}")
    if vuln.severity:
        facts.append(f"Severity: {vuln.severity}")
    if vuln.affected_versions:
        facts.append(f"Affected: {'; '.join(vuln.affected_versions)}")
    if vuln.kev:
        facts.append("CISA KEV: exploited in the wild")
    body = "\n".join(part for part in (header, " | ".join(facts), vuln.description) if part)
    return clipped(body)


def vuln_index_metadata(vuln: UnifiedVuln) -> dict[str, str]:
    """构造漏洞描述的向量元数据（扁平标量，可被 Chroma ``where`` 过滤）。

    Args:
        vuln: L2 归一化实体。

    Returns:
        形如 ``{"cve_id": ..., "source": ..., "published_at": ..., "severity": ..., "kev": ...}``；
        缺失字段**不写入键**（Chroma 不接受 ``None``）。
    """
    metadata: dict[str, str] = {"cve_id": vuln.vuln_id}
    if vuln.sources:
        metadata["source"] = ",".join(sorted(vuln.sources))
    if vuln.published_at is not None:
        metadata["published_at"] = iso_z(vuln.published_at)
    if vuln.severity:
        metadata["severity"] = vuln.severity
    if vuln.kev:
        metadata["kev"] = "true"
    return metadata


def render_remediation_text(enriched: EnrichedVuln) -> str:
    """渲染「处置要点」的向量文本（事实层确定性拼装 + 已落库的富化维度⑦结论）。

    内容组成：
        1. 富化维度⑦修复结论（``remediation_json``：LLM 摘要 / 修复版本 / 缓解措施 /
           白名单校验通过的补丁链接）—— Day17 v1.2 起已落库，故问答层可直接引用；
        2. 受影响版本区间（``affected_versions``）；
        3. 处置动作（升级到区间之外的版本；无法升级时以厂商缓解措施为准）；
        4. 官方补丁 / 公告链接（``references`` 中 patch 类，禁止编造 URL）；
        5. 受影响组件与资产（``cpe_matches`` / ``affected_assets``）；
        6. 当前风险级别（``risk_level``，由确定性公式得出，§3.2 闸门③）。

    Args:
        enriched: L3 富化实体（父字段来自 ``unified_vuln``）。

    Returns:
        多行文本；无任何可用事实时仅返回带主键的说明行。
    """
    lines: list[str] = [f"{enriched.vuln_id} 处置要点"]
    remediation = enriched.remediation_json or {}
    summary = str(remediation.get("summary") or "").strip()
    if summary:
        lines.append(f"修复结论: {summary}")
    fixed_versions = [str(item) for item in remediation.get("fixed_versions") or [] if str(item).strip()]
    if fixed_versions:
        lines.append(f"修复版本: {', '.join(fixed_versions)}")
    mitigations = [str(item) for item in remediation.get("mitigations") or [] if str(item).strip()]
    if mitigations:
        lines.append("缓解措施: " + " | ".join(mitigations))
    envelope_patches = [str(item) for item in remediation.get("patch_urls") or [] if str(item).strip()]
    if envelope_patches:
        lines.append("富化补丁链接: " + " | ".join(envelope_patches))
    if enriched.affected_versions:
        lines.append(f"受影响版本: {'; '.join(enriched.affected_versions)}")
        lines.append("处置动作: 升级至受影响区间之外的版本；无法升级时按厂商缓解方案执行")
    elif enriched.cpe_matches:
        products = ", ".join(sorted({f"{cpe.vendor}:{cpe.product}" for cpe in enriched.cpe_matches}))
        lines.append(f"受影响组件: {products}")
        lines.append("处置动作: 确认在用版本是否落在受影响区间，按厂商公告处置")
    patches = patch_references(enriched)
    if patches:
        lines.append("官方补丁/公告: " + " | ".join(patches))
    assets = ", ".join(sorted({asset.name for asset in enriched.affected_assets if asset.name}))
    if assets:
        lines.append(f"受影响资产: {assets}")
    lines.append(f"当前风险级别: {enriched.risk_level}")
    return clipped("\n".join(lines))


def remediation_index_metadata(enriched: EnrichedVuln) -> dict[str, str]:
    """构造处置要点的向量元数据。

    Args:
        enriched: L3 富化实体。

    Returns:
        形如 ``{"cve_id": ..., "source": "enriched_vuln", "published_at": ..., "risk_level": ...}``。
    """
    metadata: dict[str, str] = {"cve_id": enriched.vuln_id, "source": "enriched_vuln"}
    if enriched.published_at is not None:
        metadata["published_at"] = iso_z(enriched.published_at)
    metadata["risk_level"] = enriched.risk_level
    return metadata

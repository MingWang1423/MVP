"""论文归一化（PROJECT_PLAN.md §5.5 P4 论文源 / §5.7 P6 前置）。

**纯函数层**：无 IO、无全局状态、禁止 LLM（§0 约束 1）。

职责：
    - 把论文类源的 ``RawItem``（``arxiv`` / ``openalex``）投影为领域模型 :class:`Paper`；
    - 只保留**元数据与摘要**，不落全文 PDF（§7 R10 版权合规）；
    - **不写** ``unified_vuln``：论文不是漏洞，P6 由 ``paper`` 表 / 图谱 / 向量承载。

用途：富化 Agent②（PaperLinker）用 :func:`paper_text` 构造 embedding 与关键词检索输入。
"""

from __future__ import annotations

from aisec_intel.models.paper import Paper, PaperSource
from aisec_intel.models.raw_item import RawItem
from aisec_intel.normalize.datetime_utils import parse_datetime

PAPER_SOURCES: frozenset[str] = frozenset({"arxiv", "openalex"})
"""论文类源标识（与 ``services/collect_service.PAPER_SOURCES`` 语义一致）。"""

_SOURCE_MAP: dict[str, PaperSource] = {"arxiv": "arxiv", "openalex": "openalex"}
"""``RawItem.source`` → ``Paper.source``（未知源降级为 ``other``）。"""


def is_paper_source(source: str) -> bool:
    """判断源标识是否为论文源（大小写不敏感）。

    Args:
        source: 源标识。

    Returns:
        论文源返回 ``True``。
    """
    return source.strip().lower() in PAPER_SOURCES


def raw_item_to_paper(item: RawItem) -> Paper:
    """把论文源 ``RawItem`` 转换为 :class:`Paper`（确定性，无推断）。

    Args:
        item: ``arxiv`` / ``openalex`` 采集件（``raw_text`` 为条目级保真 JSON）。

    Returns:
        :class:`Paper`（``trace_ids`` 透传 ``item.trace_id``，§10.2 不变式 5）。

    Raises:
        ValueError: 源不是论文源（避免把漏洞条目误当论文）。
    """
    if not is_paper_source(item.source):
        raise ValueError(f"{item.source!r} 不是论文源，无法转换为 Paper（可选：{sorted(PAPER_SOURCES)}）")
    payload = item.payload or {}
    if item.source == "arxiv":
        authors = [str(name) for name in payload.get("authors") or []]
        venue = payload.get("journal_ref") or payload.get("comment")
        abstract = payload.get("summary")
        url = payload.get("abstract_url") or item.url
        published = payload.get("published") or item.published_at
    else:
        authors = [str(name) for name in payload.get("authors") or []]
        venue = payload.get("venue")
        abstract = payload.get("abstract")
        url = payload.get("landing_page_url") or item.url
        published = payload.get("publication_date") or item.published_at

    paper_id = str(payload.get("arxiv_id") or payload.get("openalex_id") or item.source_id)
    return Paper(
        paper_id=paper_id,
        source=_SOURCE_MAP.get(item.source, "other"),
        title=str(payload.get("title") or item.title or paper_id),
        abstract=str(abstract) if abstract else None,
        authors=authors,
        venue=str(venue) if venue else None,
        url=str(url) if url else None,
        published_at=parse_datetime(published),
        trace_ids=[item.trace_id],
    )


def paper_text(paper: Paper) -> str:
    """拼接论文的可检索文本（标题 + 摘要；用于向量化与关键词召回）。

    Args:
        paper: 论文实体。

    Returns:
        以换行分隔的文本；无摘要时仅标题。
    """
    return "\n".join(part for part in (paper.title, paper.abstract) if part)

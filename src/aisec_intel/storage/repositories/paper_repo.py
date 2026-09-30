"""论文只读检索仓储（PROJECT_PLAN.md §5.5 P4 任务 4 / §5.7 P6 前置）。

**只读**：论文实体（``arxiv`` / ``openalex``）当前存放于 ``raw_item`` 表（内容寻址），
本仓储把它们投影为领域模型 :class:`~aisec_intel.models.paper.Paper`，供富化 Agent②
（PaperLinker）做「CVE → 论文」候选召回；**绝不写入** ``unified_vuln``
（论文不是漏洞；P6 由图谱与向量承载）。

检索口径（确定性、无 LLM，可离线复现）：

1. :meth:`list_recent`：按发布时间倒序列出论文；
2. :meth:`get`：按 ``paper_id`` 精确命中（容忍 arXiv 版本号后缀，如 ``2404.12345v2``）；
3. :meth:`search`：标题 + 摘要的词元命中打分（:func:`aisec_intel.normalize.dedupe.tokenize`），
   排序键为「命中数 ↓ → 发布时间 ↓ → paper_id ↑」，保证输出确定；
4. :meth:`count`：论文总数（数据质量 / 运维页）。

Note:
    跨库（PostgreSQL / SQLite）一致：JSON 字段的匹配在 Python 侧完成，
    不使用方言相关的 JSON 运算符，保证本地降级模式与生产行为一致。
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aisec_intel.models.paper import Paper
from aisec_intel.normalize.dedupe import tokenize
from aisec_intel.normalize.papers import PAPER_SOURCES, paper_text, raw_item_to_paper
from aisec_intel.storage.models.raw import RawItemRow

_VERSION_SUFFIX: re.Pattern[str] = re.compile(r"v\d+$")
"""arXiv 版本号后缀（``2404.12345v2`` → ``2404.12345``）。"""

DEFAULT_SCAN_LIMIT: int = 2000
"""关键词检索时最多扫描的论文行数（防止超大库拖垮 Agent）。"""


@dataclass(frozen=True, slots=True)
class PaperHit:
    """关键词检索命中结果。

    Attributes:
        paper: 命中的论文。
        score: 命中词元数（越大越相关）。
        matched: 命中的关键词列表（去重保序，便于留证）。
    """

    paper: Paper
    score: int
    matched: list[str]


def normalize_paper_id(paper_id: str) -> str:
    """规范化论文主键（去空白 + 去 arXiv 版本号后缀）。

    Args:
        paper_id: 原始主键，如 ``" 2404.12345v2 "``。

    Returns:
        规范化主键，如 ``"2404.12345"``。
    """
    return _VERSION_SUFFIX.sub("", paper_id.strip())


class PaperRepository:
    """论文只读仓储（数据来源：``raw_item`` 表的论文源行）。"""

    def __init__(self, session: AsyncSession) -> None:
        """绑定异步会话。

        Args:
            session: 由 :func:`aisec_intel.storage.database.session_scope` 提供的会话。
        """
        self._session = session

    @staticmethod
    def _sources(sources: Sequence[str] | None) -> list[str]:
        """归一化源过滤条件（默认全部论文源）。

        Args:
            sources: 调用方指定的源；``None`` 表示全部论文源。

        Returns:
            源标识列表。
        """
        if not sources:
            return sorted(PAPER_SOURCES)
        return sorted({source.strip().lower() for source in sources if source.strip()})

    async def _rows(
        self,
        *,
        sources: Sequence[str] | None = None,
        limit: int = DEFAULT_SCAN_LIMIT,
        source_id: str | None = None,
    ) -> list[RawItemRow]:
        """按源读取论文行（发布时间倒序，缺失时回退采集时间）。

        Args:
            sources: 源过滤条件。
            limit: 最多读取行数。
            source_id: 仅读取指定 ``source_id``（精确匹配）。

        Returns:
            ORM 行列表。
        """
        await self._session.flush()
        stmt = (
            select(RawItemRow)
            .where(RawItemRow.source.in_(self._sources(sources)))
            .order_by(RawItemRow.published_at.desc().nullslast(), RawItemRow.fetched_at.desc())
            .limit(max(1, limit))
        )
        if source_id is not None:
            stmt = stmt.where(RawItemRow.source_id == source_id)
        return list((await self._session.execute(stmt)).scalars().all())

    async def list_recent(
        self,
        *,
        limit: int = 20,
        sources: Sequence[str] | None = None,
    ) -> list[Paper]:
        """按发布时间倒序返回最近的论文。

        Args:
            limit: 返回条数上限。
            sources: 源过滤条件；``None`` 表示全部论文源。

        Returns:
            :class:`Paper` 列表。
        """
        rows = await self._rows(sources=sources, limit=limit)
        return [raw_item_to_paper(row.to_domain()) for row in rows]

    async def get(self, paper_id: str, *, sources: Sequence[str] | None = None) -> Paper | None:
        """按 ``paper_id`` 读取单篇论文（容忍 arXiv 版本号后缀）。

        Args:
            paper_id: 论文主键（arXiv ID / OpenAlex Work ID）。
            sources: 源过滤条件。

        Returns:
            命中时返回 :class:`Paper`，否则 ``None``。
        """
        normalized = normalize_paper_id(paper_id)
        for candidate in (paper_id.strip(), normalized):
            rows = await self._rows(sources=sources, limit=1, source_id=candidate)
            if rows:
                return raw_item_to_paper(rows[0].to_domain())
        return None

    async def search(
        self,
        keywords: Sequence[str],
        *,
        limit: int = 20,
        sources: Sequence[str] | None = None,
        min_score: int = 1,
        scan_limit: int = DEFAULT_SCAN_LIMIT,
    ) -> list[PaperHit]:
        """关键词召回论文（标题 + 摘要词元命中打分，确定性排序）。

        Args:
            keywords: 关键词列表（单词或短语，大小写不敏感；空白项被忽略）。
            limit: 返回条数上限。
            sources: 源过滤条件。
            min_score: 最低命中词元数（默认 1）。
            scan_limit: 最多扫描的论文行数。

        Returns:
            :class:`PaperHit` 列表（按命中数降序、发布时间降序、paper_id 升序）。
        """
        cleaned = [keyword.strip().lower() for keyword in keywords if keyword.strip()]
        if not cleaned or limit <= 0:
            return []

        hits: list[PaperHit] = []
        for row in await self._rows(sources=sources, limit=scan_limit):
            paper = raw_item_to_paper(row.to_domain())
            tokens = tokenize(paper_text(paper))
            score = 0
            matched: list[str] = []
            for keyword in cleaned:
                # 短语（如 "prompt injection"）要求各词元均命中；单词按子串匹配（含复数/派生）
                parts = tokenize(keyword)
                if not parts:
                    continue
                counts = [sum(1 for token in tokens if part in token) for part in parts]
                if all(count > 0 for count in counts):
                    score += sum(counts)
                    matched.append(keyword)
            if score >= min_score:
                hits.append(PaperHit(paper=paper, score=score, matched=matched))

        hits.sort(key=lambda hit: (-hit.score, _recency_key(hit.paper), hit.paper.paper_id))
        return hits[:limit]

    async def count(self, *, sources: Sequence[str] | None = None) -> int:
        """统计论文总数。

        Args:
            sources: 源过滤条件。

        Returns:
            论文条数。
        """
        return len(await self._rows(sources=sources))


def _recency_key(paper: Paper) -> float:
    """排序辅助：发布时间越新越靠前（缺失时间视为最旧）。

    Args:
        paper: 论文实体。

    Returns:
        负数纪元秒；``published_at`` 缺失时返回 ``0.0``（排在最新之后、最早之前）。
    """
    if paper.published_at is None:
        return 0.0
    return -paper.published_at.timestamp()


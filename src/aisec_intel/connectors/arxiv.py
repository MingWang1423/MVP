"""arXiv 论文采集器（PROJECT_PLAN.md §5.4 P3 扩展源：AI 安全论文情报）。

数据源：arXiv 官方 API ``http://export.arxiv.org/api/query``（Atom 1.0 XML）。

约定：
    - ``source_name = "arxiv"``；
    - 查询关键词默认 ``cs.CR AND (LLM OR agent OR prompt injection)``（可用构造参数覆盖）；
    - **支持多检索式**（Day9 扩容）：``queries`` 传入一组互补检索式（LLM security /
      prompt injection / AI agent attack），逐条翻页后跨检索式按 ``source_id`` 去重，
      整体受 ``max_results`` 上限约束；
    - **增量按 ``submittedDate``**：查询串追加 ``submittedDate:[YYYYMMDDHHMM TO ...]``，
      并在客户端再按 ``published_at >= since`` 过滤（双保险，便于离线夹具测试）；
    - ``source_id`` 使用 arXiv ID（去掉版本号，如 ``2404.12345``），版本号写入 ``meta``；
    - ``raw_text`` 保存条目级保真 JSON（标题 / 摘要 / 作者 / 分类 / 链接），
      仅存**元数据与摘要**、不存全文 PDF（§7 R10 版权合规）；
    - L1 采集层禁止 LLM（§0 约束 1）。
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from datetime import datetime
from typing import Any, ClassVar

from lxml import etree

from aisec_intel.connectors.base import BaseConnector
from aisec_intel.connectors.registry import register
from aisec_intel.logging_config import get_logger
from aisec_intel.models.raw_item import RawItem

logger = get_logger(__name__)

ARXIV_API_URL: str = "http://export.arxiv.org/api/query"
"""arXiv 查询 API 地址。"""

ARXIV_DEFAULT_QUERY: str = 'cat:cs.CR AND (all:LLM OR all:agent OR all:"prompt injection")'
"""默认检索式：密码学与安全（cs.CR）类目中与 LLM / agent / prompt injection 相关的论文。"""

ARXIV_DEFAULT_QUERIES: tuple[str, ...] = (
    ARXIV_DEFAULT_QUERY,
    'cat:cs.CR AND all:"LLM security"',
    'cat:cs.CR AND all:"prompt injection"',
    'cat:cs.CR AND (all:"AI agent" AND all:attack)',
)
"""Day9 默认多检索式（与 ``configs/sources.yaml`` 的 ``queries`` 一致，便于无配置时离线演示）。"""

ARXIV_SOURCE_NAME: str = "arxiv"
"""源标识。"""

ATOM_NS: str = "http://www.w3.org/2005/Atom"
"""Atom 命名空间。"""

ARXIV_NS: str = "http://arxiv.org/schemas/atom"
"""arXiv 扩展命名空间（``arxiv:primary_category`` 等）。"""

NAMESPACES: dict[str, str] = {"atom": ATOM_NS, "arxiv": ARXIV_NS}
"""XPath 命名空间映射。"""

DEFAULT_PAGE_SIZE: int = 100
"""单页条数（arXiv 建议一次不超过 100~200 条）。"""

MAX_PAGES: int = 5
"""单次采集最多翻页数（防止宽时间窗下无限翻页）。"""

_VERSION_PATTERN: re.Pattern[str] = re.compile(r"^(?P<base>[\w.\-/]+?)(?P<version>v\d+)?$")
_WS_PATTERN: re.Pattern[str] = re.compile(r"\s+")


def split_arxiv_id(raw: str) -> tuple[str, str | None]:
    """拆分 arXiv ID 与版本号。

    Args:
        raw: 形如 ``"2404.12345v2"`` 或 ``"http://arxiv.org/abs/2404.12345v2"``。

    Returns:
        ``(不含版本的 arXiv ID, 版本号或 None)``；无法解析时返回 ``(原值, None)``。
    """
    candidate = raw.strip().rsplit("/abs/", 1)[-1].strip()
    match = _VERSION_PATTERN.match(candidate)
    if not match:
        return candidate, None
    return match.group("base"), match.group("version")


def _squash(text: str | None) -> str:
    """压缩空白（arXiv 的标题与摘要均含换行缩进）。"""
    return _WS_PATTERN.sub(" ", text or "").strip()


@register
class ArxivConnector(BaseConnector):
    """arXiv 采集器（Atom XML）。

    Attributes:
        api_url: 查询 API 地址（测试可覆盖）。
        page_size: 单页条数。
    """

    source_name: ClassVar[str] = ARXIV_SOURCE_NAME
    rate_limit: ClassVar[str] = "1/3"
    timeout: ClassVar[float] = 60.0
    api_url: ClassVar[str] = ARXIV_API_URL
    page_size: ClassVar[int] = DEFAULT_PAGE_SIZE
    max_pages: ClassVar[int] = MAX_PAGES

    def __init__(
        self,
        *,
        query: str | None = None,
        queries: Sequence[str] | None = None,
        category: str | None = None,
        max_results: int | None = None,
        **kwargs: Any,
    ) -> None:
        """初始化采集器。

        Args:
            query: 单条检索式（原样传入 ``search_query``）；与 ``queries`` 同时给出时会被并入。
            queries: 多条检索式（Day9 扩容），逐条翻页后跨检索式去重。
            category: 追加类目限定（如 ``cs.CR``），与 ``query`` 取交集。
            max_results: 单次采集条数上限（``configs/sources.yaml`` 的 ``max_results``），
                等价于基类的 ``max_records``。
            **kwargs: 透传给 :class:`BaseConnector`（``http`` / ``limiter`` / ``max_records``）。
        """
        if max_results is not None and max_results > 0:
            kwargs.setdefault("max_records", int(max_results))
        super().__init__(**kwargs)
        self._queries = self._merge_queries(query, queries)
        self._query = self._queries[0]
        self._category = (category or "").strip()

    @staticmethod
    def _merge_queries(query: str | None, queries: Sequence[str] | None) -> tuple[str, ...]:
        """合并单条与多条检索式（纯函数，去重且保序）。

        Args:
            query: 单条检索式（可为空）。
            queries: 多条检索式（可为空）。

        Returns:
            去重后的检索式元组；全为空时返回 :data:`ARXIV_DEFAULT_QUERIES`。
        """
        ordered: list[str] = []
        base = (query or "").strip()
        candidates: list[str] = [base] if base else []
        candidates.extend(item.strip() for item in (queries or []) if isinstance(item, str))
        for candidate in candidates:
            if candidate and candidate not in ordered:
                ordered.append(candidate)
        return tuple(ordered) or ARXIV_DEFAULT_QUERIES

    @property
    def queries(self) -> tuple[str, ...]:
        """当前全部检索式（不含时间窗）。"""
        return self._queries

    @property
    def query(self) -> str:
        """当前检索式（不含时间窗）。"""
        return self._query

    @property
    def source_url(self) -> str:
        """源首页地址（``RawItem.url`` 的回退值）。"""
        return "https://arxiv.org/list/cs.CR/recent"

    def build_search_query(
        self, since: datetime, *, until: datetime | None = None, query: str | None = None
    ) -> str:
        """构造带 ``submittedDate`` 时间窗的检索式。

        Args:
            since: 起始时间（UTC，含）。
            until: 结束时间（UTC，含）；``None`` 表示不设上界。
            query: 覆盖检索式（多检索式模式下由 :meth:`_fetch_query` 逐条传入）。

        Returns:
            形如 ``(cat:cs.CR AND all:LLM) AND submittedDate:[202401010000 TO 202609300000]``。
        """
        window = f"[{since.strftime('%Y%m%d%H%M')} TO "
        window += f"{until.strftime('%Y%m%d%H%M')}]" if until is not None else "999912312359]"
        return f"({(query or self._query)}) AND submittedDate:{window}"

    async def fetch_page(
        self,
        *,
        since: datetime,
        offset: int = 0,
        until: datetime | None = None,
        query: str | None = None,
    ) -> str:
        """抓取一页 Atom XML（含限流）。

        Args:
            since: 增量起点（UTC）。
            offset: 分页起点（``start``）。
            until: 增量终点（UTC）；``None`` 表示不设上界。
            query: 检索式；``None`` 时使用首条（单检索式模式的兼容路径）。

        Returns:
            响应文本（Atom XML）。

        Raises:
            ValueError: 响应不是 XML（源侧结构变更）。
        """
        await self.limiter.acquire()
        text = await self.http.get_text(
            self.api_url,
            params={
                "search_query": self.build_search_query(since, until=until, query=query),
                "start": offset,
                "max_results": self.page_size,
                "sortBy": "submittedDate",
                "sortOrder": "descending",
            },
        )
        if "<feed" not in text and "<entry" not in text:
            raise ValueError(f"arXiv 响应不是 Atom XML（前 80 字符：{text[:80]!r}）")
        return text

    def parse_entries(self, xml_text: str) -> list[dict[str, Any]]:
        """把 Atom XML 解析为条目字典列表（纯函数，便于离线测试）。

        Args:
            xml_text: Atom XML 文本。

        Returns:
            条目字典列表，字段见 :meth:`entry_to_raw_item`。

        Raises:
            ValueError: XML 语法错误（源侧返回了错误页）。
        """
        try:
            root = etree.fromstring(xml_text.encode("utf-8"))
        except etree.XMLSyntaxError as exc:
            raise ValueError(f"arXiv Atom XML 解析失败：{exc}") from exc

        entries: list[dict[str, Any]] = []
        for node in root.findall("atom:entry", NAMESPACES):
            entry = self._parse_entry_node(node)
            if entry is not None:
                entries.append(entry)
        return entries

    def _parse_entry_node(self, node: etree._Element) -> dict[str, Any] | None:
        """把单个 ``<entry>`` 节点解析为字典（缺少 ID 时返回 ``None``）。

        Args:
            node: Atom ``<entry>`` 元素。

        Returns:
            条目字典；无有效 ID 时返回 ``None``。
        """
        raw_id = _squash(node.findtext("atom:id", default="", namespaces=NAMESPACES))
        if not raw_id:
            logger.warning("跳过缺少 atom:id 的 arXiv 条目")
            return None
        arxiv_id, version = split_arxiv_id(raw_id)
        links = {
            str(link.get("title")): str(link.get("href"))
            for link in node.findall("atom:link", NAMESPACES)
            if link.get("href")
        }
        primary = node.find("arxiv:primary_category", NAMESPACES)
        return {
            "arxiv_id": arxiv_id,
            "version": version,
            "title": _squash(node.findtext("atom:title", default="", namespaces=NAMESPACES)),
            "summary": _squash(node.findtext("atom:summary", default="", namespaces=NAMESPACES)),
            "published": _squash(node.findtext("atom:published", default="", namespaces=NAMESPACES)),
            "updated": _squash(node.findtext("atom:updated", default="", namespaces=NAMESPACES)),
            "authors": [
                _squash(name.text) for name in node.findall("atom:author/atom:name", NAMESPACES) if name.text
            ],
            "categories": [str(tag.get("term")) for tag in node.findall("atom:category", NAMESPACES)],
            "primary_category": str(primary.get("term")) if primary is not None else None,
            "comment": _squash(node.findtext("arxiv:comment", default="", namespaces=NAMESPACES)) or None,
            "journal_ref": _squash(node.findtext("arxiv:journal_ref", default="", namespaces=NAMESPACES)) or None,
            "doi": _squash(node.findtext("arxiv:doi", default="", namespaces=NAMESPACES)) or None,
            "abstract_url": f"https://arxiv.org/abs/{raw_id.rsplit('/abs/', 1)[-1]}",
            "pdf_url": links.get("pdf"),
        }

    def entry_to_raw_item(self, entry: dict[str, Any]) -> RawItem:
        """把解析后的条目转换为 ``RawItem``。

        Args:
            entry: :meth:`parse_entries` 产出的条目字典。

        Returns:
            统一格式的 ``RawItem``（``source_id`` 为不含版本的 arXiv ID）。

        Raises:
            ValueError: 条目缺少 ``arxiv_id``（不能写入无主键数据）。
        """
        arxiv_id = str(entry.get("arxiv_id") or "").strip()
        if not arxiv_id:
            raise ValueError(f"arXiv 条目缺少 arxiv_id：{entry!r}")

        categories = [str(tag) for tag in entry.get("categories") or []]
        authors = [str(name) for name in entry.get("authors") or []]
        meta: dict[str, str] = {
            "arxiv_version": str(entry.get("version") or ""),
            "primary_category": str(entry.get("primary_category") or ""),
            "categories": ", ".join(categories),
            "authors": ", ".join(authors),
            "pdf_url": str(entry.get("pdf_url") or ""),
        }
        for optional in ("comment", "journal_ref", "doi"):
            if entry.get(optional):
                meta[optional] = str(entry[optional])

        return self.build_raw_item(
            source_id=arxiv_id,
            raw_text=self.raw_text_from_json(
                {
                    "arxiv_id": arxiv_id,
                    "version": entry.get("version"),
                    "title": entry.get("title"),
                    "summary": entry.get("summary"),
                    "published": entry.get("published"),
                    "updated": entry.get("updated"),
                    "authors": authors,
                    "categories": categories,
                    "primary_category": entry.get("primary_category"),
                    "comment": entry.get("comment"),
                    "journal_ref": entry.get("journal_ref"),
                    "doi": entry.get("doi"),
                    "abstract_url": entry.get("abstract_url"),
                    "pdf_url": entry.get("pdf_url"),
                }
            ),
            url=str(entry.get("abstract_url") or f"https://arxiv.org/abs/{arxiv_id}"),
            title=str(entry.get("title") or "") or None,
            published_at=self.to_utc_datetime(entry.get("published")),
            lang="en",
            meta=meta,
        )

    async def fetch_incremental(self, since: datetime, *, until: datetime | None = None) -> list[RawItem]:
        """抓取 ``submittedDate >= since`` 的论文（多检索式 + 分页 + 客户端二次过滤）。

        逐条检索式调用 :meth:`_fetch_query`，跨检索式按 ``source_id`` 去重，
        并受 ``max_results``（基类 ``max_records``）整体上限约束。

        Args:
            since: 增量起点（UTC，含）；naive 时间按 UTC 处理。
            until: 增量终点（UTC，含）；``None`` 表示不设上界。

        Returns:
            按提交时间倒序的 ``RawItem`` 列表。
        """
        threshold = self.to_utc_datetime(since)
        items: list[RawItem] = []
        seen: set[str] = set()
        for query in self._queries:
            items.extend(await self._fetch_query(query, since, until=until, threshold=threshold, seen=seen))
            if self.limit_reached(len(seen)):
                break

        items.sort(key=lambda item: item.published_at or item.fetched_at, reverse=True)
        logger.info(
            f"arXiv 采集完成：命中 {len(items)} 条（queries={len(self._queries)}，since={since.isoformat()}）"
        )
        return items

    async def _fetch_query(
        self,
        query: str,
        since: datetime,
        *,
        until: datetime | None,
        threshold: datetime | None,
        seen: set[str],
    ) -> list[RawItem]:
        """按单条检索式分页抓取（跨检索式共享 ``seen`` 去重集合）。

        Args:
            query: 检索式。
            since: 增量起点（UTC）。
            until: 增量终点（UTC）；``None`` 表示不设上界。
            threshold: 客户端二次过滤的起点（``>=``）。
            seen: 已命中的 ``source_id`` 集合（原地更新）。

        Returns:
            本条检索式新增的 ``RawItem`` 列表。
        """
        collected: list[RawItem] = []
        offset = 0
        for _ in range(self.max_pages):
            xml_text = await self.fetch_page(since=since, offset=offset, until=until, query=query)
            entries = self.parse_entries(xml_text)
            added = 0
            for entry in entries:
                item = self.entry_to_raw_item(entry)
                if item.source_id in seen:
                    continue
                if threshold is not None and (item.published_at is None or item.published_at < threshold):
                    continue
                seen.add(item.source_id)
                added += 1
                collected.append(item)
            # 结果按 submittedDate 倒序：本页无新增（重复或已越过时间窗）即停止翻页
            if len(entries) < self.page_size or self.limit_reached(len(seen)) or added == 0:
                break
            offset += self.page_size
        return collected

    async def health_check(self) -> bool:
        """探活：请求 1 条结果并检查 HTTP 200。

        Returns:
            源可用返回 ``True``；任何异常均返回 ``False``（探活不得中断主流程）。
        """
        try:
            await self.limiter.acquire()
            response = await self.http.request(
                "GET", self.api_url, params={"search_query": "cat:cs.CR", "max_results": 1}
            )
        except Exception as exc:  # noqa: BLE001 - 探活需吞掉所有异常
            logger.warning(f"arXiv 探活失败：{exc!r}")
            return False
        return response.status_code == 200



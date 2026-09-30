"""OpenAlex 论文采集器（PROJECT_PLAN.md §5.4 P3 扩展源：AI 安全论文情报）。

数据源：OpenAlex REST API ``https://api.openalex.org/works``（JSON，无需鉴权）。

约定：
    - ``source_name = "openalex"``；
    - 默认检索 ``AI security``，可用构造参数覆盖；
    - **增量按 ``from_publication_date``**：``filter=from_publication_date:YYYY-MM-DD``，
      并在客户端再按发布时间过滤（双保险，便于离线夹具测试）；
    - ``source_id`` 使用 OpenAlex Work ID（``W2741809807`` 形式），DOI 写入 ``meta``；
    - 摘要在源侧为**倒排索引**（``abstract_inverted_index``），由 :func:`reconstruct_abstract`
      确定性还原为纯文本（不引入任何模型）；
    - 只存元数据与摘要、不存全文（§7 R10 版权合规）；
    - L1 采集层禁止 LLM（§0 约束 1）。
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, ClassVar

from aisec_intel.connectors.base import BaseConnector
from aisec_intel.connectors.registry import register
from aisec_intel.logging_config import get_logger
from aisec_intel.models.raw_item import RawItem

logger = get_logger(__name__)

OPENALEX_WORKS_URL: str = "https://api.openalex.org/works"
"""OpenAlex works 检索地址。"""

OPENALEX_SOURCE_NAME: str = "openalex"
"""源标识。"""

DEFAULT_SEARCH: str = "AI security"
"""默认检索词（AI 安全相关论文）。"""

DEFAULT_PER_PAGE: int = 100
"""单页条数（OpenAlex 上限 200）。"""

MAX_PAGES: int = 5
"""单次采集最多翻页数。"""


def reconstruct_abstract(inverted_index: dict[str, list[int]] | None) -> str:
    """把 OpenAlex 倒排摘要还原为纯文本（确定性纯函数）。

    Args:
        inverted_index: ``{"word": [position, ...], ...}``；``None`` / 空表示无摘要。

    Returns:
        按位置排序拼接的摘要文本；无摘要时返回空串。
    """
    if not inverted_index:
        return ""
    positioned: list[tuple[int, str]] = []
    for word, positions in inverted_index.items():
        for position in positions or []:
            positioned.append((int(position), str(word)))
    positioned.sort()
    return " ".join(word for _, word in positioned)


@register
class OpenAlexConnector(BaseConnector):
    """OpenAlex 采集器（JSON）。

    Attributes:
        api_url: 检索 API 地址（测试可覆盖）。
        per_page: 单页条数。
    """

    source_name: ClassVar[str] = OPENALEX_SOURCE_NAME
    rate_limit: ClassVar[str] = "10/1"
    timeout: ClassVar[float] = 60.0
    api_url: ClassVar[str] = OPENALEX_WORKS_URL
    per_page: ClassVar[int] = DEFAULT_PER_PAGE
    max_pages: ClassVar[int] = MAX_PAGES

    def __init__(
        self,
        *,
        search: str | None = None,
        extra_filter: str | None = None,
        mailto: str | None = None,
        per_page: int | None = None,
        max_results: int | None = None,
        **kwargs: Any,
    ) -> None:
        """初始化采集器。

        Args:
            search: 覆盖默认检索词。
            extra_filter: 追加过滤条件（OpenAlex 语法，逗号连接），如 ``type:article``。
            mailto: 联系邮箱（OpenAlex polite pool，可选）。
            per_page: 覆盖单页条数（1~200）。
            max_results: 单次采集条数上限（``configs/sources.yaml`` 的 ``max_results``），
                等价于基类的 ``max_records``。
            **kwargs: 透传给 :class:`BaseConnector`（``http`` / ``limiter`` / ``max_records``）。
        """
        if max_results is not None and max_results > 0:
            kwargs.setdefault("max_records", int(max_results))
        super().__init__(**kwargs)
        self._search = (search or DEFAULT_SEARCH).strip()
        self._extra_filter = (extra_filter or "").strip()
        self._mailto = (mailto or "").strip()
        if per_page is not None and per_page > 0:
            self.per_page = min(int(per_page), 200)

    @property
    def search(self) -> str:
        """当前检索词。"""
        return self._search

    @property
    def source_url(self) -> str:
        """源首页地址（``RawItem.url`` 的回退值）。"""
        return "https://openalex.org/works"

    def build_filter(self, since: datetime) -> str:
        """构造增量过滤条件。

        Args:
            since: 增量起点（UTC，含）。

        Returns:
            形如 ``from_publication_date:2024-01-01``（含追加过滤条件）。
        """
        parts = [f"from_publication_date:{since.strftime('%Y-%m-%d')}"]
        if self._extra_filter:
            parts.append(self._extra_filter)
        return ",".join(parts)

    async def fetch_page(self, *, since: datetime, page: int = 1) -> dict[str, Any]:
        """抓取一页 JSON（含限流）。

        Args:
            since: 增量起点（UTC）。
            page: 页码（从 1 开始）。

        Returns:
            OpenAlex 响应对象（含 ``meta`` / ``results``）。

        Raises:
            ValueError: 响应不是 JSON 对象（源侧结构变更）。
        """
        params: dict[str, Any] = {
            "search": self._search,
            "filter": self.build_filter(since),
            "per-page": self.per_page,
            "page": page,
            "sort": "publication_date:desc",
        }
        if self._mailto:
            params["mailto"] = self._mailto
        await self.limiter.acquire()
        payload = await self.http.get_json(self.api_url, params=params)
        if not isinstance(payload, dict):
            raise ValueError(f"OpenAlex 响应结构异常，期望 object，实际 {type(payload).__name__}")
        return payload

    def entry_to_raw_item(self, entry: dict[str, Any]) -> RawItem:
        """把单条 OpenAlex work 转换为 ``RawItem``。

        Args:
            entry: ``results`` 中的一条 work 对象。

        Returns:
            统一格式的 ``RawItem``（``source_id`` 为 OpenAlex Work ID）。

        Raises:
            ValueError: 条目缺少 ``id``（不能写入无主键数据）。
        """
        raw_id = str(entry.get("id") or "").strip()
        if not raw_id:
            raise ValueError(f"OpenAlex 条目缺少 id：{entry!r}")
        work_id = raw_id.rsplit("/", 1)[-1]
        doi = str(entry.get("doi") or "").strip()
        primary = entry.get("primary_location") if isinstance(entry.get("primary_location"), dict) else {}
        source = primary.get("source") if isinstance(primary.get("source"), dict) else {}
        authors = [
            str(auth.get("author", {}).get("display_name"))
            for auth in entry.get("authorships") or []
            if isinstance(auth, dict) and isinstance(auth.get("author"), dict) and auth["author"].get("display_name")
        ]
        topics = [
            str(topic.get("display_name"))
            for topic in (entry.get("topics") or entry.get("concepts") or [])
            if isinstance(topic, dict) and topic.get("display_name")
        ]
        abstract = reconstruct_abstract(entry.get("abstract_inverted_index"))
        keywords = [str(kw.get("display_name")) for kw in entry.get("keywords") or [] if isinstance(kw, dict)]
        url = str(primary.get("landing_page_url") or doi or raw_id)

        meta: dict[str, str] = {
            "doi": doi,
            "type": str(entry.get("type") or ""),
            "publication_year": str(entry.get("publication_year") or ""),
            "cited_by_count": str(entry.get("cited_by_count") or 0),
            "venue": str(source.get("display_name") or ""),
            "authors": ", ".join(authors),
            "open_access": str(bool(entry.get("open_access", {}).get("is_oa")))
            if isinstance(entry.get("open_access"), dict)
            else "False",
        }

        return self.build_raw_item(
            source_id=work_id,
            raw_text=self.raw_text_from_json(
                {
                    "openalex_id": work_id,
                    "doi": doi or None,
                    "title": entry.get("title") or entry.get("display_name"),
                    "abstract": abstract or None,
                    "publication_date": entry.get("publication_date"),
                    "publication_year": entry.get("publication_year"),
                    "type": entry.get("type"),
                    "authors": authors,
                    "topics": topics,
                    "keywords": keywords,
                    "cited_by_count": entry.get("cited_by_count"),
                    "referenced_works_count": entry.get("referenced_works_count"),
                    "venue": source.get("display_name"),
                    "landing_page_url": primary.get("landing_page_url"),
                    "pdf_url": primary.get("pdf_url"),
                }
            ),
            url=url,
            title=str(entry.get("title") or entry.get("display_name") or "") or None,
            published_at=self.to_utc_datetime(entry.get("publication_date")),
            lang=str(entry.get("language") or "") or None,
            meta=meta,
        )

    async def fetch_incremental(self, since: datetime) -> list[RawItem]:
        """抓取 ``publication_date >= since`` 的论文（分页 + 客户端二次过滤）。

        Args:
            since: 增量起点（UTC，含）；naive 时间按 UTC 处理。

        Returns:
            按发布时间倒序的 ``RawItem`` 列表。
        """
        threshold = self.to_utc_datetime(since)
        items: list[RawItem] = []
        seen: set[str] = set()
        for page in range(1, self.max_pages + 1):
            payload = await self.fetch_page(since=since, page=page)
            results = payload.get("results")
            if not isinstance(results, list):
                raise ValueError("OpenAlex 响应的 results 字段不是数组")
            added = 0
            for entry in results:
                if not isinstance(entry, dict):
                    logger.warning(f"跳过非对象条目：{type(entry).__name__}")
                    continue
                item = self.entry_to_raw_item(entry)
                if item.source_id in seen:
                    continue
                if threshold is not None and (item.published_at is None or item.published_at < threshold):
                    continue
                seen.add(item.source_id)
                added += 1
                items.append(item)
            # 结果按 publication_date 倒序：本页无新增（重复或已越过时间窗）即停止翻页
            if len(results) < self.per_page or self.limit_reached(len(items)) or added == 0:
                break

        items.sort(key=lambda item: item.published_at or item.fetched_at, reverse=True)
        logger.info(f"OpenAlex 采集完成：命中 {len(items)} 条（since={since.isoformat()}）")
        return items

    async def health_check(self) -> bool:
        """探活：请求 1 条结果并检查 HTTP 200。

        Returns:
            源可用返回 ``True``；任何异常均返回 ``False``（探活不得中断主流程）。
        """
        try:
            await self.limiter.acquire()
            response = await self.http.request(
                "GET", self.api_url, params={"search": self._search, "per-page": 1}
            )
        except Exception as exc:  # noqa: BLE001 - 探活需吞掉所有异常
            logger.warning(f"OpenAlex 探活失败：{exc!r}")
            return False
        return response.status_code == 200


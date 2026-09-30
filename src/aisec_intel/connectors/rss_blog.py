"""厂商 / 安全博客 RSS/Atom 采集器（PROJECT_PLAN.md §5.4 P3 扩展源：公告与博客情报）。

数据源：通用 **RSS 2.0 / Atom 1.0** 订阅（lxml 解析，复用 :mod:`aisec_intel.connectors.arxiv`
的 lxml 依赖与 XPath 命名空间手法）。

约定：
    - ``source_name = "rss_blog"``；``source_id`` 取 ``<feed>:<guid|id|link>``（跨源唯一）；
    - **增量按发布时间**：客户端按 ``published_at >= since`` 过滤（RSS 本身不支持时间过滤）；
    - **单 feed 失败不阻断整体**（异常隔离），错误写日志；
    - ``raw_text`` 只保存**标题 + 摘要**（不抓正文，§7 R10 版权合规）；
    - 关注 AI/ML 厂商与安全公告（:data:`RSS_BLOG_FEEDS`），feed 列表可由
      ``configs/sources.yaml`` 的 ``params.feeds`` 覆盖；
    - L1 采集层禁止 LLM（§0 约束 1）。

Note:
    2026-09-30 实测（本项目环境）：``cisa_alerts`` / ``pytorch`` 返回 **403**（厂商边缘防护），
    ``apache_security`` 官方 RSS 返回 **404**；故 :data:`DEFAULT_FEEDS` 默认使用实测可达的
    安全/AI 博客源，上述官方源仍登记在册（配置可随时启用，代码无需改动）。
"""

from __future__ import annotations

import email.utils
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from typing import Any, ClassVar

from lxml import etree

from aisec_intel.connectors.base import BaseConnector
from aisec_intel.connectors.registry import register
from aisec_intel.logging_config import get_logger
from aisec_intel.models.raw_item import RawItem
from aisec_intel.utils.hashing import sha256_text

logger = get_logger(__name__)

RSS_BLOG_SOURCE_NAME: str = "rss_blog"
"""源标识。"""

RSS_BLOG_FEEDS: dict[str, str] = {
    # —— 任务指定的官方公告源（本环境实测 403/404，登记在册、可配置启用）——
    "cisa_alerts": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "apache_security": "https://httpd.apache.org/security/vulnerabilities_24.rss",
    "pytorch": "https://pytorch.org/feed.xml",
    # —— 环境实测可达的补充源（安全与 AI 生态博客）——
    "github_security_blog": "https://github.blog/security/feed/",
    "huggingface_blog": "https://huggingface.co/blog/feed.xml",
    "sans_isc": "https://isc.sans.edu/rssfeed.xml",
    "cloudflare_security": "https://blog.cloudflare.com/tag/security/rss/",
}
"""feed 注册表：``名称 → 订阅地址``。"""

DEFAULT_FEEDS: tuple[str, ...] = ("github_security_blog", "huggingface_blog", "sans_isc", "cisa_alerts")
"""默认采集的 feed（实测可达源 + 一个官方源，官方源失败仅记日志）。"""

ATOM_NS: str = "http://www.w3.org/2005/Atom"
"""Atom 命名空间。"""

DEFAULT_MAX_ITEMS_PER_FEED: int = 20
"""单 feed 单次采集条数上限。"""

MAX_SOURCE_ID_LENGTH: int = 64
"""``raw_item.source_id`` 的数据库上限（``VARCHAR(64)``）。"""


def build_source_id(feed: str, identifier: str) -> str:
    """构造稳定且不超长的 ``source_id``（纯函数）。

    规则：``"<feed>:<原文 ID>"``；超过 :data:`MAX_SOURCE_ID_LENGTH` 时改用
    ``"<feed>:<sha256(identifier)[:20]>"``（确定性哈希，跨次采集稳定）。

    Args:
        feed: feed 名称。
        identifier: 源内 ID（guid / id / 链接）。

    Returns:
        长度 ≤ :data:`MAX_SOURCE_ID_LENGTH` 的 ``source_id``。
    """
    candidate = f"{feed}:{identifier.strip()}"
    if len(candidate) <= MAX_SOURCE_ID_LENGTH:
        return candidate
    return f"{feed}:{sha256_text(identifier.strip())[:20]}"

DEFAULT_USER_AGENT: str = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0 Safari/537.36 aisec-intel/0.1"
)
"""浏览器风格 UA：部分厂商站点（Cloudflare/Akamai）会拒绝默认 UA。"""


def _squash(text: str | None) -> str:
    """压缩空白（feed 标题与摘要常含换行缩进）。"""
    return " ".join((text or "").split())


def parse_feed_date(value: Any) -> datetime | None:
    """解析 feed 日期（RSS 用 RFC 822，Atom 用 ISO 8601，纯函数）。

    Args:
        value: 日期字符串（``Tue, 02 Apr 2024 10:00:00 GMT`` / ``2024-05-01T00:00:00Z``）。

    Returns:
        UTC ``datetime``；无法解析时返回 ``None``。

    Note:
        RSS 2.0 的 ``pubDate`` 为 RFC 822 格式，L2 的 :func:`~aisec_intel.normalize.datetime_utils.parse_datetime`
        面向 ISO 8601（NVD/GHSA/OSV 口径），故在**源边界**做一次 RFC 822 兼容转换
        （``email.utils.parsedate_to_datetime``，标准库实现）。
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        parsed = email.utils.parsedate_to_datetime(text)
    except (TypeError, ValueError):
        return None
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def parse_feed(xml_text: str) -> list[dict[str, Any]]:
    """解析 RSS 2.0 / Atom 1.0 文档为条目列表（纯函数，无网络）。

    Args:
        xml_text: feed 原文。

    Returns:
        条目列表；每项含 ``id`` / ``title`` / ``link`` / ``published`` / ``summary``。

    Raises:
        ValueError: XML 非法。
    """
    try:
        root = etree.fromstring(xml_text.encode("utf-8") if isinstance(xml_text, str) else xml_text)
    except etree.XMLSyntaxError as exc:
        raise ValueError(f"feed XML 解析失败：{exc}") from exc

    tag = etree.QName(root).localname.lower()
    if tag == "feed":
        entries = root.findall(f"{{{ATOM_NS}}}entry")
        return [_parse_atom_entry(entry) for entry in entries]
    items = root.findall("./channel/item")
    return [_parse_rss_item(item) for item in items]


def _text(node: etree._Element | None) -> str | None:
    """取元素文本（压缩空白）。"""
    if node is None or node.text is None:
        return None
    return " ".join(node.text.split())


def _parse_rss_item(item: etree._Element) -> dict[str, Any]:
    """解析 RSS 2.0 ``<item>``。"""
    return {
        "id": _text(item.find("guid")) or _text(item.find("link")),
        "title": _text(item.find("title")),
        "link": _text(item.find("link")),
        "published": _text(item.find("pubDate")) or _text(item.find("{http://purl.org/dc/elements/1.1/}date")),
        "summary": _text(item.find("description")),
    }


def _parse_atom_entry(entry: etree._Element) -> dict[str, Any]:
    """解析 Atom 1.0 ``<entry>``。"""
    link = None
    for node in entry.findall(f"{{{ATOM_NS}}}link"):
        rel = node.get("rel") or "alternate"
        if rel == "alternate" and node.get("href"):
            link = node.get("href")
            break
    if link is None:
        link = next((n.get("href") for n in entry.findall(f"{{{ATOM_NS}}}link") if n.get("href")), None)
    return {
        "id": _text(entry.find(f"{{{ATOM_NS}}}id")) or link,
        "title": _text(entry.find(f"{{{ATOM_NS}}}title")),
        "link": link,
        "published": _text(entry.find(f"{{{ATOM_NS}}}published")) or _text(entry.find(f"{{{ATOM_NS}}}updated")),
        "summary": _text(entry.find(f"{{{ATOM_NS}}}summary")) or _text(entry.find(f"{{{ATOM_NS}}}content")),
    }


@register
class RssBlogConnector(BaseConnector):
    """通用 RSS/Atom 博客与公告采集器。

    Attributes:
        feeds: 本次采集的 ``(名称, 地址)`` 列表。
        max_items_per_feed: 单 feed 条数上限。
    """

    source_name: ClassVar[str] = RSS_BLOG_SOURCE_NAME
    rate_limit: ClassVar[str] = "10/1"
    timeout: ClassVar[float] = 45.0
    user_agent: ClassVar[str] = DEFAULT_USER_AGENT

    def __init__(
        self,
        *,
        feeds: Sequence[str] | None = None,
        feed_urls: dict[str, str] | None = None,
        max_items_per_feed: int = DEFAULT_MAX_ITEMS_PER_FEED,
        **kwargs: Any,
    ) -> None:
        """初始化采集器。

        Args:
            feeds: 要采集的 feed 名称列表；``None`` 时用 :data:`DEFAULT_FEEDS`。
            feed_urls: 覆盖 :data:`RSS_BLOG_FEEDS`（可新增自定义 feed）。
            max_items_per_feed: 单 feed 条数上限。
            **kwargs: 透传给 :class:`BaseConnector`（``http`` / ``limiter`` / ``max_records``）。
        """
        super().__init__(**kwargs)
        registry = {**RSS_BLOG_FEEDS, **(feed_urls or {})}
        names = tuple(feeds) if feeds else DEFAULT_FEEDS
        self._feeds: list[tuple[str, str]] = [(name, registry[name]) for name in names if name in registry]
        unknown = [name for name in names if name not in registry]
        if unknown:
            logger.warning(f"rss_blog 忽略未注册的 feed：{unknown}")
        self._max_items_per_feed = max(1, max_items_per_feed)

    @property
    def feeds(self) -> list[tuple[str, str]]:
        """本次采集的 ``(名称, 地址)`` 列表。"""
        return list(self._feeds)

    @property
    def source_url(self) -> str:
        """源首页地址。"""
        return next((url for name, url in self._feeds if name == "github_security_blog"), "https://github.blog/")

    def entry_to_raw_item(self, entry: dict[str, Any], *, feed: str) -> RawItem | None:
        """把解析出的条目转换为 ``RawItem``。

        Args:
            entry: :func:`parse_feed` 产出的条目。
            feed: feed 名称（写入 ``meta``）。

        Returns:
            ``RawItem``；条目缺少链接与标题时返回 ``None``（跳过该条）。
        """
        link = str(entry.get("link") or "").strip()
        title = str(entry.get("title") or "").strip()
        if not link and not title:
            return None
        identifier = str(entry.get("id") or link or title).strip()
        return self.build_raw_item(
            source_id=build_source_id(feed, identifier),
            raw_text=self.raw_text_from_json(
                {"feed": feed, "title": title or None, "link": link or None, "summary": entry.get("summary")}
            ),
            url=link or self.source_url,
            title=title or None,
            published_at=parse_feed_date(entry.get("published")) or self.to_utc_datetime(entry.get("published")),
            lang="en",
            meta={"feed": feed, "source_type": "blog", "summary_len": str(len(entry.get("summary") or ""))},
        )

    async def fetch_feed(self, name: str, url: str) -> list[RawItem]:
        """抓取并解析单个 feed（失败显式抛出，由调用方隔离）。

        Args:
            name: feed 名称。
            url: feed 地址。

        Returns:
            ``RawItem`` 列表（按源顺序）。

        Raises:
            Exception: 网络 / 解析失败。
        """
        await self.limiter.acquire()
        response = await self.http.request("GET", url)
        entries = parse_feed(response.text)
        items = [item for entry in entries if (item := self.entry_to_raw_item(entry, feed=name)) is not None]
        logger.info(f"rss_blog {name}：条目 {len(entries)} 条，有效 {len(items)} 条")
        return items[: self._max_items_per_feed]

    async def fetch_incremental(self, since: datetime) -> list[RawItem]:
        """采集全部配置 feed 中 ``published_at >= since`` 的条目。

        Args:
            since: 增量起点（UTC，含）。

        Returns:
            按发布时间倒序的 ``RawItem`` 列表（单 feed 失败仅记日志）。
        """
        threshold = self.to_utc_datetime(since)
        items: list[RawItem] = []
        for name, url in self._feeds:
            try:
                fetched = await self.fetch_feed(name, url)
            except Exception as exc:  # noqa: BLE001 - 单 feed 失败不阻断整体
                logger.warning(f"rss_blog {name} 采集失败（{type(exc).__name__}: {exc}）")
                continue
            for item in fetched:
                if threshold is not None and (item.published_at is None or item.published_at < threshold):
                    continue
                items.append(item)
            if self.limit_reached(len(items)):
                logger.info(f"rss_blog 达到条数上限（{self.max_records}），提前结束")
                break

        items.sort(key=lambda item: item.published_at or item.fetched_at, reverse=True)
        logger.info(f"rss_blog 采集完成：命中 {len(items)} 条（since={since.isoformat()}）")
        return items

    async def health_check(self) -> bool:
        """探活：逐个 feed 取一条，任一成功即视为可用。

        Returns:
            至少一个 feed 可用返回 ``True``。
        """
        for name, url in self._feeds:
            try:
                await self.limiter.acquire()
                response = await self.http.request("GET", url)
            except Exception as exc:  # noqa: BLE001 - 探活需吞掉所有异常
                logger.warning(f"rss_blog {name} 探活失败：{exc!r}")
                continue
            if response.status_code == 200 and parse_feed(response.text):
                logger.info(f"rss_blog 探活成功：{name}")
                return True
        return False


def iter_feed_names() -> Iterable[str]:
    """返回已注册的 feed 名称（供 CLI / 文档展示）。

    Returns:
        feed 名称的可迭代对象。
    """
    return tuple(RSS_BLOG_FEEDS)

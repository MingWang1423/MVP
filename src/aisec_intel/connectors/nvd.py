"""NVD API 2.0 采集器（PROJECT_PLAN.md §5.3 / §5.4）。

数据源：``GET https://services.nvd.nist.gov/rest/json/cves/2.0``。

要点：
    - **增量**：``lastModStartDate`` / ``lastModEndDate``（RFC3339）。NVD 规定单次查询窗口
      **最大 120 天**，因此 :meth:`fetch_incremental` 会把 ``since → now`` 自动切分为多个窗口；
    - **分页**：``resultsPerPage``（最大 2000）+ ``startIndex`` 循环，直到取满 ``totalResults``；
    - **限流**：``RateLimiter.for_source("nvd")`` 自动按是否配置 ``NVD_API_KEY`` 选择
      ``5/30``（无 Key）或 ``50/30``（有 Key）；有 Key 时请求头带 ``apiKey``；
    - **提前止损**：``max_records`` 达到即停止翻页（配合 ``run_collect --limit``）；
    - L1 采集层禁止 LLM（§0 约束 1）。
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar

from aisec_intel.connectors.base import BaseConnector
from aisec_intel.connectors.registry import register
from aisec_intel.logging_config import get_logger
from aisec_intel.models.raw_item import RawItem

logger = get_logger(__name__)

NVD_SOURCE_NAME: str = "nvd"
"""源标识。"""

NVD_API_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
"""NVD CVE API 2.0 端点。"""

NVD_DETAIL_URL_TEMPLATE: str = "https://nvd.nist.gov/vuln/detail/{cve_id}"
"""CVE 详情页模板（``RawItem.url``）。"""

HEALTH_CHECK_CVE_ID: str = "CVE-2021-44228"
"""探活用的长期存在 CVE（Log4Shell）。"""

MAX_WINDOW_DAYS: int = 120
"""NVD 单次查询允许的最大时间窗（天）。"""

DEFAULT_PAGE_SIZE: int = 2000
"""单页条数（NVD 上限）。"""

DEFAULT_MAX_PAGES: int = 10
"""单个窗口的最大翻页数（保护 API 配额）。"""


@register
class NvdConnector(BaseConnector):
    """NVD API 2.0 采集器。

    Attributes:
        api_url: API 端点（测试可覆盖）。
        window_days: 时间窗切片长度（天，≤120）。
    """

    source_name: ClassVar[str] = NVD_SOURCE_NAME
    rate_limit: ClassVar[str] = "5/30"
    timeout: ClassVar[float] = 60.0
    api_url: ClassVar[str] = NVD_API_URL
    window_days: ClassVar[int] = MAX_WINDOW_DAYS

    def __init__(
        self,
        *,
        api_key: str | None = None,
        page_size: int = DEFAULT_PAGE_SIZE,
        max_pages: int = DEFAULT_MAX_PAGES,
        **kwargs: Any,
    ) -> None:
        """初始化采集器。

        Args:
            api_key: NVD API Key（``None`` 时读取 ``Settings.nvd_api_key``）。
            page_size: 单页条数（NVD 上限 2000）。
            max_pages: 单个时间窗的最大翻页数。
            **kwargs: 透传给 :class:`BaseConnector`（``http``/``limiter``/``settings``/``max_records``）。
        """
        super().__init__(**kwargs)
        self._api_key = (api_key if api_key is not None else self.settings.nvd_api_key.get_secret_value()).strip()
        self._page_size = min(max(1, page_size), DEFAULT_PAGE_SIZE)
        self._max_pages = max(1, max_pages)

    @property
    def has_api_key(self) -> bool:
        """是否配置了 API Key（决定限流档位）。"""
        return bool(self._api_key and self._api_key.isascii())

    @property
    def enabled(self) -> bool:
        """NVD 无 Key 也可采集（限流更严格），故恒为启用。"""
        return True

    @property
    def page_size(self) -> int:
        """单页条数。"""
        return self._page_size

    @property
    def source_url(self) -> str:
        """源首页地址（``RawItem.url`` 的回退值）。"""
        return "https://nvd.nist.gov/"

    def _headers(self) -> dict[str, str]:
        """构造请求头（仅有 Key 时附带 ``apiKey``）。"""
        return {"apiKey": self._api_key} if self.has_api_key else {}

    @staticmethod
    def format_window(moment: datetime) -> str:
        """把时间格式化为 NVD 接受的 RFC3339 字符串（UTC）。

        Args:
            moment: 任意时间。

        Returns:
            形如 ``2024-01-01T00:00:00.000Z`` 的字符串。
        """
        normalized = moment if moment.tzinfo is not None else moment.replace(tzinfo=UTC)
        return normalized.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    def split_windows(self, since: datetime, until: datetime) -> list[tuple[datetime, datetime]]:
        """把 ``since → until`` 切分为不超过 ``window_days`` 的窗口列表。

        Args:
            since: 起点（UTC）。
            until: 终点（UTC）。

        Returns:
            ``[(start, end), ...]``（按时间升序；``since >= until`` 时返回空列表）。
        """
        span = timedelta(days=self.window_days)
        windows: list[tuple[datetime, datetime]] = []
        cursor = since
        while cursor < until:
            end = min(cursor + span, until)
            windows.append((cursor, end))
            cursor = end
        return windows

    async def fetch_page(
        self,
        *,
        window_start: datetime,
        window_end: datetime,
        start_index: int = 0,
        cve_id: str | None = None,
    ) -> dict[str, Any]:
        """拉取一页数据（含限流）。

        Args:
            window_start: 窗口起点（UTC）。
            window_end: 窗口终点（UTC）。
            start_index: 起始偏移。
            cve_id: 指定单个 CVE（探活/单条采集用），提供时不带时间窗参数。

        Returns:
            NVD 响应对象。

        Raises:
            ValueError: 响应结构异常。
        """
        params: dict[str, Any] = {"resultsPerPage": self._page_size, "startIndex": start_index}
        if cve_id:
            params["cveId"] = cve_id
        else:
            params["lastModStartDate"] = self.format_window(window_start)
            params["lastModEndDate"] = self.format_window(window_end)

        await self.limiter.acquire()
        payload = await self.http.get_json(self.api_url, params=params, headers=self._headers())
        if not isinstance(payload, dict):
            raise ValueError(f"NVD 响应结构异常（期望 object）：{type(payload).__name__}")
        return payload


    def vuln_to_raw_item(self, entry: dict[str, Any]) -> RawItem:
        """把 NVD 条目转换为 ``RawItem``。

        Args:
            entry: 形如 ``{"cve": {"id": "CVE-...", "descriptions": [...], ...}}``。

        Returns:
            统一格式的 ``RawItem``。

        Raises:
            ValueError: 条目缺少 ``cve.id``。
        """
        cve = entry.get("cve") if isinstance(entry.get("cve"), dict) else entry
        cve_id = str(cve.get("id") or "").strip().upper()
        if not cve_id:
            raise ValueError(f"NVD 条目缺少 cve.id：{entry!r}")

        metrics = cve.get("metrics") or {}
        severity = ""
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            for item in metrics.get(key) or []:
                data = item.get("cvssData") if isinstance(item, dict) else None
                if isinstance(data, dict):
                    severity = str(data.get("baseSeverity") or item.get("baseSeverity") or severity)
                    break
            if severity:
                break

        return self.build_raw_item(
            source_id=cve_id,
            raw_text=self.raw_text_from_json(entry),
            url=NVD_DETAIL_URL_TEMPLATE.format(cve_id=cve_id),
            title=None,
            published_at=self.to_utc_datetime(cve.get("published")),
            lang="en",
            meta={
                "status": str(cve.get("vulnStatus") or ""),
                "severity": severity,
                "last_modified": str(cve.get("lastModified") or ""),
            },
        )

    async def fetch_incremental(self, since: datetime) -> list[RawItem]:
        """按 ``lastModStartDate/lastModEndDate`` 增量拉取（自动切分 120 天窗口 + 分页）。

        Args:
            since: 增量起点（UTC，含）。

        Returns:
            按发布时间倒序排列的 ``RawItem`` 列表（跨窗口去重）。

        Raises:
            ValueError: 响应缺少 ``vulnerabilities`` 数组。
        """
        threshold = self.to_utc_datetime(since) or datetime.now(UTC) - timedelta(days=7)
        until = datetime.now(UTC)
        windows = self.split_windows(threshold, until)
        items: list[RawItem] = []
        seen: set[str] = set()

        for window_start, window_end in windows:
            for page in range(self._max_pages):
                payload = await self.fetch_page(
                    window_start=window_start,
                    window_end=window_end,
                    start_index=page * self._page_size,
                )
                entries = payload.get("vulnerabilities") or []
                if not isinstance(entries, list):
                    raise ValueError("NVD 响应的 vulnerabilities 字段不是数组")
                if not entries:
                    break

                for entry in entries:
                    if not isinstance(entry, dict):
                        continue
                    cve = entry.get("cve") if isinstance(entry.get("cve"), dict) else entry
                    cve_id = str(cve.get("id") or "").strip().upper()
                    if not cve_id or cve_id in seen:
                        continue
                    seen.add(cve_id)
                    items.append(self.vuln_to_raw_item(entry))

                total = int(payload.get("totalResults") or 0)
                fetched_so_far = (page + 1) * self._page_size
                logger.info(
                    f"NVD 窗口 {self.format_window(window_start)}~{self.format_window(window_end)} "
                    f"第 {page + 1} 页：本页={len(entries)} 累计={len(items)}/{total}"
                )
                if fetched_so_far >= total or len(entries) < self._page_size or self.limit_reached(len(items)):
                    break
            if self.limit_reached(len(items)):
                logger.info(f"NVD 已达 max_records={self.max_records}，提前停止采集")
                break

        items.sort(key=lambda item: item.published_at or item.fetched_at, reverse=True)
        logger.info(f"NVD 采集完成：命中={len(items)}（since={threshold.isoformat()}，窗口数={len(windows)}）")
        return items

    async def health_check(self) -> bool:
        """探活：按 ``cveId`` 查询一条已知 CVE，检查 HTTP 200。

        Returns:
            可用返回 ``True``；任何异常返回 ``False``。
        """
        try:
            payload = await self.fetch_page(
                window_start=datetime.now(UTC) - timedelta(days=1),
                window_end=datetime.now(UTC),
                cve_id=HEALTH_CHECK_CVE_ID,
            )
        except Exception as exc:  # noqa: BLE001 - 探活需吞掉所有异常
            logger.warning(f"NVD 探活失败：{exc!r}")
            return False
        return bool(payload.get("vulnerabilities") is not None)

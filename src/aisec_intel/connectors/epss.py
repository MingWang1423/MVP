"""FIRST EPSS 采集器（PROJECT_PLAN.md §5.3 / §5.4）。

数据源：``GET https://api.first.org/data/v1/epss``（无需鉴权），返回 JSON：

```json
{"status": "OK", "data": [{"cve": "CVE-2024-3400", "epss": "0.97432",
                           "percentile": "0.99912", "date": "2024-04-15"}]}
```

约定：
    - ``source_name = "epss"``；``source_id`` 使用 ``cve``；
    - ``published_at`` 取 EPSS **模型日期**（``row.date``），增量即按该日期过滤；
    - 支持两种取数方式：① 按 ``since.date()`` 取某日快照；② 指定 ``cve_ids`` 精确查询；
    - L1 采集层禁止 LLM（§0 约束 1）。
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Any, ClassVar

from aisec_intel.connectors.base import BaseConnector
from aisec_intel.connectors.http_client import HttpStatusError
from aisec_intel.connectors.registry import register
from aisec_intel.logging_config import get_logger
from aisec_intel.models.raw_item import RawItem

logger = get_logger(__name__)

EPSS_SOURCE_NAME: str = "epss"
"""源标识。"""

EPSS_API_URL: str = "https://api.first.org/data/v1/epss"
"""EPSS 数据接口。"""

EPSS_VULN_URL_TEMPLATE: str = "https://api.first.org/data/v1/epss?cve={cve_id}"
"""单 CVE 查询地址（亦用于探活）。"""

EPSS_DOC_URL: str = "https://www.first.org/epss/"
"""EPSS 说明页（``RawItem.url`` 回退值）。"""

HEALTH_CHECK_CVE_ID: str = "CVE-2021-44228"
"""探活用的长期存在 CVE（Log4Shell）。"""

DEFAULT_PAGE_LIMIT: int = 100
"""单次请求返回上限（保守取值以节省带宽）。"""


@register
class EpssConnector(BaseConnector):
    """FIRST EPSS 采集器。

    Attributes:
        page_limit: 单次请求条数上限。
        api_url: 数据接口地址（测试可覆盖）。
    """

    source_name: ClassVar[str] = EPSS_SOURCE_NAME
    rate_limit: ClassVar[str] = "10/1"
    timeout: ClassVar[float] = 60.0
    api_url: ClassVar[str] = EPSS_API_URL

    def __init__(
        self,
        *,
        cve_ids: Sequence[str] | None = None,
        page_limit: int | None = None,
        model_date: str | None = None,
        **kwargs: Any,
    ) -> None:
        """初始化采集器。

        Args:
            cve_ids: 指定 CVE 清单（精确查询模式）；``None`` 时按日期取快照。
            page_limit: 单次请求条数上限；``None`` 时使用 ``DEFAULT_PAGE_LIMIT``。
            model_date: 显式指定 EPSS 快照日期（``YYYY-MM-DD``）；``None`` 时取最新快照。
            **kwargs: 透传给 :class:`BaseConnector`。
        """
        super().__init__(**kwargs)
        self._cve_ids: list[str] = [item.strip().upper() for item in (cve_ids or []) if item.strip()]
        self._page_limit = int(page_limit) if page_limit else DEFAULT_PAGE_LIMIT
        self._model_date = (model_date or "").strip() or None

    @property
    def model_date(self) -> str | None:
        """显式指定的 EPSS 快照日期（``None`` 表示取最新）。"""
        return self._model_date

    @property
    def cve_ids(self) -> list[str]:
        """精确查询模式下的 CVE 清单。"""
        return list(self._cve_ids)

    @property
    def page_limit(self) -> int:
        """单次请求条数上限。"""
        return self._page_limit

    @property
    def source_url(self) -> str:
        """源首页地址（``RawItem.url`` 的回退值）。"""
        return EPSS_DOC_URL

    async def fetch_scores(self, *, since: datetime | None = None) -> list[dict[str, Any]]:
        """拉取 EPSS 评分行（含限流）。

        Note:
            **不按服务端 ``date`` 参数取数**：EPSS 当日快照常在 UTC 午后发布，
            传当日 ``date`` 会返回 HTTP 422（``listNoResults``）。因此默认取「最新快照」，
            再由 :meth:`fetch_incremental` 在客户端按 ``row.date >= since.date()`` 过滤；
            如需指定快照日期，请使用 ``model_date`` 构造参数。

        Args:
            since: 增量起点（仅用于日志与返回值语义，不参与请求参数）。

        Returns:
            EPSS 数据行列表；源侧返回「无数据」（422）时返回空列表。
        """
        params: dict[str, Any] = {"limit": self._page_limit}
        if self._cve_ids:
            params["cve"] = ",".join(self._cve_ids)
        elif self._model_date:
            params["date"] = self._model_date

        await self.limiter.acquire()
        try:
            payload = await self.http.get_json(self.api_url, params=params)
        except HttpStatusError as exc:
            if exc.status_code == 422:
                logger.warning("EPSS 返回 422（listNoResults）：该日期/条件无数据，按空结果处理")
                return []
            raise
        if not isinstance(payload, dict):
            raise ValueError(f"EPSS 响应结构异常（期望 object）：{type(payload).__name__}")
        data = payload.get("data") or []
        if not isinstance(data, list):
            raise ValueError("EPSS 响应的 data 字段不是数组")
        return [row for row in data if isinstance(row, dict)]


    def row_to_raw_item(self, row: dict[str, Any]) -> RawItem:
        """把单行 EPSS 数据转换为 ``RawItem``。

        Args:
            row: 形如 ``{"cve": ..., "epss": ..., "percentile": ..., "date": ...}``。

        Returns:
            统一格式的 ``RawItem``。

        Raises:
            ValueError: 行内缺少 ``cve``。
        """
        cve_id = str(row.get("cve") or "").strip().upper()
        if not cve_id:
            raise ValueError(f"EPSS 行缺少 cve：{row!r}")

        return self.build_raw_item(
            source_id=cve_id,
            raw_text=self.raw_text_from_json(row),
            url=EPSS_VULN_URL_TEMPLATE.format(cve_id=cve_id),
            title=f"EPSS score for {cve_id}",
            published_at=self.to_utc_datetime(row.get("date")),
            lang="en",
            meta={
                "epss": str(row.get("epss") or ""),
                "percentile": str(row.get("percentile") or ""),
                "model_date": str(row.get("date") or ""),
            },
        )

    async def fetch_incremental(self, since: datetime) -> list[RawItem]:
        """拉取 ``date >= since.date()`` 的 EPSS 评分行。

        Args:
            since: 增量起点（UTC）。

        Returns:
            按 CVE 升序排列的 ``RawItem`` 列表。
        """
        threshold = self.to_utc_datetime(since)
        threshold_date = threshold.date() if threshold is not None else None
        rows = await self.fetch_scores(since=threshold)
        items: list[RawItem] = []
        for row in rows:
            row_date = self.to_utc_datetime(row.get("date"))
            if threshold_date is not None and row_date is not None and row_date.date() < threshold_date:
                continue
            items.append(self.row_to_raw_item(row))
        items.sort(key=lambda item: item.source_id)
        logger.info(f"EPSS 采集完成：命中={len(items)}（since={since.isoformat()}）")
        return items

    async def health_check(self) -> bool:
        """探活：查询一个长期存在的 CVE，检查 HTTP 200。

        Returns:
            可用返回 ``True``；任何异常返回 ``False``。
        """
        try:
            await self.limiter.acquire()
            response = await self.http.request("GET", EPSS_VULN_URL_TEMPLATE.format(cve_id=HEALTH_CHECK_CVE_ID))
        except Exception as exc:  # noqa: BLE001 - 探活需吞掉所有异常
            logger.warning(f"EPSS 探活失败：{exc!r}")
            return False
        return response.status_code == 200

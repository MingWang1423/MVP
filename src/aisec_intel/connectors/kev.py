"""CISA KEV 采集器（PROJECT_PLAN.md §5.3 P2）。

数据源：CISA「Known Exploited Vulnerabilities Catalog」全量 JSON。
本采集器是**第一个真实源**，用于打通「采集 → 指纹去重 → 入库」链路。

约定：
    - ``source_name = "kev"``；
    - ``source_id`` 使用 ``cveID``（同一 CVE 更新时会因 ``raw_text`` 变化而产生新指纹，
      形成可审计的历史版本；``raw_repo`` 以 ``sha256`` 幂等）；
    - ``raw_text`` 保存**条目级保真 JSON**（而非整份目录），便于按条回溯；
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

KEV_SOURCE_NAME: str = "kev"
"""源标识。"""

KEV_CATALOG_URL: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
"""CISA KEV 全量目录 URL。"""

NVD_DETAIL_URL_TEMPLATE: str = "https://nvd.nist.gov/vuln/detail/{cve_id}"
"""CVE 详情页模板（作为 ``RawItem.url``，便于引用回溯）。"""

KEV_META_KEYS: tuple[str, ...] = (
    "vendorProject",
    "product",
    "requiredAction",
    "dueDate",
    "knownRansomwareCampaignUse",
    "shortDescription",
    "notes",
    "cwes",
)
"""除 ``cveID`` / ``vulnerabilityName`` / ``dateAdded`` 外写入 ``meta`` 的字段。"""


@register
class KevConnector(BaseConnector):
    """CISA KEV 采集器。

    Attributes:
        catalog_url: KEV 目录地址（子类/测试可覆盖为 fixture 地址）。
    """

    source_name: ClassVar[str] = KEV_SOURCE_NAME
    rate_limit: ClassVar[str] = "10/1"
    timeout: ClassVar[float] = 60.0
    catalog_url: ClassVar[str] = KEV_CATALOG_URL

    @property
    def source_url(self) -> str:
        """源首页地址（``RawItem.url`` 的回退值）。"""
        return self.catalog_url

    async def fetch_catalog(self) -> dict[str, Any]:
        """拉取 KEV 全量 JSON（含限流）。

        Returns:
            KEV 目录对象，形如 ``{"title": ..., "vulnerabilities": [...]}``。

        Raises:
            ValueError: 响应不是 JSON 对象（源侧结构变更）。
        """
        await self.limiter.acquire()
        payload = await self.http.get_json(self.catalog_url)
        if not isinstance(payload, dict):
            raise ValueError(f"KEV 目录结构异常，期望 object，实际 {type(payload).__name__}")
        return payload

    def entry_to_raw_item(self, entry: dict[str, Any]) -> RawItem:
        """把单条 KEV 条目转换为 ``RawItem``。

        Args:
            entry: KEV 目录中的一条漏洞记录。

        Returns:
            统一格式的 ``RawItem``（``source_id`` 为 ``cveID``）。

        Raises:
            ValueError: 条目缺少 ``cveID``。
        """
        cve_id = str(entry.get("cveID") or "").strip()
        if not cve_id:
            raise ValueError(f"KEV 条目缺少 cveID：{entry!r}")

        meta: dict[str, str] = {key: _to_meta(entry.get(key)) for key in KEV_META_KEYS if entry.get(key) is not None}
        meta["dateAdded"] = str(entry.get("dateAdded") or "")

        return self.build_raw_item(
            source_id=cve_id,
            raw_text=self.raw_text_from_json(entry),
            url=NVD_DETAIL_URL_TEMPLATE.format(cve_id=cve_id),
            title=str(entry.get("vulnerabilityName") or "") or None,
            published_at=self.to_utc_datetime(entry.get("dateAdded")),
            lang="en",
            meta=meta,
        )

    async def fetch_incremental(self, since: datetime) -> list[RawItem]:
        """拉取 ``dateAdded >= since`` 的 KEV 条目。

        Args:
            since: 增量起点（UTC，含）；naive 时间按 UTC 处理。

        Returns:
            按 ``dateAdded`` 倒序排列的 ``RawItem`` 列表。

        Raises:
            ValueError: 目录中 ``vulnerabilities`` 字段类型异常。
        """
        threshold = self.to_utc_datetime(since)
        catalog = await self.fetch_catalog()
        raw_entries = catalog.get("vulnerabilities", [])
        if not isinstance(raw_entries, list):
            raise ValueError("KEV 目录的 vulnerabilities 字段不是数组")

        items: list[RawItem] = []
        for entry in raw_entries:
            if not isinstance(entry, dict):
                logger.warning(f"跳过非对象条目：{type(entry).__name__}")
                continue
            added = self.to_utc_datetime(entry.get("dateAdded"))
            if added is None or (threshold is not None and added < threshold):
                continue
            items.append(self.entry_to_raw_item(entry))

        items.sort(key=lambda item: item.published_at or item.fetched_at, reverse=True)
        logger.info(f"KEV 采集完成：命中 {len(items)} 条（since={since.isoformat()}）")
        return items

    async def health_check(self) -> bool:
        """探活：GET KEV 目录并检查 HTTP 200。

        Returns:
            源可用返回 ``True``；任何异常均返回 ``False``（探活不得中断主流程）。
        """
        try:
            await self.limiter.acquire()
            response = await self.http.request("GET", self.catalog_url)
        except Exception as exc:  # noqa: BLE001 - 探活需吞掉所有异常
            logger.warning(f"KEV 探活失败：{exc!r}")
            return False
        return response.status_code == 200


def _to_meta(value: Any) -> str:
    """把 KEV 字段值扁平化为 ``meta`` 可接受的字符串。"""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return ", ".join(str(item) for item in value)
    return str(value)

"""OSV.dev 采集器（PROJECT_PLAN.md §5.3 / §5.4）。

数据源：``POST https://api.osv.dev/v1/query``（按包查询，无需鉴权）。
覆盖范围：PyPI / npm / Go 等生态的**带修复版本**漏洞情报，是 NVD 之外的“主力补充源”。

约定：
    - ``source_name = "osv"``；``source_id`` 使用 OSV 的 ``id``（如 ``GHSA-xxxx`` / ``PYSEC-xxxx``）；
    - 监听包清单来自 ``Settings.watchlist``（``AI_PACKAGE_WATCHLIST``，默认 vllm/ollama/transformers/langchain/torch）；
    - 增量口径：按 ``vuln.modified``（缺失时回退 ``published``）与 ``since`` 比较；
    - L1 采集层禁止 LLM（§0 约束 1）。
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Any, ClassVar

from aisec_intel.connectors.base import BaseConnector
from aisec_intel.connectors.registry import register
from aisec_intel.logging_config import get_logger
from aisec_intel.models.raw_item import RawItem

logger = get_logger(__name__)

OSV_SOURCE_NAME: str = "osv"
"""源标识。"""

OSV_QUERY_URL: str = "https://api.osv.dev/v1/query"
"""按包查询接口（POST）。"""

OSV_VULN_URL_TEMPLATE: str = "https://api.osv.dev/v1/vulns/{vuln_id}"
"""单条漏洞接口（GET），亦用于探活。"""

OSV_DETAIL_URL_TEMPLATE: str = "https://osv.dev/vulnerability/{vuln_id}"
"""OSV 网页详情（``RawItem.url`` 回退值）。"""

NVD_DETAIL_URL_TEMPLATE: str = "https://nvd.nist.gov/vuln/detail/{cve_id}"
"""NVD 详情页模板（条目含 CVE 别名时优先使用）。"""

DEFAULT_ECOSYSTEM: str = "PyPI"
"""默认查询生态。"""

HEALTH_CHECK_VULN_ID: str = "GHSA-jfh8-c2jp-5v3q"
"""探活用的**长期存在**漏洞（Log4Shell，2021 年公开后不会下线）。"""


@register
class OsvConnector(BaseConnector):
    """OSV.dev 采集器。

    Attributes:
        ecosystem: 查询生态（默认 ``PyPI``）。
        query_url: 查询接口地址（测试可覆盖）。
        vuln_url_template: 单条接口模板（测试可覆盖）。
    """

    source_name: ClassVar[str] = OSV_SOURCE_NAME
    rate_limit: ClassVar[str] = "10/1"
    timeout: ClassVar[float] = 60.0
    ecosystem: ClassVar[str] = DEFAULT_ECOSYSTEM
    query_url: ClassVar[str] = OSV_QUERY_URL
    vuln_url_template: ClassVar[str] = OSV_VULN_URL_TEMPLATE

    def __init__(self, *, packages: Sequence[str] | None = None, **kwargs: Any) -> None:
        """初始化采集器。

        Args:
            packages: 监听包清单；``None`` 时读取 ``Settings.watchlist``。
            **kwargs: 透传给 :class:`BaseConnector`（``http`` / ``limiter`` / ``settings``）。
        """
        super().__init__(**kwargs)
        self._packages: list[str] = list(packages) if packages is not None else list(self.settings.watchlist)

    @property
    def packages(self) -> list[str]:
        """当前监听的包清单（去重保序）。"""
        return list(self._packages)

    @property
    def source_url(self) -> str:
        """源首页地址（``RawItem.url`` 的回退值）。"""
        return "https://osv.dev/"

    async def query_package(self, package: str, *, ecosystem: str | None = None) -> list[dict[str, Any]]:
        """按包查询漏洞（含限流）。

        Args:
            package: 包名，如 ``vllm``。
            ecosystem: 生态；``None`` 时使用类属性 ``ecosystem``。

        Returns:
            OSV 漏洞对象列表。

        Raises:
            ValueError: 响应结构异常（源侧变更需显式暴露）。
        """
        await self.limiter.acquire()
        payload = await self.http.post_json(
            self.query_url,
            payload={"package": {"name": package, "ecosystem": ecosystem or self.ecosystem}},
        )
        if not isinstance(payload, dict):
            raise ValueError(f"OSV 查询响应结构异常（期望 object）：{type(payload).__name__}")
        vulns = payload.get("vulns") or []
        if not isinstance(vulns, list):
            raise ValueError("OSV 响应的 vulns 字段不是数组")
        return [item for item in vulns if isinstance(item, dict)]

    def vuln_to_raw_item(self, vuln: dict[str, Any]) -> RawItem:
        """把单条 OSV 漏洞转换为 ``RawItem``。

        Args:
            vuln: OSV 漏洞对象。

        Returns:
            统一格式的 ``RawItem``。

        Raises:
            ValueError: 条目缺少 ``id``。
        """
        vuln_id = str(vuln.get("id") or "").strip()
        if not vuln_id:
            raise ValueError(f"OSV 条目缺少 id：{vuln!r}")

        aliases = [str(item) for item in (vuln.get("aliases") or []) if item]
        cve_ids = [alias for alias in aliases if alias.upper().startswith("CVE-")]
        url = (
            NVD_DETAIL_URL_TEMPLATE.format(cve_id=cve_ids[0])
            if cve_ids
            else OSV_DETAIL_URL_TEMPLATE.format(vuln_id=vuln_id)
        )

        meta: dict[str, str] = {"ecosystem": self.ecosystem, "aliases": ", ".join(aliases)}
        affected = [item for item in (vuln.get("affected") or []) if isinstance(item, dict)]
        package_names: list[str] = []
        for item in affected:
            package = item.get("package")
            if isinstance(package, dict) and package.get("name"):
                package_names.append(str(package["name"]))
        if package_names:
            meta["packages"] = ", ".join(dict.fromkeys(package_names))

        return self.build_raw_item(
            source_id=vuln_id,
            raw_text=self.raw_text_from_json(vuln),
            url=url,
            title=str(vuln.get("summary") or "") or None,
            published_at=self.to_utc_datetime(vuln.get("published")),
            lang="en",
            meta=meta,
        )


    async def fetch_incremental(self, since: datetime) -> list[RawItem]:
        """按 ``watchlist`` 批量查询，返回 ``modified >= since`` 的漏洞。

        Args:
            since: 增量起点（UTC，含）。

        Returns:
            按发布时间倒序排列的 ``RawItem`` 列表（跨包去重）。
        """
        threshold = self.to_utc_datetime(since)
        items: list[RawItem] = []
        seen: set[str] = set()
        for package in self.packages:
            try:
                vulns = await self.query_package(package)
            except Exception as exc:  # noqa: BLE001 - 单包失败不应中断整体采集
                logger.warning(f"OSV 查询失败 package={package}：{exc!r}")
                continue
            for vuln in vulns:
                vuln_id = str(vuln.get("id") or "")
                if not vuln_id or vuln_id in seen:
                    continue
                changed = self.to_utc_datetime(vuln.get("modified") or vuln.get("published"))
                if threshold is not None and changed is not None and changed < threshold:
                    continue
                seen.add(vuln_id)
                items.append(self.vuln_to_raw_item(vuln))

        items.sort(key=lambda item: item.published_at or item.fetched_at, reverse=True)
        logger.info(f"OSV 采集完成：包数={len(self.packages)} 命中={len(items)}（since={since.isoformat()}）")
        return items

    async def health_check(self) -> bool:
        """探活：GET 一条长期存在的漏洞详情，检查 HTTP 200。

        Returns:
            可用返回 ``True``；任何异常返回 ``False``。
        """
        try:
            await self.limiter.acquire()
            response = await self.http.request("GET", self.vuln_url_template.format(vuln_id=HEALTH_CHECK_VULN_ID))
        except Exception as exc:  # noqa: BLE001 - 探活需吞掉所有异常
            logger.warning(f"OSV 探活失败：{exc!r}")
            return False
        return response.status_code == 200

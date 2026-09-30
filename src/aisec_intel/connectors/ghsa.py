"""GitHub Security Advisory（GHSA）采集器（PROJECT_PLAN.md §5.3 / §5.4）。

数据源：``POST https://api.github.com/graphql``（**需要 ``GITHUB_TOKEN``**）。
关注范围：``PIP`` / ``NPM`` 生态中与 AI/ML 相关的安全公告（关键词过滤）。

约定：
    - ``source_name = "ghsa"``；``source_id`` 使用 ``ghsaId``（如 ``GHSA-xxxx-xxxx-xxxx``）；
    - **cursor 分页**：``securityAdvisories(orderBy: UPDATED_AT DESC)`` + ``pageInfo.endCursor``；
    - **增量**：结果按 ``updatedAt`` 倒序，遇到 ``updatedAt < since`` 即停止翻页（省配额）；
    - 未配置 ``GITHUB_TOKEN`` 时 ``enabled=False``，采集显式报错而不是静默返回空；
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

GHSA_SOURCE_NAME: str = "ghsa"
"""源标识。"""

GITHUB_GRAPHQL_URL: str = "https://api.github.com/graphql"
"""GitHub GraphQL 端点。"""

GHSA_DETAIL_URL_TEMPLATE: str = "https://github.com/advisories/{ghsa_id}"
"""GHSA 网页详情（``RawItem.url``）。"""

VIEWER_QUERY: str = "query { viewer { login } }"
"""探活查询。"""

ADVISORY_FIELDS: str = """
      ghsaId
      summary
      description
      severity
      publishedAt
      updatedAt
      cvss { vectorString score }
      cwes(first: 5) { nodes { cweId } }
      identifiers { type value }
      references { url }
      vulnerabilities(first: 10) {
        nodes {
          package { ecosystem name }
          vulnerableVersionRange
          firstPatchedVersion { identifier }
        }
      }
"""
"""安全公告节点的 GraphQL 字段选择（**被 ``vendor_github`` 复用**，改动需同步两处）。"""

ADVISORY_QUERY: str = f"""
query($first: Int!, $after: String) {{
  securityAdvisories(first: $first, after: $after, orderBy: {{field: UPDATED_AT, direction: DESC}}) {{
    nodes {{ {ADVISORY_FIELDS} }}
    pageInfo {{ hasNextPage endCursor }}
  }}
}}
"""
"""安全公告查询（含 CVSS / CWE / 受影响包与修复版本）。"""

DEFAULT_ECOSYSTEMS: tuple[str, ...] = ("PIP", "NPM")
"""关注的生态。"""

AI_ML_KEYWORDS: tuple[str, ...] = (
    "ai",
    "ml",
    "machine learning",
    "deep learning",
    "llm",
    "large language",
    "neural",
    "transformer",
    "langchain",
    "torch",
    "ollama",
    "vllm",
    "huggingface",
    "model",
)
"""AI/ML 关键词（对 ``summary`` / ``description`` / 包名做小写包含匹配）。"""

DEFAULT_PAGE_SIZE: int = 50
"""单页条数。"""

DEFAULT_MAX_PAGES: int = 5
"""最大翻页数（保护 GitHub API 配额）。"""


class GhsaError(RuntimeError):
    """GHSA 采集错误基类。"""


class GhsaAuthError(GhsaError):
    """缺少或无效的 ``GITHUB_TOKEN``。"""


class GhsaQueryError(GhsaError):
    """GraphQL 返回 errors（语法 / 权限 / 配额问题）。"""


@register
class GhsaConnector(BaseConnector):
    """GitHub Security Advisory 采集器。

    Attributes:
        graphql_url: GraphQL 端点（测试可覆盖）。
        ecosystems: 关注的生态集合。
        keywords: AI/ML 关键词集合。
    """

    source_name: ClassVar[str] = GHSA_SOURCE_NAME
    rate_limit: ClassVar[str] = "10/1"
    timeout: ClassVar[float] = 60.0
    graphql_url: ClassVar[str] = GITHUB_GRAPHQL_URL
    ecosystems: ClassVar[tuple[str, ...]] = DEFAULT_ECOSYSTEMS
    keywords: ClassVar[tuple[str, ...]] = AI_ML_KEYWORDS

    def __init__(
        self,
        *,
        token: str | None = None,
        page_size: int = DEFAULT_PAGE_SIZE,
        max_pages: int = DEFAULT_MAX_PAGES,
        ecosystems: Sequence[str] | None = None,
        keywords: Sequence[str] | None = None,
        **kwargs: Any,
    ) -> None:
        """初始化采集器。

        Args:
            token: GitHub Token；``None`` 时读取 ``Settings.github_token``。
            page_size: 单页条数。
            max_pages: 最大翻页数。
            ecosystems: 覆盖默认生态集合（大小写不敏感）。
            keywords: 覆盖默认关键词集合（转小写比较）。
            **kwargs: 透传给 :class:`BaseConnector`。
        """
        super().__init__(**kwargs)
        self._token = token if token is not None else self.settings.github_token.get_secret_value()
        self._page_size = max(1, page_size)
        self._max_pages = max(1, max_pages)
        if ecosystems is not None:
            self.ecosystems = tuple(item.strip().upper() for item in ecosystems if item.strip())
        if keywords is not None:
            self.keywords = tuple(item.strip().lower() for item in keywords if item.strip())

    @property
    def token(self) -> str:
        """当前使用的 GitHub Token（明文，仅内部使用）。"""
        return self._token

    @property
    def enabled(self) -> bool:
        """是否已配置 Token（未配置时该源不可用）。"""
        return bool(self._token.strip())

    @property
    def page_size(self) -> int:
        """单页条数。"""
        return self._page_size

    @property
    def max_pages(self) -> int:
        """最大翻页数。"""
        return self._max_pages

    @property
    def source_url(self) -> str:
        """源首页地址（``RawItem.url`` 的回退值）。"""
        return "https://github.com/advisories"

    def _headers(self) -> dict[str, str]:
        """构造 GraphQL 请求头（Token 不写入日志）。

        Returns:
            请求头字典。

        Raises:
            GhsaAuthError: Token 为空或含非 ASCII 字符（`.env` 值后写了行内注释是常见原因）。
        """
        token = self._token.strip()
        if not token:
            raise GhsaAuthError("未配置 GITHUB_TOKEN：请在 .env 中设置后重试（GHSA 源必需）")
        if not token.isascii():
            raise GhsaAuthError(
                "GITHUB_TOKEN 含非 ASCII 字符（常见原因：把注释写在了同一行）。"
                "请在 .env 中只保留 Token 本身，注释请单独成行。"
            )
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/vnd.github+json",
        }


    async def _graphql(self, query: str, variables: dict[str, Any] | None = None) -> dict[str, Any]:
        """执行 GraphQL 查询（含限流与错误处理）。

        Args:
            query: GraphQL 查询文本。
            variables: 查询变量。

        Returns:
            ``data`` 字段内容。

        Raises:
            GhsaAuthError: 未配置 Token。
            GhsaQueryError: 响应包含 ``errors``。
            ValueError: 响应缺少 ``data``。
        """
        if not self.enabled:
            raise GhsaAuthError("未配置 GITHUB_TOKEN：请在 .env 中设置后重试（GHSA 源必需）")
        await self.limiter.acquire()
        payload = await self.http.post_json(
            self.graphql_url,
            payload={"query": query, "variables": variables or {}},
            headers=self._headers(),
        )
        if not isinstance(payload, dict):
            raise ValueError(f"GraphQL 响应结构异常：{type(payload).__name__}")
        errors = payload.get("errors")
        if errors:
            raise GhsaQueryError(f"GraphQL 返回错误：{str(errors)[:300]}")
        data = payload.get("data")
        if not isinstance(data, dict):
            raise ValueError("GraphQL 响应缺少 data 字段")
        return data

    async def health_check(self) -> bool:
        """探活：GraphQL ``viewer { login }``。

        Returns:
            已配置 Token 且查询成功返回 ``True``；否则 ``False``。
        """
        if not self.enabled:
            logger.warning("GHSA 探活跳过：未配置 GITHUB_TOKEN")
            return False
        try:
            data = await self._graphql(VIEWER_QUERY)
        except Exception as exc:  # noqa: BLE001 - 探活需吞掉所有异常
            logger.warning(f"GHSA 探活失败：{exc!r}")
            return False
        return isinstance(data.get("viewer"), dict)


    def collect_packages(self, node: dict[str, Any]) -> list[tuple[str, str]]:
        """抽取公告涉及的 ``(生态, 包名)`` 列表（去重保序）。

        Args:
            node: GraphQL 公告节点。

        Returns:
            ``(ecosystem, package)`` 元组列表。
        """
        packages: list[tuple[str, str]] = []
        vulnerabilities = node.get("vulnerabilities") or {}
        for entry in vulnerabilities.get("nodes") or []:
            package = entry.get("package") if isinstance(entry, dict) else None
            if not isinstance(package, dict):
                continue
            ecosystem = str(package.get("ecosystem") or "").strip()
            name = str(package.get("name") or "").strip()
            if ecosystem and name and (ecosystem, name) not in packages:
                packages.append((ecosystem, name))
        return packages

    def matches_filters(self, node: dict[str, Any]) -> bool:
        """判断公告是否符合「生态 + AI/ML 关键词」过滤条件。

        Args:
            node: GraphQL 公告节点。

        Returns:
            命中返回 ``True``。
        """
        packages = self.collect_packages(node)
        if not any(ecosystem.upper() in self.ecosystems for ecosystem, _ in packages):
            return False
        haystack = " ".join(
            [str(node.get("summary") or ""), str(node.get("description") or ""), *[name for _, name in packages]]
        ).lower()
        return any(keyword in haystack for keyword in self.keywords)

    def advisory_to_raw_item(self, node: dict[str, Any]) -> RawItem:
        """把 GraphQL 公告节点转换为 ``RawItem``（整节点作为保真原文）。

        Args:
            node: GraphQL 公告节点。

        Returns:
            统一格式的 ``RawItem``。

        Raises:
            ValueError: 节点缺少 ``ghsaId``。
        """
        ghsa_id = str(node.get("ghsaId") or "").strip()
        if not ghsa_id:
            raise ValueError(f"GHSA 节点缺少 ghsaId：{node!r}")

        packages = self.collect_packages(node)
        meta: dict[str, str] = {
            "severity": str(node.get("severity") or ""),
            "ecosystems": ", ".join(sorted({ecosystem for ecosystem, _ in packages})),
            "packages": ", ".join(sorted({name for _, name in packages})),
        }
        identifiers = [item.get("value") for item in (node.get("identifiers") or []) if item.get("value")]
        if identifiers:
            meta["identifiers"] = ", ".join(str(item) for item in identifiers)

        return self.build_raw_item(
            source_id=ghsa_id,
            raw_text=self.raw_text_from_json(node),
            url=GHSA_DETAIL_URL_TEMPLATE.format(ghsa_id=ghsa_id),
            title=str(node.get("summary") or "") or None,
            published_at=self.to_utc_datetime(node.get("publishedAt")),
            lang="en",
            meta=meta,
        )

    async def fetch_incremental(self, since: datetime) -> list[RawItem]:
        """按 ``updatedAt`` 增量拉取公告（cursor 分页，遇旧数据即停）。

        Args:
            since: 增量起点（UTC，含）。

        Returns:
            按发布时间倒序的 ``RawItem`` 列表。

        Raises:
            GhsaAuthError: 未配置 Token。
            GhsaQueryError: GraphQL 报错。
        """
        threshold = self.to_utc_datetime(since)
        items: list[RawItem] = []
        cursor: str | None = None
        for page in range(1, self._max_pages + 1):
            data = await self._graphql(ADVISORY_QUERY, {"first": self._page_size, "after": cursor})
            connection = data.get("securityAdvisories") or {}
            nodes = [node for node in (connection.get("nodes") or []) if isinstance(node, dict)]
            if not nodes:
                break

            reached_oldest = False
            for node in nodes:
                updated = self.to_utc_datetime(node.get("updatedAt"))
                if threshold is not None and updated is not None and updated < threshold:
                    reached_oldest = True
                    break
                if self.matches_filters(node):
                    items.append(self.advisory_to_raw_item(node))

            page_info = connection.get("pageInfo") or {}
            logger.info(f"GHSA 第 {page} 页：节点={len(nodes)} 命中累计={len(items)} 到增量边界={reached_oldest}")
            if reached_oldest or not page_info.get("hasNextPage"):
                break
            cursor = page_info.get("endCursor")
            if not cursor:
                break

        items.sort(key=lambda item: item.published_at or item.fetched_at, reverse=True)
        logger.info(f"GHSA 采集完成：命中={len(items)}（since={since.isoformat()}）")
        return items

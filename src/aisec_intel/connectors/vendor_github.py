"""厂商仓库安全公告采集器（PROJECT_PLAN.md §5.4 P3 扩展源：厂商公告情报）。

数据源：``POST https://api.github.com/graphql``（**需要 ``GITHUB_TOKEN``**），
按仓库维度查询 ``repository.securityAdvisories``。

与 :mod:`aisec_intel.connectors.ghsa` 的关系：
    - **复用**其 GraphQL 端点常量、字段选择（:data:`~aisec_intel.connectors.ghsa.ADVISORY_FIELDS`）
      与探活查询（``VIEWER_QUERY``）；
    - 差异：GHSA 源按``UPDATED_AT`` 全站倒序翻页，本源按**受监控仓库**逐个查询
      （``ollama/ollama``、``vllm-project/vllm``、``langchain-ai/langchain``、
      ``huggingface/transformers``、``pytorch/pytorch``），更适合「盯厂商」场景。

约定：
    - ``source_name = "vendor_github"``；``source_id`` 优先用 ``ghsaId``；
    - **增量按 ``updatedAt``**：客户端按 ``since`` 过滤（GraphQL 不支持按时间过滤 advisory）；
    - 单仓库失败不阻断整体（异常隔离），错误写入日志；
    - 未配置 ``GITHUB_TOKEN`` 时 ``enabled=False``，采集显式报错而不是静默返回空；
    - L1 采集层禁止 LLM（§0 约束 1）。
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Any, ClassVar

from aisec_intel.connectors.base import BaseConnector
from aisec_intel.connectors.ghsa import ADVISORY_FIELDS, GITHUB_GRAPHQL_URL, VIEWER_QUERY, GhsaAuthError, GhsaError
from aisec_intel.connectors.registry import register
from aisec_intel.logging_config import get_logger
from aisec_intel.models.raw_item import RawItem

logger = get_logger(__name__)

VENDOR_GITHUB_SOURCE_NAME: str = "vendor_github"
"""源标识。"""

MONITORED_REPOS: tuple[str, ...] = (
    "ollama/ollama",
    "vllm-project/vllm",
    "langchain-ai/langchain",
    "huggingface/transformers",
    "pytorch/pytorch",
)
"""受监控的 AI/ML 厂商仓库（``owner/name``）。"""

REPO_PACKAGES: dict[str, tuple[str, ...]] = {
    "ollama/ollama": ("ollama",),
    "vllm-project/vllm": ("vllm",),
    "langchain-ai/langchain": ("langchain", "langgraph", "langsmith"),
    "huggingface/transformers": ("transformers",),
    "pytorch/pytorch": ("torch", "pytorch", "torchvision", "torchaudio"),
}
"""仓库 → 对应生态包名（用于「公告 → 受监控仓库」的确定性归属判断）。"""

ADVISORY_QUERY: str = f"""
query($first: Int!, $after: String) {{
  securityAdvisories(first: $first, after: $after, orderBy: {{field: UPDATED_AT, direction: DESC}}) {{
    nodes {{ {ADVISORY_FIELDS} }}
    pageInfo {{ hasNextPage endCursor }}
  }}
}}
"""
"""安全公告查询（与 ``ghsa.ADVISORY_QUERY`` 同构，复用其字段选择）。

Note:
    实测（2026-09-30）：GitHub GraphQL **没有** ``Repository.securityAdvisories`` 字段
    （报错 ``Field 'securityAdvisories' doesn't exist on type 'Repository'``），
    因此「盯厂商」改为：**全站公告 + 按受影响包名归属过滤**（:data:`REPO_PACKAGES`），
    等价且稳定可用。
"""

ADVISORY_URL_TEMPLATE: str = "https://github.com/advisories/{ghsa_id}"
"""公告详情页（``RawItem.url``）。"""

DEFAULT_PAGE_SIZE: int = 20
"""单页公告条数上限。"""

DEFAULT_MAX_PAGES: int = 5
"""最大翻页数（保护 GitHub API 配额）。"""


class VendorGithubError(GhsaError):
    """厂商仓库采集错误基类。"""


@register
class VendorGithubConnector(BaseConnector):
    """AI/ML 厂商仓库安全公告采集器。

    Attributes:
        repos: 受监控仓库列表（``owner/name``）。
        page_size: 单仓库条数上限。
    """

    source_name: ClassVar[str] = VENDOR_GITHUB_SOURCE_NAME
    rate_limit: ClassVar[str] = "10/1"
    timeout: ClassVar[float] = 60.0
    graphql_url: ClassVar[str] = GITHUB_GRAPHQL_URL

    def __init__(
        self,
        *,
        token: str | None = None,
        repos: Sequence[str] | None = None,
        page_size: int = DEFAULT_PAGE_SIZE,
        max_pages: int = DEFAULT_MAX_PAGES,
        **kwargs: Any,
    ) -> None:
        """初始化采集器。

        Args:
            token: GitHub Token；``None`` 时取 ``settings.github_token``。
            repos: 覆盖受监控仓库列表。
            page_size: 单页条数上限。
            max_pages: 最大翻页数（保护 API 配额）。
            **kwargs: 透传给 :class:`BaseConnector`（``http`` / ``limiter`` / ``max_records``）。
        """
        super().__init__(**kwargs)
        if token is None:
            token = self.settings.github_token.get_secret_value()
        self._token = (token or "").strip()
        self._repos = tuple(repos) if repos else MONITORED_REPOS
        self._page_size = max(1, page_size)
        self._max_pages = max(1, max_pages)

    @property
    def max_pages(self) -> int:
        """最大翻页数。"""
        return self._max_pages

    @property
    def enabled(self) -> bool:
        """是否具备采集条件（需 Token）。"""
        return bool(self._token)

    @property
    def repos(self) -> tuple[str, ...]:
        """受监控仓库列表。"""
        return self._repos

    @property
    def source_url(self) -> str:
        """源首页地址。"""
        return "https://github.com/advisories"

    def _headers(self) -> dict[str, str]:
        """构造 GraphQL 请求头。

        Returns:
            请求头字典。

        Raises:
            GhsaAuthError: Token 为空或含非 ASCII 字符。
        """
        if not self._token:
            raise GhsaAuthError("未配置 GITHUB_TOKEN：请在 .env 中设置后重试（vendor_github 源必需）")
        if not self._token.isascii():
            raise GhsaAuthError("GITHUB_TOKEN 含非 ASCII 字符（常见原因：把注释写在了同一行）")
        return {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
            "Accept": "application/vnd.github+json",
        }

    async def _graphql(self, query: str, variables: dict[str, Any] | None = None) -> dict[str, Any]:
        """执行 GraphQL 查询（含限流、鉴权与错误处理）。

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
        from aisec_intel.connectors.ghsa import GhsaQueryError

        if not self.enabled:
            raise GhsaAuthError("未配置 GITHUB_TOKEN：请在 .env 中设置后重试（vendor_github 源必需）")
        await self.limiter.acquire()
        payload = await self.http.post_json(
            self.graphql_url,
            payload={"query": query, "variables": variables or {}},
            headers=self._headers(),
        )
        if not isinstance(payload, dict):
            raise GhsaQueryError(f"GraphQL 响应不是对象：{type(payload).__name__}")
        errors = payload.get("errors")
        if errors:
            parts = [str(item.get("message", item)) for item in errors if isinstance(item, dict)]
            messages = "; ".join(parts) or str(errors)
            raise GhsaQueryError(f"GraphQL 返回错误：{messages}")
        data = payload.get("data")
        if not isinstance(data, dict):
            raise GhsaQueryError("GraphQL 响应缺少 data 字段")
        return data

    def advisory_to_raw_item(self, node: dict[str, Any], *, repo: str) -> RawItem:
        """把仓库安全公告节点转换为 ``RawItem``（整节点作为保真原文）。

        Args:
            node: GraphQL 公告节点。
            repo: 所属仓库（``owner/name``，写入 ``meta``）。

        Returns:
            统一格式的 ``RawItem``。

        Raises:
            ValueError: 节点既无 ``ghsaId`` 也无 ``summary``（无法生成稳定 source_id）。
        """
        ghsa_id = str(node.get("ghsaId") or "").strip()
        summary = str(node.get("summary") or "").strip()
        if not ghsa_id and not summary:
            raise ValueError(f"vendor_github 节点缺少 ghsaId/summary：{node!r}")

        packages = [
            (str(item.get("package", {}).get("ecosystem") or ""), str(item.get("package", {}).get("name") or ""))
            for item in (node.get("vulnerabilities") or {}).get("nodes", [])
            if isinstance(item, dict)
        ]
        meta: dict[str, str] = {
            "repo": repo,
            "severity": str(node.get("severity") or ""),
            "ecosystems": ", ".join(sorted({eco for eco, _ in packages if eco})),
            "packages": ", ".join(sorted({name for _, name in packages if name})),
            "source_type": "vendor-advisory",
        }
        identifiers = [item.get("value") for item in (node.get("identifiers") or []) if item.get("value")]
        if identifiers:
            meta["identifiers"] = ", ".join(str(item) for item in identifiers)

        return self.build_raw_item(
            source_id=ghsa_id or f"{repo}:{summary[:60]}",
            raw_text=self.raw_text_from_json({"repo": repo, "advisory": node}),
            url=ADVISORY_URL_TEMPLATE.format(ghsa_id=ghsa_id) if ghsa_id else f"https://github.com/{repo}/security",
            title=summary or None,
            published_at=self.to_utc_datetime(node.get("publishedAt")),
            lang="en",
            meta=meta,
        )

    async def fetch_incremental(self, since: datetime) -> list[RawItem]:
        """逐个仓库拉取 ``updatedAt >= since`` 的安全公告。

        Args:
            since: 增量起点（UTC，含）。

        Returns:
            按发布时间倒序的 ``RawItem`` 列表（单仓库失败仅记日志，不阻断其它仓库）。

        Raises:
            GhsaAuthError: 未配置 Token。
        """
        threshold = self.to_utc_datetime(since)
        items: list[RawItem] = []
        if not self.enabled:
            raise GhsaAuthError("未配置 GITHUB_TOKEN：请在 .env 中设置后重试（vendor_github 源必需）")

        cursor: str | None = None
        for page in range(1, self._max_pages + 1):
            try:
                data = await self._graphql(ADVISORY_QUERY, {"first": self._page_size, "after": cursor})
            except Exception as exc:  # noqa: BLE001 - 单页失败不阻断（返回已收集结果）
                logger.warning(f"vendor_github 第 {page} 页查询失败（{type(exc).__name__}: {exc}）")
                break

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
                repo = self.match_repo(node)
                if repo is None:
                    continue
                try:
                    items.append(self.advisory_to_raw_item(node, repo=repo))
                except ValueError as exc:
                    logger.warning(f"vendor_github 跳过异常节点：{exc}")

            page_info = connection.get("pageInfo") or {}
            logger.info(
                f"vendor_github 第 {page} 页：节点={len(nodes)} 命中累计={len(items)} 到增量边界={reached_oldest}"
            )
            if reached_oldest or not page_info.get("hasNextPage") or self.limit_reached(len(items)):
                break
            cursor = page_info.get("endCursor")
            if not cursor:
                break

        items.sort(key=lambda item: item.published_at or item.fetched_at, reverse=True)
        logger.info(f"vendor_github 采集完成：命中 {len(items)} 条（since={since.isoformat()}）")
        return items

    def match_repo(self, node: dict[str, Any]) -> str | None:
        """判断公告是否属于受监控仓库（纯函数式归属匹配）。

        规则：公告的任一受影响包名（小写）**包含**受监控仓库的包名关键字即归属该仓库
        （如 ``langchain-core`` → ``langchain-ai/langchain``）。

        Args:
            node: GraphQL 公告节点。

        Returns:
            命中的仓库 ``owner/name``；未命中返回 ``None``。
        """
        package_names = [
            str(item.get("package", {}).get("name") or "").lower()
            for item in (node.get("vulnerabilities") or {}).get("nodes", [])
            if isinstance(item, dict)
        ]
        if not package_names:
            return None
        for repo in self._repos:
            keywords = REPO_PACKAGES.get(repo, (repo.split("/")[-1].lower(),))
            if any(keyword in name for name in package_names for keyword in keywords):
                return repo
        return None

    async def health_check(self) -> bool:
        """探活：执行 ``viewer`` 查询验证 Token 有效性。

        Returns:
            可用返回 ``True``；未配置 Token 或调用失败返回 ``False``（探活不得中断主流程）。
        """
        if not self.enabled:
            logger.warning("vendor_github 未配置 GITHUB_TOKEN，探活失败")
            return False
        try:
            await self._graphql(VIEWER_QUERY)
        except Exception as exc:  # noqa: BLE001 - 探活需吞掉所有异常
            logger.warning(f"vendor_github 探活失败：{exc!r}")
            return False
        return True

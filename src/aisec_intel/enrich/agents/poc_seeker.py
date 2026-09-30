"""PoC / EXP 检索 Agent（富化维度③，PROJECT_PLAN.md §5.6 ``exploit_assessor.py``）。

设计要点：

1. **URL 一律程序化构造**（GitHub 检索 API / ExploitDB 站点检索 / Nuclei 官方模板路径），
   **禁止 LLM 生成任何 URL**（防幻觉链接，§7 R2）；
2. 多个检索器并发执行，**单源失败不阻断**（异常隔离，错误写入 ``state["errors"]``）；
3. 产出 ``ExploitRecord`` 列表（按 URL 去重），``verified`` 仅对「存在性已由 HTTP 200 证实」
   的记录为 ``True``（如官方 Nuclei 模板），其余保持 ``False``，交由 Verifier 复核。
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable, Sequence
from typing import Any

from aisec_intel.config import Settings, get_settings
from aisec_intel.connectors.http_client import HttpClient
from aisec_intel.enrich.state import EnrichmentState
from aisec_intel.enrich.tools.search_tools import search_exploitdb, search_github_poc, search_nuclei
from aisec_intel.logging_config import get_logger
from aisec_intel.models.enriched_vuln import AgentStep, ExploitRecord

logger = get_logger(__name__)

AGENT_NAME: str = "poc_seeker"
"""节点名（写入 ``agent_trace.agent``）。"""

MODEL_TAG: str = "no-llm"
"""本节点不使用 LLM（URL 程序化构造），固定模型标识。"""

DEFAULT_LIMIT_PER_SOURCE: int = 5
"""单源返回条数上限。"""

PoCSearcher = Callable[[str], Awaitable[list[ExploitRecord]]]
"""单源检索器签名：``(cve_id) -> list[ExploitRecord]``。"""


def default_poc_searchers(
    *,
    http: HttpClient | None = None,
    token: str | None = None,
    settings: Settings | None = None,
    limit: int = DEFAULT_LIMIT_PER_SOURCE,
) -> list[tuple[str, PoCSearcher]]:
    """构造默认的三个检索器（GitHub / ExploitDB / Nuclei）。

    Args:
        http: HTTP 客户端；``None`` 时按设置新建（调用方负责关闭）。
        token: GitHub Token（来自 ``settings.github_token``）。
        settings: 全局配置。
        limit: 单源条数上限。

    Returns:
        ``[(源名, 检索器), ...]``。
    """
    resolved = settings or get_settings()
    client = http or HttpClient(timeout=30.0)
    resolved_token = token if token is not None else resolved.github_token.get_secret_value() or None

    async def _github(cve_id: str) -> list[ExploitRecord]:
        return await search_github_poc(cve_id, http=client, token=resolved_token, limit=limit)

    async def _exploitdb(cve_id: str) -> list[ExploitRecord]:
        return await search_exploitdb(cve_id, http=client, limit=limit)

    async def _nuclei(cve_id: str) -> list[ExploitRecord]:
        return await search_nuclei(cve_id, http=client, limit=3)

    return [("github", _github), ("exploitdb", _exploitdb), ("nuclei", _nuclei)]


def dedupe_exploits(records: Sequence[ExploitRecord]) -> list[ExploitRecord]:
    """按 URL 去重（保留首次出现；同 URL 时保留 ``verified`` 更高者）。

    Args:
        records: 检索结果（可含重复）。

    Returns:
        去重后的记录列表。
    """
    by_url: dict[str, ExploitRecord] = {}
    for record in records:
        existing = by_url.get(record.url)
        if existing is None or record.verified and not existing.verified:
            by_url[record.url] = record
    return list(by_url.values())


class PoCSeekerAgent:
    """PoC / EXP 检索节点（可调用对象，供 LangGraph 直接注册）。

    Attributes:
        searchers: ``[(源名, 检索器), ...]``。
    """

    def __init__(
        self,
        *,
        searchers: Sequence[tuple[str, PoCSearcher]] | None = None,
        settings: Settings | None = None,
        http: HttpClient | None = None,
    ) -> None:
        """初始化节点。

        Args:
            searchers: 注入的检索器列表（测试用桩）；``None`` 时使用 :func:`default_poc_searchers`。
            settings: 全局配置（构造默认检索器时使用）。
            http: HTTP 客户端（构造默认检索器时使用）。
        """
        self._settings = settings
        self._http = http
        self._searchers = list(searchers) if searchers is not None else []

    @property
    def searchers(self) -> list[tuple[str, PoCSearcher]]:
        """当前检索器列表（惰性构造默认检索器）。"""
        if not self._searchers:
            self._searchers = default_poc_searchers(settings=self._settings, http=self._http)
        return self._searchers

    async def __call__(self, state: EnrichmentState) -> dict[str, Any]:
        """并发执行各检索器，返回状态增量。

        Args:
            state: 富化图状态（读取 ``unified_vuln.vuln_id``）。

        Returns:
            含 ``exploits`` / ``agent_steps`` / ``errors`` 的增量字典。
        """
        started = time.perf_counter()
        cve_id = state["unified_vuln"].vuln_id
        results = await asyncio.gather(
            *(searcher(cve_id) for _, searcher in self.searchers),
            return_exceptions=True,
        )

        collected: list[ExploitRecord] = []
        errors: list[str] = []
        per_source: list[str] = []
        for (name, _), outcome in zip(self.searchers, results, strict=True):
            if isinstance(outcome, BaseException):
                errors.append(f"{AGENT_NAME}: {name} 检索失败（{type(outcome).__name__}: {outcome}）")
                logger.warning(f"PoC 源 {name} 检索失败：{outcome!r}")
                per_source.append(f"{name}=err")
                continue
            collected.extend(outcome)
            per_source.append(f"{name}={len(outcome)}")

        exploits = dedupe_exploits(collected)
        step = AgentStep(
            agent=AGENT_NAME,
            round=int(state.get("round", 0)),
            confidence=_confidence(exploits),
            latency_ms=int((time.perf_counter() - started) * 1000),
            model_used=MODEL_TAG,
            output_digest=f"records={len(exploits)} ({' '.join(per_source)})",
            error=errors[0] if errors else None,
        )
        return {"exploits": exploits, "agent_steps": [step], "errors": errors}


def _confidence(exploits: Sequence[ExploitRecord]) -> float:
    """由 PoC 记录聚合节点级置信度（纯函数）。

    规则：取记录中最高 ``reliability``（Verifier 会再做可达性与来源可信度校准）；
    无记录时为 ``0.0``。

    Args:
        exploits: PoC 记录。

    Returns:
        置信度，区间 ``[0.0, 1.0]``。
    """
    verified = [record for record in exploits if record.verified]
    if verified:
        return round(max(record.reliability for record in verified), 3)
    if exploits:
        return round(max(record.reliability for record in exploits), 3)
    return 0.0

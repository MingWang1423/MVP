"""Day9 Verifier 性能回归测试（PROJECT_PLAN.md §5.6 ``verifier`` + Day9 任务 1）。

**全部离线**（``httpx.MockTransport`` 模拟慢响应），验证四件事：

1. URL 可达性检查**并发**：总耗时 ≈ 最慢一条，而非逐条之和；
2. 单 URL 超时 **5s**（修复前沿用 ``HttpClient`` 的 30s）；
3. **内存缓存**：同一 URL 在回流 / 重复校验时不再探活，且只检查 top 5 PoC；
4. 性能回归阈值：整轮 verifier 必须 **< 15s**。
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx

from aisec_intel.connectors.http_client import HttpClient
from aisec_intel.enrich.agents.verifier import (
    DEFAULT_MAX_URL_CHECKS,
    URL_CHECK_TIMEOUT_S,
    UrlReachabilityCache,
    VerifierAgent,
    rank_exploits,
)
from aisec_intel.enrich.state import new_state
from aisec_intel.models.base import utc_now
from aisec_intel.models.enriched_vuln import ExploitRecord
from aisec_intel.models.unified_vuln import Reference, UnifiedVuln

PERF_BUDGET_S: float = 15.0
"""Day9 验收阈值：verifier 单轮耗时上限（秒）。"""


def make_delayed_http(*, delay_s: float, status_code: int = 200) -> tuple[HttpClient, list[str]]:
    """构造「每条请求都耗时 ``delay_s``」的离线 HTTP 客户端。

    Args:
        delay_s: 单条请求的模拟耗时（秒）。
        status_code: 响应状态码。

    Returns:
        ``(客户端, 收到的 URL 列表)``；URL 列表按请求顺序原地追加。
    """
    seen: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        await asyncio.sleep(delay_s)
        return httpx.Response(status_code, text="ok")

    return HttpClient(transport=httpx.MockTransport(handler)), seen


def make_vuln(**overrides: Any) -> UnifiedVuln:
    """构造测试用漏洞实体（默认无参考链接，便于精确控制探活条数）。"""
    payload: dict[str, Any] = {
        "vuln_id": "CVE-2024-3400",
        "description": "PAN-OS GlobalProtect command injection vulnerability.",
        "title": "PAN-OS Command Injection",
        "sources": ["nvd"],
        "trace_ids": ["trace-nvd"],
        "normalized_at": utc_now(),
    }
    payload.update(overrides)
    return UnifiedVuln(**payload)


def make_exploits(count: int, *, prefix: str = "https://example.test") -> list[ExploitRecord]:
    """构造 ``count`` 条 PoC 记录（``reliability`` 递减，便于断言排序结果）。"""
    return [
        ExploitRecord(
            source="github",
            url=f"{prefix}/{index}",
            maturity="poc",
            reliability=round(max(0.05, 0.9 - index * 0.05), 2),
        )
        for index in range(count)
    ]


class TestConcurrency:
    """并发探活（修复点 1）。"""

    async def test_checks_run_concurrently(self) -> None:
        """12 条 URL × 1.0s：并发后总耗时 < 6s（串行需 ≥12s）。"""
        http, seen = make_delayed_http(delay_s=1.0)
        state = new_state(make_vuln())
        state["exploits"] = make_exploits(12)

        started = time.perf_counter()
        result = await VerifierAgent(http=http, max_url_checks=12, max_poc_urls=12)(state)
        elapsed = time.perf_counter() - started

        assert result["verification"].checked_urls == 12
        assert len(seen) == 12
        assert elapsed < 6.0, f"并发失效：12 条慢 URL 耗时 {elapsed:.2f}s"

    async def test_perf_regression_budget_under_15s(self) -> None:
        """性能回归：16 条 URL × 1.0s（串行 ≥16s）→ 必须 < 15s。"""
        http, _ = make_delayed_http(delay_s=1.0)
        state = new_state(make_vuln())
        state["exploits"] = make_exploits(16)

        started = time.perf_counter()
        result = await VerifierAgent(http=http, max_url_checks=16, max_poc_urls=16)(state)
        elapsed = time.perf_counter() - started

        assert result["verification"].checked_urls == 16
        assert elapsed < PERF_BUDGET_S, f"性能回归：耗时 {elapsed:.2f}s ≥ {PERF_BUDGET_S}s"


class TestTimeout:
    """单 URL 5s 超时（修复点 2）。"""

    async def test_hanging_url_is_capped_by_five_seconds(self) -> None:
        """挂死 30s 的 URL 被 5s 超时截断：整轮 < 9s 且该 URL 判为不可达。"""
        http, _ = make_delayed_http(delay_s=30.0)
        state = new_state(make_vuln())
        state["exploits"] = make_exploits(1)

        started = time.perf_counter()
        result = await VerifierAgent(http=http)(state)
        elapsed = time.perf_counter() - started

        assert URL_CHECK_TIMEOUT_S == 5.0
        assert 3.0 <= elapsed < 9.0, f"超时未生效（耗时 {elapsed:.2f}s，期望 ≈5s）"
        assert result["verification"].reachable_urls == 0
        assert result["exploits"][0].verified is False
        assert result["exploits"][0].reliability < 0.6


class TestCacheAndTopN:
    """内存缓存（修复点 3）与「只检查 top 5 PoC」（修复点 4）。"""

    async def test_cache_avoids_repeat_probe(self) -> None:
        """同一 URL 第二轮（回流 / 重复校验）直接命中缓存，不再发请求。"""
        http, seen = make_delayed_http(delay_s=0.0)
        agent = VerifierAgent(http=http)
        state = new_state(make_vuln())
        state["exploits"] = make_exploits(1)

        first = await agent(state)
        second = await agent(state)

        assert len(seen) == 1, "同一 URL 被重复探活（缓存未生效）"
        assert first["verification"].checked_urls == 1
        assert second["verification"].checked_urls == 0
        assert any("缓存命中 1" in note for note in second["verification"].notes)
        assert second["verification"].reachable_urls == 1

    async def test_cache_ttl_expiry_triggers_reprobe(self) -> None:
        """TTL 过期后重新探活（缓存不是永久有效）。"""
        cache = UrlReachabilityCache(ttl_s=0.0)
        cache.put("https://example.test/x", (True, 200))
        assert cache.get("https://example.test/x") is None
        assert cache.misses == 1

    async def test_only_top_pocs_are_checked(self) -> None:
        """8 条 PoC 只检查相关性最高的 5 条（``DEFAULT_MAX_URL_CHECKS``）。"""
        http, seen = make_delayed_http(delay_s=0.0)
        state = new_state(make_vuln())
        state["exploits"] = make_exploits(8)

        result = await VerifierAgent(http=http)(state)

        assert DEFAULT_MAX_URL_CHECKS == 5
        assert result["verification"].checked_urls == 5
        assert set(seen) == {f"https://example.test/{index}" for index in range(5)}

    async def test_references_fill_remaining_budget(self) -> None:
        """预算受 ``max_url_checks`` 约束：PoC 优先，参考链接只在剩余名额内被检查。"""
        http, seen = make_delayed_http(delay_s=0.0)
        vuln = make_vuln(references=[Reference(url="https://example.test/advisory", source="nvd")])
        state = new_state(vuln)
        state["exploits"] = make_exploits(3)

        result = await VerifierAgent(http=http, max_url_checks=3)(state)

        assert result["verification"].checked_urls == 3
        assert "https://example.test/advisory" not in seen


class TestRankExploits:
    """``rank_exploits`` 纯函数排序规则。"""

    def test_maturity_and_verified_first(self) -> None:
        """成熟度、已验证、可信度依次决定优先级。"""
        records = [
            ExploitRecord(source="exploitdb-search", url="https://example.test/c", maturity="none"),
            ExploitRecord(source="github", url="https://example.test/b", maturity="poc", reliability=0.6),
            ExploitRecord(
                source="nuclei", url="https://example.test/a", maturity="functional", verified=True, reliability=0.8
            ),
        ]
        ranked = rank_exploits(records)
        assert [record.url for record in ranked] == [
            "https://example.test/a",
            "https://example.test/b",
            "https://example.test/c",
        ]

    def test_is_deterministic_for_equal_keys(self) -> None:
        """同键记录按 URL 升序，保证结果可复现。"""
        records = [
            ExploitRecord(source="github", url="https://example.test/z", maturity="poc"),
            ExploitRecord(source="github", url="https://example.test/a", maturity="poc"),
        ]
        assert [record.url for record in rank_exploits(records)] == [
            "https://example.test/a",
            "https://example.test/z",
        ]


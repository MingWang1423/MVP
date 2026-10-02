"""Day7 PoCSeeker（含检索工具）测试（PROJECT_PLAN.md §5.6）。

**全部离线**：``httpx.MockTransport`` 桩 HTTP + 桩检索器；验证 URL 为**程序化构造**。
"""

from __future__ import annotations

from typing import Any

import pytest

from aisec_intel.connectors.http_client import HttpClient
from aisec_intel.enrich.agents.poc_seeker import (
    AGENT_NAME,
    PoCSeekerAgent,
    _confidence,
    dedupe_exploits,
)
from aisec_intel.enrich.state import new_state
from aisec_intel.enrich.tools.search_tools import (
    EXPLOITDB_SEARCH_URL_TEMPLATE,
    GITHUB_SEARCH_URL,
    build_exploitdb_search_url,
    build_github_poc_query,
    build_nuclei_template_url,
    check_url_reachable,
    looks_like_poc,
    search_exploitdb,
    search_github_poc,
    search_nuclei,
)
from aisec_intel.models.base import utc_now
from aisec_intel.models.enriched_vuln import ExploitRecord
from aisec_intel.models.unified_vuln import UnifiedVuln

CVE = "CVE-2024-3400"


def make_vuln(**overrides: Any) -> UnifiedVuln:
    """构造测试用漏洞实体。"""
    payload: dict[str, Any] = {
        "vuln_id": CVE,
        "description": "PAN-OS command injection.",
        "trace_ids": ["trace-nvd"],
        "normalized_at": utc_now(),
    }
    payload.update(overrides)
    return UnifiedVuln(**payload)


class TestUrlConstruction:
    """URL 程序化构造（纯函数，**禁止 LLM 生成**）。"""

    def test_merged_batch1(self) -> None:
        """合并用例批次 1：顺序执行 5 个子用例并汇总失败。"""
        failures: list[str] = []
        try:
            self._case_test_github_query()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_github_query: {type(exc).__name__}: {exc}")
        try:
            self._case_test_exploitdb_search_url()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_exploitdb_search_url: {type(exc).__name__}: {exc}")
        try:
            self._case_test_nuclei_urls_use_year_directory()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_nuclei_urls_use_year_directory: {type(exc).__name__}: {exc}")
        try:
            self._case_test_nuclei_url_empty_for_non_cve()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_nuclei_url_empty_for_non_cve: {type(exc).__name__}: {exc}")
        try:
            self._case_test_looks_like_poc()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_looks_like_poc: {type(exc).__name__}: {exc}")
        assert not failures, "合并用例失败：" + " | ".join(failures)
    def _case_test_github_query(self) -> None:
        """GitHub 检索查询串固定为「CVE + poc + 字段限定」。"""
        assert build_github_poc_query("cve-2024-3400") == "CVE-2024-3400 poc in:name,description,readme"

    def _case_test_exploitdb_search_url(self) -> None:
        """ExploitDB 检索页由模板拼装。"""
        assert build_exploitdb_search_url(CVE) == EXPLOITDB_SEARCH_URL_TEMPLATE.format(cve_id=CVE)

    def _case_test_nuclei_urls_use_year_directory(self) -> None:
        """Nuclei 模板路径含年份目录（``http/cves/<年>/<CVE>.yaml``）。"""
        raw, html = build_nuclei_template_url(CVE)
        assert "/http/cves/2024/CVE-2024-3400.yaml" in raw
        assert raw.startswith("https://raw.githubusercontent.com/")
        assert html.startswith("https://github.com/")

    def _case_test_nuclei_url_empty_for_non_cve(self) -> None:
        """非 CVE 编号无法定位目录 → 返回空串（不猜测路径）。"""
        assert build_nuclei_template_url("GHSA-xxxx-yyyy-zzzz") == ("", "")

    def _case_test_looks_like_poc(self) -> None:
        """PoC 关键词启发式（确定性）。"""
        assert looks_like_poc("CVE-2024-3400-poc") is True
        assert looks_like_poc("my personal blog") is False


class TestGithubSearch:
    """GitHub 检索（桩 HTTP）。"""

    async def test_maps_repositories(self, mock_router: Any, mock_http: HttpClient) -> None:
        """仓库条目映射为 ``ExploitRecord``（含 star 证据）。"""
        mock_router.always(
            GITHUB_SEARCH_URL,
            json_body={
                "items": [
                    {
                        "full_name": "attacker/CVE-2024-3400-poc",
                        "description": "PoC for PAN-OS RCE",
                        "stargazers_count": 42,
                    },
                    {"full_name": "someone/notes"},
                ]
            },
        )
        records = await search_github_poc(CVE, http=mock_http, token=None, limit=5)

        assert [record.source for record in records] == ["github", "github"]
        assert records[0].url == "https://github.com/attacker/CVE-2024-3400-poc"
        assert records[0].exploit_type == "poc" and records[0].maturity == "poc"
        assert records[0].verified is False
        assert "stars=42" in records[0].evidence_refs

    async def test_invalid_payload_raises(self, mock_router: Any, mock_http: HttpClient) -> None:
        """响应缺少 ``items`` 时显式报错（由 Agent 捕获降级）。"""
        mock_router.always(GITHUB_SEARCH_URL, json_body={"message": "rate limited"})
        with pytest.raises(ValueError, match="items"):
            await search_github_poc(CVE, http=mock_http)


class TestExploitDbSearch:
    """ExploitDB 检索（JSON 优先 / 检索入口兜底）。"""

    async def test_json_endpoint_maps_rows(self, mock_router: Any, mock_http: HttpClient) -> None:
        """站点 JSON 可用时按条目 ID 生成详情链。"""
        mock_router.always(
            EXPLOITDB_SEARCH_URL_TEMPLATE.format(cve_id=CVE),
            json_body={"data": [{"id": "51234", "description": "PAN-OS CVE-2024-3400 exploit"}]},
        )
        records = await search_exploitdb(CVE, http=mock_http)
        assert records[0].url == "https://www.exploit-db.com/exploits/51234"
        assert records[0].maturity == "poc"

    async def test_falls_back_to_search_entry(self, mock_router: Any, mock_http: HttpClient) -> None:
        """接口不可用（非 JSON）时返回检索入口候选，并标记未验证。"""
        mock_router.always(EXPLOITDB_SEARCH_URL_TEMPLATE.format(cve_id=CVE), text="<html>blocked</html>")
        records = await search_exploitdb(CVE, http=mock_http)
        assert len(records) == 1
        assert records[0].source == "exploitdb-search"
        assert records[0].maturity == "none" and records[0].verified is False
        assert records[0].url == EXPLOITDB_SEARCH_URL_TEMPLATE.format(cve_id=CVE)


class TestNucleiSearch:
    """Nuclei 官方模板存在性检查。"""

    async def test_hit_marks_verified(self, mock_router: Any, mock_http: HttpClient) -> None:
        """HTTP 200 → ``verified=True``（存在性已证实）。"""
        raw, _ = build_nuclei_template_url(CVE)
        mock_router.always(raw, text="id: CVE-2024-3400\ninfo:\n  name: PAN-OS RCE")
        records = await search_nuclei(CVE, http=mock_http)
        assert len(records) == 1
        assert records[0].source == "nuclei" and records[0].verified is True
        assert records[0].maturity == "functional"

    async def test_miss_returns_empty(self, mock_router: Any, mock_http: HttpClient) -> None:
        """模板不存在（404）→ 空列表。"""
        raw, _ = build_nuclei_template_url(CVE)
        mock_router.always(raw, status_code=404, text="not found")
        assert await search_nuclei(CVE, http=mock_http) == []


class TestReachability:
    """URL 可达性检查（Verifier 用）。"""

    async def test_reachable_statuses(self, mock_router: Any, mock_http: HttpClient) -> None:
        """200 与「存在但反爬」（403/405）均视为可达。"""
        mock_router.always("https://example.test/ok", status_code=200, text="ok")
        mock_router.always("https://example.test/blocked", status_code=403, text="forbidden")
        assert await check_url_reachable("https://example.test/ok", http=mock_http) == (True, 200)
        assert await check_url_reachable("https://example.test/blocked", http=mock_http) == (True, 403)

    async def test_missing_url_is_unreachable(self, mock_router: Any, mock_http: HttpClient) -> None:
        """404 → 不可达，并带回状态码（便于诊断）。"""
        mock_router.always("https://example.test/gone", status_code=404, text="gone")
        assert await check_url_reachable("https://example.test/gone", http=mock_http) == (False, 404)


class TestDedupeAndConfidence:
    """去重与置信度聚合（纯函数）。"""

    def test_merged_batch1(self) -> None:
        """合并用例批次 1：顺序执行 2 个子用例并汇总失败。"""
        failures: list[str] = []
        try:
            self._case_test_dedupe_prefers_verified()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_dedupe_prefers_verified: {type(exc).__name__}: {exc}")
        try:
            self._case_test_confidence_prefers_verified()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_confidence_prefers_verified: {type(exc).__name__}: {exc}")
        assert not failures, "合并用例失败：" + " | ".join(failures)
    def _case_test_dedupe_prefers_verified(self) -> None:
        """同 URL 去重时保留 ``verified=True`` 的记录。"""
        plain = ExploitRecord(source="github", url="https://x.test/a", reliability=0.6, verified=False)
        verified = ExploitRecord(source="nuclei", url="https://x.test/a", reliability=0.8, verified=True)
        other = ExploitRecord(source="github", url="https://x.test/b")
        assert len(dedupe_exploits([plain, verified, other])) == 2
        assert dedupe_exploits([plain, verified])[0].verified is True

    def _case_test_confidence_prefers_verified(self) -> None:
        """置信度取已验证记录的最高可靠性；空列表为 0。"""
        assert _confidence([]) == 0.0
        assert _confidence([ExploitRecord(source="github", url="https://x.test/a", reliability=0.6)]) == 0.6
        assert (
            _confidence(
                [
                    ExploitRecord(source="github", url="https://x.test/a", reliability=0.6, verified=False),
                    ExploitRecord(source="nuclei", url="https://x.test/b", reliability=0.8, verified=True),
                ]
            )
            == 0.8
        )


class TestAgent:
    """节点行为：并发检索 + 异常隔离 + 状态增量。"""

    async def test_runs_searchers_and_dedupes(self) -> None:
        """多源并发检索并按 URL 去重，轨迹记录各源命中数。"""

        async def first(cve_id: str) -> list[ExploitRecord]:
            return [ExploitRecord(source="github", url="https://x.test/a", reliability=0.6)]

        async def second(cve_id: str) -> list[ExploitRecord]:
            return [
                ExploitRecord(source="github", url="https://x.test/a", reliability=0.6),
                ExploitRecord(source="nuclei", url="https://x.test/b", reliability=0.8, verified=True, maturity="poc"),
            ]

        agent = PoCSeekerAgent(searchers=[("github", first), ("nuclei", second)])
        result = await agent(new_state(make_vuln()))

        assert len(result["exploits"]) == 2  # 去重后
        assert result["errors"] == []
        step = result["agent_steps"][0]
        assert step.agent == AGENT_NAME
        assert "github=1" in step.output_digest and "nuclei=2" in step.output_digest
        assert step.confidence == pytest.approx(0.8)

    async def test_single_source_failure_is_isolated(self) -> None:
        """单源异常不影响其它源（异常隔离）。"""

        async def broken(cve_id: str) -> list[ExploitRecord]:
            raise RuntimeError("network down")

        async def good(cve_id: str) -> list[ExploitRecord]:
            return [ExploitRecord(source="nuclei", url="https://x.test/b", reliability=0.8, verified=True)]

        agent = PoCSeekerAgent(searchers=[("github", broken), ("nuclei", good)])
        result = await agent(new_state(make_vuln()))

        assert len(result["exploits"]) == 1
        assert any("github 检索失败" in error for error in result["errors"])
        assert result["agent_steps"][0].error is not None

    async def test_no_records_yields_zero_confidence(self) -> None:
        """全部源无结果 → 空列表 + 置信度 0（无结论）。"""

        async def empty(cve_id: str) -> list[ExploitRecord]:
            return []

        result = await PoCSeekerAgent(searchers=[("github", empty)])(new_state(make_vuln()))
        assert result["exploits"] == []
        assert result["agent_steps"][0].confidence == 0.0
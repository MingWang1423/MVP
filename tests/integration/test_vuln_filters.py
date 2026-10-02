"""Day15 任务 4：漏洞列表增强筛选集成测试（``GET /api/v1/vulnerabilities``）。

用 SQLite 内存库 + ``dependency_overrides`` 覆盖 ``get_vuln_repo``，**不需要 PostgreSQL**，
锁定以下新增筛选口径（前端筛选栏与 URL 同步依赖它们）：

- 严重度 **多选**（并集）、来源 **多选**（JSON 数组并集）；
- ``since`` / ``until`` 时间区间（含端点，时间轴 ``published_at`` 优先、回退 ``normalized_at``）；
- ``kev`` 三态（``true`` / ``false`` / 缺省）与兼容开关 ``kev_only``；
- ``has_poc`` 三态（``EXISTS`` 子查询，含未富化条目视为无 PoC）；
- ``q`` 关键词（命中 ``vuln_id`` / ``title`` / ``description``）；
- 响应新增 ``poc_count``（``enriched_vuln.exploits`` 条数）。
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Iterator
from datetime import timedelta
from typing import Any

import pytest

pytest.importorskip("sqlalchemy", reason="需要 sqlalchemy：pip install sqlalchemy[asyncio] aiosqlite")
pytest.importorskip("aiosqlite", reason="需要 aiosqlite：pip install aiosqlite")

from fastapi.testclient import TestClient  # noqa: E402

from aisec_intel.api.deps import get_vuln_repo  # noqa: E402
from aisec_intel.api.main import create_app  # noqa: E402
from aisec_intel.models import EnrichedVuln, UnifiedVuln, utc_now  # noqa: E402
from aisec_intel.storage.database import (  # noqa: E402
    create_engine,
    create_session_factory,
    init_models,
    session_scope,
)
from aisec_intel.storage.repositories.vuln_repo import VulnRepository  # noqa: E402

MEMORY_DSN = "sqlite+aiosqlite:///:memory:"
NOW = utc_now()
"""基准时间（UTC）：种子数据相对它偏移，避免受真实时钟影响。"""


def make_vuln(vuln_id: str, **overrides: Any) -> UnifiedVuln:
    """构造一条事实层实体（测试辅助）。"""
    payload: dict[str, Any] = {
        "vuln_id": vuln_id,
        "title": f"{vuln_id} title",
        "description": f"{vuln_id} description",
        "severity": "MEDIUM",
        "sources": ["nvd"],
        "normalized_at": NOW - timedelta(days=1),
    }
    payload.update(overrides)
    return UnifiedVuln(**payload)


def make_enriched(vuln_id: str, *, poc: int) -> EnrichedVuln:
    """构造一条富化实体（``poc`` 为 exploits 条数）。"""
    return EnrichedVuln(
        vuln_id=vuln_id,
        description=f"{vuln_id} description",
        normalized_at=NOW - timedelta(days=1),
        exploits=[
            {"source": "github", "url": f"https://example.test/{vuln_id}/{index}", "maturity": "poc"}
            for index in range(poc)
        ],
        risk_score=90.0,
        risk_level="critical",
        confidence=0.9,
        model_used="deepseek-chat",
        enriched_at=NOW - timedelta(hours=12),
    )


async def seed(engine: Any) -> None:
    """写入 4 条覆盖各种筛选维度的漏洞。

    =========  ==========  ==============  =========  =====  ========
    条目       严重度       时间轴           来源       KEV    PoC 数
    =========  ==========  ==============  =========  =====  ========
    ``A``      CRITICAL    NOW-1d           nvd        ✅     2
    ``B``      HIGH        NOW-10d          nvd/ghsa   ❌     0
    ``C``      MEDIUM      NOW-100d         osv        ❌     无富化
    ``D``      未定级       ``published=None`` / 归一化 NOW-2d  ghsa  ✅  无富化
    =========  ==========  ==============  =========  =====  ========
    """
    async with session_scope(engine) as session:
        repo = VulnRepository(session)
        await repo.upsert(
            make_vuln(
                "CVE-FILTER-A",
                title="alpha proxy rce",
                severity="CRITICAL",
                sources=["nvd"],
                kev=True,
                published_at=NOW - timedelta(days=1),
            )
        )
        await repo.upsert(
            make_vuln(
                "CVE-FILTER-B",
                title="beta library escape",
                severity="HIGH",
                sources=["nvd", "ghsa"],
                kev=False,
                published_at=NOW - timedelta(days=10),
            )
        )
        await repo.upsert(
            make_vuln(
                "CVE-FILTER-C",
                severity="MEDIUM",
                sources=["osv"],
                published_at=NOW - timedelta(days=100),
            )
        )
        await repo.upsert(
            make_vuln(
                "CVE-FILTER-D",
                severity=None,
                sources=["ghsa"],
                published_at=None,
                normalized_at=NOW - timedelta(days=2),
                kev=True,
            )
        )
        await repo.upsert_enriched(make_enriched("CVE-FILTER-A", poc=2))
        await repo.upsert_enriched(make_enriched("CVE-FILTER-B", poc=0))


@pytest.fixture()
def client() -> Iterator[TestClient]:
    """构造注入了内存库仓储的测试客户端（``TestClient`` 自带事件循环）。"""
    engine = create_engine(MEMORY_DSN)
    asyncio.run(init_models(engine))
    asyncio.run(seed(engine))
    factory = create_session_factory(engine)

    async def override_repo() -> AsyncIterator[VulnRepository]:
        async with factory() as session:
            yield VulnRepository(session)

    app = create_app()
    app.dependency_overrides[get_vuln_repo] = override_repo
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
    asyncio.run(engine.dispose())


def ids(payload: dict[str, Any]) -> list[str]:
    """取出响应中的 ``vuln_id`` 列表（保持返回顺序）。"""
    return [item["vuln_id"] for item in payload["items"]]


@pytest.fixture()
def fetch(client: TestClient):
    """返回一个「按参数取 ID 列表」的便捷函数。"""

    def _fetch(**params: Any) -> list[str]:
        response = client.get("/api/v1/vulnerabilities", params=params)
        assert response.status_code == 200, response.text
        return ids(response.json())

    return _fetch


@pytest.fixture()
def filter_ids(client: TestClient):
    """返回「按参数取 ID 集合」的便捷函数（筛选用例只关心命中集合）。

    默认排序（时间轴倒序：``A(NOW-1d) > D(NOW-2d) > B(NOW-10d) > C(NOW-100d)``）
    由 :class:`TestOrderingAndSummary` 单独锁定，避免每个用例都重复断言顺序。
    """

    def _ids(**params: Any) -> set[str]:
        response = client.get("/api/v1/vulnerabilities", params=params)
        assert response.status_code == 200, response.text
        return {item["vuln_id"] for item in response.json()["items"]}

    return _ids


class TestMultiValueFilters:
    """严重度 / 来源多选（取并集）。"""

    def test_severity_single_value_still_supported(self, filter_ids: Any) -> None:
        """单值传参（Streamlit 前端与旧调用方）继续可用。"""
        assert filter_ids(severity="HIGH") == {"CVE-FILTER-B"}

    def test_severity_multi_value(self, client: TestClient) -> None:
        response = client.get(
            "/api/v1/vulnerabilities", params=[("severity", "CRITICAL"), ("severity", "HIGH")]
        )
        assert response.status_code == 200
        assert {item["vuln_id"] for item in response.json()["items"]} == {
            "CVE-FILTER-A",
            "CVE-FILTER-B",
        }
        assert response.json()["total"] == 2

    def test_severity_multi_value_case_insensitive(self, client: TestClient) -> None:
        response = client.get("/api/v1/vulnerabilities?severity=critical&severity=medium")
        assert {item["vuln_id"] for item in response.json()["items"]} == {
            "CVE-FILTER-A",
            "CVE-FILTER-C",
        }

    def test_source_multi_value_union(self, client: TestClient) -> None:
        response = client.get("/api/v1/vulnerabilities?source=osv&source=ghsa")
        assert {item["vuln_id"] for item in response.json()["items"]} == {
            "CVE-FILTER-B",
            "CVE-FILTER-C",
            "CVE-FILTER-D",
        }

    def test_severity_and_source_combined(self, filter_ids: Any) -> None:
        """组合筛选取交集。"""
        assert filter_ids(severity="HIGH", source="ghsa") == {"CVE-FILTER-B"}
        assert filter_ids(severity="CRITICAL", source="osv") == set()

    def test_invalid_severity_rejected(self, client: TestClient) -> None:
        """非白名单严重度由 FastAPI 校验为 422。"""
        assert client.get("/api/v1/vulnerabilities?severity=SUPER").status_code == 422


class TestTimeRangeFilters:
    """``since`` / ``until`` 区间（含端点）。"""

    def test_since(self, filter_ids: Any) -> None:
        since = (NOW - timedelta(days=15)).isoformat()
        assert filter_ids(since=since) == {"CVE-FILTER-A", "CVE-FILTER-B", "CVE-FILTER-D"}

    def test_until(self, filter_ids: Any) -> None:
        until = (NOW - timedelta(days=15)).isoformat()
        assert filter_ids(until=until) == {"CVE-FILTER-C"}

    def test_since_prefers_over_days(self, filter_ids: Any) -> None:
        """显式传 ``since`` 时忽略 ``days``。"""
        since = (NOW - timedelta(days=15)).isoformat()
        assert filter_ids(since=since, days=200) == {
            "CVE-FILTER-A",
            "CVE-FILTER-B",
            "CVE-FILTER-D",
        }

    def test_days_window_still_supported(self, filter_ids: Any) -> None:
        """兼容旧前端的 ``days`` 窗口（近 3 天 → A、D）。"""
        assert filter_ids(days=3) == {"CVE-FILTER-A", "CVE-FILTER-D"}


class TestKevAndPocFilters:
    """``kev`` / ``has_poc`` 三态与兼容开关。"""

    def test_kev_true_and_false(self, filter_ids: Any) -> None:
        assert filter_ids(kev="true") == {"CVE-FILTER-A", "CVE-FILTER-D"}
        assert filter_ids(kev="false") == {"CVE-FILTER-B", "CVE-FILTER-C"}

    def test_kev_default_no_filter(self, filter_ids: Any) -> None:
        assert filter_ids() == {
            "CVE-FILTER-A",
            "CVE-FILTER-B",
            "CVE-FILTER-C",
            "CVE-FILTER-D",
        }

    def test_kev_only_compat_switch(self, filter_ids: Any) -> None:
        """旧前端的 ``kev_only=true`` 与 ``kev=true`` 等价。"""
        assert filter_ids(kev_only="true") == filter_ids(kev="true")

    def test_has_poc(self, filter_ids: Any) -> None:
        assert filter_ids(has_poc="true") == {"CVE-FILTER-A"}
        # 无 PoC：含「已富化但 exploits 为空」与「完全未富化」两类
        assert filter_ids(has_poc="false") == {
            "CVE-FILTER-B",
            "CVE-FILTER-C",
            "CVE-FILTER-D",
        }

    def test_has_poc_combined_with_severity(self, filter_ids: Any) -> None:
        assert filter_ids(has_poc="true", severity="CRITICAL") == {"CVE-FILTER-A"}
        assert filter_ids(has_poc="true", severity="HIGH") == set()


class TestOrderingAndSummary:
    """默认排序与列表条目字段。"""

    def test_default_order_is_timeline_desc(self, fetch: Any) -> None:
        """时间轴倒序：``A(NOW-1d) → D(NOW-2d) → B(NOW-10d) → C(NOW-100d)``。

        ``D`` 的 ``published_at`` 为空，回退 ``normalized_at``（NOW-2d），
        因此排在 ``B`` 之前——这是「时间轴」口径的直接体现。
        """
        assert fetch() == ["CVE-FILTER-A", "CVE-FILTER-D", "CVE-FILTER-B", "CVE-FILTER-C"]

    def test_keyword_matches_id_title_description(self, filter_ids: Any) -> None:
        assert filter_ids(q="filter-a") == {"CVE-FILTER-A"}
        assert filter_ids(q="proxy") == {"CVE-FILTER-A"}  # 命中 title
        assert filter_ids(q="description") == {
            "CVE-FILTER-A",
            "CVE-FILTER-B",
            "CVE-FILTER-C",
            "CVE-FILTER-D",
        }  # 命中 description

    def test_keyword_no_match(self, filter_ids: Any) -> None:
        assert filter_ids(q="不存在的关键词") == set()

    def test_poc_count_in_summary(self, client: TestClient) -> None:
        payload = client.get("/api/v1/vulnerabilities", params={"limit": 100}).json()
        counts = {item["vuln_id"]: item["poc_count"] for item in payload["items"]}
        assert counts == {
            "CVE-FILTER-A": 2,
            "CVE-FILTER-B": 0,
            "CVE-FILTER-C": 0,
            "CVE-FILTER-D": 0,
        }
        enriched = {item["vuln_id"]: item["enriched"] for item in payload["items"]}
        assert enriched["CVE-FILTER-A"] is True and enriched["CVE-FILTER-C"] is False

    def test_pagination_with_filter(self, client: TestClient) -> None:
        payload = client.get(
            "/api/v1/vulnerabilities", params={"limit": 2, "offset": 0, "source": "ghsa"}
        ).json()
        assert payload["total"] == 2
        assert [item["vuln_id"] for item in payload["items"]] == ["CVE-FILTER-D", "CVE-FILTER-B"]
        second = client.get(
            "/api/v1/vulnerabilities", params={"limit": 2, "offset": 2, "source": "ghsa"}
        ).json()
        assert second["items"] == [] and second["total"] == 2

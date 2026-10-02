"""Day2 存储层测试（PROJECT_PLAN.md §5.2 P1）：SQLite 内存库，不依赖 PostgreSQL。

覆盖点：
    1. 引擎 / 会话工厂（内存库自动 StaticPool）与探活；
    2. ORM 元数据（表集合）与 Alembic 迁移一致；
    3. ``VulnRepository.upsert`` 幂等 + ``trace_ids``/``sources`` 并集合并；
    4. ``get_by_cve`` 大小写不敏感；
    5. ``list_recent`` 排序与 ``kev_only`` 过滤；
    6. 富化行 ``upsert_enriched`` / ``get_enriched`` 往返与 ``list_top_risk``；
    7. ``session_scope`` 提交后数据对后续会话可见。

Note:
    本模块在 SQLAlchemy / aiosqlite 缺失时会整体 skip（例如仅装了 Day1 依赖的环境）。
    安装命令：``pip install "sqlalchemy[asyncio]" aiosqlite``（可加国内镜像）。
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import datetime, timedelta
from typing import Any

import pytest

pytest.importorskip("sqlalchemy", reason="需要 sqlalchemy：pip install sqlalchemy[asyncio] aiosqlite")
pytest.importorskip("aiosqlite", reason="需要 aiosqlite：pip install aiosqlite")

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession  # noqa: E402

from aisec_intel.models import EnrichedVuln, UnifiedVuln, utc_now  # noqa: E402
from aisec_intel.models.base import new_trace_id  # noqa: E402
from aisec_intel.storage.base import Base  # noqa: E402
from aisec_intel.storage.database import (  # noqa: E402
    create_engine,
    create_session_factory,
    init_models,
    ping,
    session_scope,
)
from aisec_intel.storage.repositories.vuln_repo import VulnRepository, normalize_vuln_id  # noqa: E402

MEMORY_DSN = "sqlite+aiosqlite:///:memory:"


@pytest.fixture()
async def engine() -> AsyncIterator[AsyncEngine]:
    """为每个用例创建独立的 SQLite 内存库引擎。"""
    eng = create_engine(MEMORY_DSN)
    await init_models(eng)
    yield eng
    await eng.dispose()


@pytest.fixture()
async def session(engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    """提供绑定到内存库的会话。"""
    factory = create_session_factory(engine)
    async with factory() as sess:
        yield sess


def make_vuln(vuln_id: str = "CVE-2024-3400", **overrides: Any) -> UnifiedVuln:
    """构造一个合法的 ``UnifiedVuln``。"""
    payload: dict[str, Any] = {
        "vuln_id": vuln_id,
        "description": "PAN-OS GlobalProtect command injection vulnerability.",
        "normalized_at": utc_now(),
    }
    payload.update(overrides)
    return UnifiedVuln(**payload)


def make_enriched(vuln_id: str = "CVE-2024-3400", **overrides: Any) -> EnrichedVuln:
    """构造一个合法的 ``EnrichedVuln``。"""
    payload: dict[str, Any] = {
        "vuln_id": vuln_id,
        "description": "PAN-OS GlobalProtect command injection vulnerability.",
        "normalized_at": utc_now(),
        "risk_score": 92.5,
        "risk_level": "critical",
        "confidence": 0.86,
        "model_used": "deepseek-chat",
        "enriched_at": utc_now(),
        "risk_breakdown": {"cvss": 60.0, "epss": 20.0, "kev": 12.5},
        "review_status": "auto_pass",
    }
    payload.update(overrides)
    return EnrichedVuln(**payload)


class TestEngineAndMetadata:
    """引擎、元数据与迁移一致性测试。"""

    async def test_ping(self, engine: AsyncEngine) -> None:
        """内存库可探活。"""
        assert await ping(engine) is True

    def test_merged_batch1(self) -> None:
        """合并用例批次 1：顺序执行 2 个子用例并汇总失败。"""
        failures: list[str] = []
        try:
            self._case_test_metadata_contains_contract_tables()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_metadata_contains_contract_tables: {type(exc).__name__}: {exc}")
        try:
            self._case_test_normalize_vuln_id()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_normalize_vuln_id: {type(exc).__name__}: {exc}")
        assert not failures, "合并用例失败：" + " | ".join(failures)
    def _case_test_metadata_contains_contract_tables(self) -> None:
        """ORM 元数据包含与迁移一致的两张表。"""
        assert {"unified_vuln", "enriched_vuln"} <= set(Base.metadata.tables)

    def _case_test_normalize_vuln_id(self) -> None:
        """主键规范化：去空格 + 大写。"""
        assert normalize_vuln_id("  cve-2024-3400 ") == "CVE-2024-3400"


class TestVulnRepository:
    """``unified_vuln`` 仓储测试。"""

    async def test_upsert_inserts_then_reads_back(self, session: AsyncSession) -> None:
        """首次 upsert 插入，``get_by_cve`` 可读回且字段完整。"""
        repo = VulnRepository(session)
        trace = new_trace_id()
        stored = await repo.upsert(
            make_vuln(trace_ids=[trace], sources=["nvd"], kev=True, epss_score=0.94, cwe_ids=["CWE-77"])
        )
        assert stored.vuln_id == "CVE-2024-3400"
        assert stored.kev is True
        assert stored.trace_ids == [trace]

        loaded = await repo.get_by_cve("cve-2024-3400")  # 大小写不敏感
        assert loaded is not None
        assert loaded.vuln_id == "CVE-2024-3400"
        assert loaded.epss_score == pytest.approx(0.94)
        assert loaded.cwe_ids == ["CWE-77"]

    async def test_upsert_is_idempotent_and_merges_trace_ids(self, session: AsyncSession) -> None:
        """重复 upsert 不产生新行，trace_ids/sources 做并集合并。"""
        repo = VulnRepository(session)
        await repo.upsert(make_vuln(trace_ids=["t1"], sources=["nvd"]))
        merged = await repo.upsert(make_vuln(trace_ids=["t2"], sources=["ghsa"], kev=True))

        assert sorted(merged.trace_ids) == ["t1", "t2"]
        assert sorted(merged.sources) == ["ghsa", "nvd"]
        assert merged.kev is True  # 第二次写入的字段生效（OR）

        rows = await repo.list_recent(limit=10)
        assert len(rows) == 1

    async def test_upsert_keeps_existing_values_when_incoming_empty(self, session: AsyncSession) -> None:
        """Day7 回归：后写记录为空值时**不得清空**先写记录的值（原「后写覆盖」缺陷）。"""
        from aisec_intel.models.unified_vuln import CVSSVector

        repo = VulnRepository(session)
        await repo.upsert(
            make_vuln(
                cvss=[CVSSVector(version="3.1", vector="CVSS:3.1/AV:N", base_score=10.0, severity="CRITICAL")],
                severity="CRITICAL",
                cwe_ids=["CWE-77"],
                description="NVD 的完整描述文本（更长）",
                epss_score=0.95,
                published_at=utc_now(),
                sources=["nvd"],
            )
        )
        # KEV 视图：无 CVSS / 无 EPSS / 无 CPE，仅有短描述与自己的 CWE
        merged = await repo.upsert(make_vuln(sources=["kev"], cwe_ids=["CWE-20"], kev=True, description="KEV short"))

        assert merged.cvss and merged.cvss[0].base_score == 10.0  # 未被清空
        assert merged.severity == "CRITICAL"  # 只升不降
        assert merged.epss_score == pytest.approx(0.95)
        assert merged.description == "NVD 的完整描述文本（更长）"  # 取最长
        assert set(merged.cwe_ids) == {"CWE-77", "CWE-20"}  # 并集
        assert merged.kev is True
        assert sorted(merged.sources) == ["kev", "nvd"]

    async def test_upsert_normalizes_primary_key(self, session: AsyncSession) -> None:
        """写入时主键被规范化（去空格 + 大写）。"""
        repo = VulnRepository(session)
        stored = await repo.upsert(make_vuln(vuln_id=" cve-2024-1111 "))
        assert stored.vuln_id == "CVE-2024-1111"
        assert (await repo.get_by_cve("CVE-2024-1111")) is not None

    async def test_get_by_cve_returns_none_when_missing(self, session: AsyncSession) -> None:
        """未命中返回 ``None``。"""
        assert await VulnRepository(session).get_by_cve("CVE-1999-0001") is None

    async def test_list_recent_orders_and_filters(self, session: AsyncSession) -> None:
        """``list_recent`` 按发布时间倒序，``kev_only`` 只返回 KEV 条目。"""
        repo = VulnRepository(session)
        now = utc_now()
        await repo.upsert(
            make_vuln(vuln_id="CVE-2024-0001", published_at=now - timedelta(days=10), normalized_at=now)
        )
        await repo.upsert(make_vuln(vuln_id="CVE-2024-0002", published_at=now, normalized_at=now, kev=True))

        recent = await repo.list_recent(limit=10)
        assert [item.vuln_id for item in recent] == ["CVE-2024-0002", "CVE-2024-0001"]

        kev_only = await repo.list_recent(limit=10, kev_only=True)
        assert [item.vuln_id for item in kev_only] == ["CVE-2024-0002"]

    async def test_list_recent_falls_back_to_normalized_at(self, session: AsyncSession) -> None:
        """``published_at`` 为空时按 ``normalized_at`` 排序。"""
        repo = VulnRepository(session)
        base = datetime(2024, 3, 1, 12, 0, 0, tzinfo=utc_now().tzinfo)
        await repo.upsert(make_vuln(vuln_id="CVE-2024-0100", normalized_at=base))
        await repo.upsert(make_vuln(vuln_id="CVE-2024-0200", normalized_at=base + timedelta(hours=1)))
        recent = await repo.list_recent(limit=10)
        assert [item.vuln_id for item in recent] == ["CVE-2024-0200", "CVE-2024-0100"]


class TestEnrichedRepository:
    """``enriched_vuln`` 仓储测试。"""

    async def test_upsert_enriched_requires_parent_row(self, session: AsyncSession) -> None:
        """父表缺失时写入富化结果必须报错（§10.2 不变式 4）。"""
        with pytest.raises(ValueError, match="unified_vuln"):
            await VulnRepository(session).upsert_enriched(make_enriched())

    async def test_roundtrip_preserves_dimensions(self, session: AsyncSession) -> None:
        """富化行写入后可完整还原（含五维度与链路）。"""
        repo = VulnRepository(session)
        await repo.upsert(make_vuln(trace_ids=["t1"]))
        enriched = make_enriched(
            affected_assets=[
                {
                    "asset_type": "service",
                    "name": "GlobalProtect",
                    "vendor": "Palo Alto",
                    "confidence": 0.9,
                    "evidence_refs": ["t1"],
                }
            ],
            exploits=[{"source": "exploitdb", "url": "https://example.com/1", "maturity": "poc"}],
        )
        await repo.upsert_enriched(enriched)

        loaded = await repo.get_enriched("CVE-2024-3400")
        assert loaded is not None
        assert loaded.affected_assets[0].name == "GlobalProtect"
        assert loaded.exploits[0].maturity == "poc"
        assert loaded.risk_score == pytest.approx(92.5)
        assert loaded.trace_ids == ["t1"]  # 父字段同样还原

    async def test_get_enriched_returns_none_when_missing(self, session: AsyncSession) -> None:
        """未富化时返回 ``None``。"""
        assert await VulnRepository(session).get_enriched("CVE-2024-3400") is None

    async def test_upsert_enriched_is_idempotent(self, session: AsyncSession) -> None:
        """重复写入富化结果更新同一行而非新增。"""
        repo = VulnRepository(session)
        await repo.upsert(make_vuln())
        await repo.upsert_enriched(make_enriched(risk_score=10.0, risk_level="low"))
        await repo.upsert_enriched(make_enriched(risk_score=95.0, risk_level="critical"))
        assert await repo.list_top_risk(limit=5) == [("CVE-2024-3400", 95.0, "critical")]

    async def test_list_top_risk_orders_desc(self, session: AsyncSession) -> None:
        """``list_top_risk`` 按风险分倒序。"""
        repo = VulnRepository(session)
        for cve, score, level in [
            ("CVE-2024-1000", 12.0, "low"),
            ("CVE-2024-1001", 88.0, "high"),
            ("CVE-2024-1002", 55.0, "medium"),
        ]:
            await repo.upsert(make_vuln(vuln_id=cve))
            await repo.upsert_enriched(make_enriched(vuln_id=cve, risk_score=score, risk_level=level))
        assert [row[0] for row in await repo.list_top_risk(limit=2)] == ["CVE-2024-1001", "CVE-2024-1002"]


class TestSessionScope:
    """``session_scope`` 事务语义测试。"""

    async def test_committed_data_is_visible_after_scope(self, engine: AsyncEngine) -> None:
        """``session_scope`` 退出时提交，后续会话可读到数据。"""
        async with session_scope(engine) as sess:
            await VulnRepository(sess).upsert(make_vuln(vuln_id="CVE-2024-7777"))

        async with session_scope(engine) as sess:
            loaded = await VulnRepository(sess).get_by_cve("CVE-2024-7777")
            assert loaded is not None
            assert loaded.vuln_id == "CVE-2024-7777"
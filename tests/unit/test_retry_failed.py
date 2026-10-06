"""Day23 任务 2：失败重试队列（自愈缺口）测试。

覆盖点：

1. **纯函数**：``count_retry_attempts`` / ``append_retry_step`` / ``mark_permanently_failed`` /
   ``as_unified`` / ``bump_contract_version``；
2. **队列主流程** ``retry_failed``（SQLite 内存库 + 桩 ``enrich_vuln``，不调 LLM、不联网）：
   恢复（recovered）/ 仍失败（retry_failed）/ 第 3 次用尽 → ``permanently_failed`` /
   已耗尽则直接补齐终态（不再重跑图）/ 空队列；
3. **常量一致性**：调度器常量与 ``enrich_service`` 常量同源（防止两处漂移）。

契约背景：``EnrichedVuln`` v1.2 → v1.3 新增 ``review_status='permanently_failed'``（§10.3 只增不改）。
"""

from __future__ import annotations

from typing import Any

import pytest

pytest.importorskip("sqlalchemy", reason="需要 sqlalchemy：pip install sqlalchemy[asyncio] aiosqlite")
pytest.importorskip("aiosqlite", reason="需要 aiosqlite：pip install aiosqlite")

from aisec_intel.config import Settings  # noqa: E402
from aisec_intel.models import EnrichedVuln, UnifiedVuln, utc_now  # noqa: E402
from aisec_intel.services import enrich_service  # noqa: E402
from aisec_intel.services import scheduler as scheduler_module  # noqa: E402
from aisec_intel.services.enrich_service import (  # noqa: E402
    MAX_RETRY_ATTEMPTS,
    PERMANENT_FAILURE_STATUS,
    QUEUE_REVIEW_STATUS,
    RETRY_AGENT_NAME,
    EnrichmentRun,
    append_retry_step,
    as_unified,
    bump_contract_version,
    carry_retry_history,
    count_retry_attempts,
    mark_permanently_failed,
    retry_failed,
)
from aisec_intel.storage.database import session_scope  # noqa: E402
from aisec_intel.storage.repositories.vuln_repo import VulnRepository  # noqa: E402


def make_unified(vuln_id: str) -> UnifiedVuln:
    """构造事实层实体（测试辅助）。"""
    return UnifiedVuln(
        vuln_id=vuln_id,
        title=f"{vuln_id} title",
        description=f"{vuln_id} description",
        normalized_at=utc_now(),
    )


def make_needs_human(vuln_id: str, **overrides: Any) -> EnrichedVuln:
    """构造一条「降级待人工」的富化实体（队列候选）。"""
    payload: dict[str, Any] = {
        "vuln_id": vuln_id,
        "description": f"{vuln_id} description",
        "normalized_at": utc_now(),
        "risk_score": 42.0,
        "risk_level": "high",
        "confidence": 0.0,
        "review_status": QUEUE_REVIEW_STATUS,
        "review_notes": ["输出二次校验 3 次未通过"],
        "agent_trace": [],
        "model_used": "deepseek-chat",
        "enriched_at": utc_now(),
    }
    payload.update(overrides)
    return EnrichedVuln(**payload)


def make_output(entity: EnrichedVuln) -> Any:
    """把富化实体包装成 ``EnrichmentOutput``（图输出契约）。"""
    from aisec_intel.models.agent_io import EnrichmentOutput

    return EnrichmentOutput(
        enriched_vuln=entity,
        agent_steps=list(entity.agent_trace),
        confidence=entity.confidence,
    )


def success_run(vuln_id: str) -> EnrichmentRun:
    """构造一次「重试成功」的图执行结果（``review_status=auto_pass``）。"""
    fresh = make_needs_human(vuln_id, review_status="auto_pass", confidence=0.77)
    return EnrichmentRun(cve_id=vuln_id, output=make_output(fresh), duration_s=0.25)


def failure_run(vuln_id: str) -> EnrichmentRun:
    """构造一次「重试仍失败」的图执行结果（未产出结论 + 错误说明）。"""
    return EnrichmentRun(
        cve_id=vuln_id,
        output=None,
        duration_s=0.1,
        errors=["模拟二次校验失败"],
        degraded=True,
    )


def degraded_run(vuln_id: str) -> EnrichmentRun:
    """构造一次「有结论但仍降级」的图结果（生产真实场景）。

    Note:
        ``enrich_vuln`` 在输出校验未通过时也会返回**实体**（``review_status=needs_human``）+
        **本轮全新业务轨迹**，而非 ``output=None``；这正是「重试次数被重置」缺陷的触发路径。
    """
    from aisec_intel.models.enriched_vuln import AgentStep

    business_step = AgentStep(
        agent="extractor",
        round=0,
        confidence=0.46,
        latency_ms=12,
        model_used="retrieval-only",
        output_digest="本轮业务抽取摘要",
    )
    fresh = make_needs_human(
        vuln_id,
        review_notes=["本轮业务说明"],
        agent_trace=[business_step],
    )
    return EnrichmentRun(
        cve_id=vuln_id,
        output=make_output(fresh),
        duration_s=0.2,
        errors=["attack_mapper: 无法映射 ATT&CK（无 LLM 且 CWE 未登记兜底表）"],
        degraded=True,
    )


class TestPureHelpers:
    """纯函数（无 IO：重试次数口径与留痕）。"""

    def test_count_ignores_other_agents(self) -> None:
        """只统计 ``auto_retry`` 节点条目，业务节点不计入重试次数。"""
        entity = make_needs_human("CVE-2024-0001")
        assert count_retry_attempts(entity) == 0
        once = append_retry_step(entity, attempt=1, status="retry_failed", digest="x")
        assert count_retry_attempts(once) == 1
        assert entity.agent_trace == []  # 纯函数：原对象不被改写

    def test_append_step_records_status_and_note(self) -> None:
        """重试轨迹含状态前缀、轮次、错误原因，并追加 ``review_notes`` 说明。"""
        updated = append_retry_step(
            make_needs_human("CVE-2024-0002"),
            attempt=2,
            status="retry_failed",
            digest="仍失败",
            error="boom",
            latency_ms=120,
            model_used="retry-queue",
            notes=["自动重试第 2/3 次仍失败"],
        )
        step = updated.agent_trace[-1]
        assert step.agent == RETRY_AGENT_NAME
        assert step.round == 2
        assert step.output_digest.startswith("[retry_failed]")
        assert step.error == "boom" and step.latency_ms == 120
        assert updated.review_notes[-1] == "自动重试第 2/3 次仍失败"

    def test_mark_permanently_failed_keeps_conclusions(self) -> None:
        """标记终态：状态与置信度改写，既有富化结论（风险分）保留不删。"""
        marked = mark_permanently_failed(
            make_needs_human("CVE-2024-0003"), reason="已达最大重试次数 3", attempts=3
        )
        assert marked.review_status == PERMANENT_FAILURE_STATUS
        assert marked.confidence == 0.0
        assert marked.risk_score == 42.0
        assert count_retry_attempts(marked) == 1  # 终态轨迹同样计入次数
        assert "permanently_failed" in marked.review_notes[-1]

    def test_as_unified_drops_enrichment_fields(self) -> None:
        """还原事实层视图：只保留父契约字段（避免把 L3 结论当事实回喂）。"""
        entity = make_needs_human("CVE-2024-0004")
        base = as_unified(entity)
        assert type(base) is UnifiedVuln
        assert base.vuln_id == entity.vuln_id
        assert not hasattr(base, "review_status")

    def test_bump_contract_version_upgrades_legacy_row(self) -> None:
        """历史 v1.2 行被重试后抬到当前契约版本（避免 v1.2 + permanently_failed 组合）。"""
        legacy = make_needs_human("CVE-2024-0005", schema_version="1.2")
        assert bump_contract_version(legacy).schema_version == "1.3"

    def test_carry_retry_history_keeps_attempts(self) -> None:
        """重跑图产出全新轨迹时，历史 ``auto_retry`` 条目与重试说明必须并回。"""
        previous = append_retry_step(
            make_needs_human("CVE-2024-0006"),
            attempt=1,
            status="retry_failed",
            digest="第 1 次失败",
            error="e",
            notes=["自动重试第 1/3 次仍失败：e"],
        )
        fresh = make_needs_human("CVE-2024-0006", review_notes=["本轮业务说明"])
        merged = carry_retry_history(previous, fresh)
        assert count_retry_attempts(merged) == 1
        assert merged.review_notes[0] == "自动重试第 1/3 次仍失败：e"
        assert "本轮业务说明" in merged.review_notes


class TestConstantsMatchScheduler:
    """调度器与富化服务的重试参数必须同源（防止两处漂移）。"""

    def test_batch_and_attempts(self) -> None:
        """``RETRY_BATCH_SIZE`` / ``RETRY_MAX_ATTEMPTS`` 与 enrich_service 一致。"""
        assert scheduler_module.RETRY_BATCH_SIZE == enrich_service.DEFAULT_RETRY_BATCH_SIZE
        assert scheduler_module.RETRY_MAX_ATTEMPTS == MAX_RETRY_ATTEMPTS

    def test_cron_is_daily_2am(self) -> None:
        """每日 02:00 触发（cron ``0 2 * * *``），job id 固定。"""
        assert (scheduler_module.RETRY_CRON_HOUR, scheduler_module.RETRY_CRON_MINUTE) == (2, 0)
        assert scheduler_module.RETRY_JOB_ID == "maintenance:retry-failed"


@pytest.fixture()
def retry_engine(memory_engine: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
    """把富化服务的数据引擎指向 SQLite 内存库（离线可跑，无需 PostgreSQL）。"""
    monkeypatch.setattr(enrich_service, "get_engine", lambda settings: memory_engine)
    return memory_engine


async def seed_rows(engine: Any, entities: list[EnrichedVuln]) -> None:
    """写入事实层 + 富化层（父子行各一条）。"""
    async with session_scope(engine) as session:
        repo = VulnRepository(session)
        for entity in entities:
            await repo.upsert(make_unified(entity.vuln_id))
            await repo.upsert_enriched(entity)


async def read_back(engine: Any, vuln_id: str) -> EnrichedVuln:
    """按主键读回富化实体（断言落库结果）。"""
    async with session_scope(engine) as session:
        found = await VulnRepository(session).get_enriched(vuln_id)
    assert found is not None
    return found


def stub_run(run: EnrichmentRun) -> Any:
    """把固定结果包装成可 ``await`` 的 ``enrich_vuln`` 桩函数。"""

    async def _call(*args: Any, **kwargs: Any) -> EnrichmentRun:
        return run

    return _call


class TestRetryQueue:
    """``retry_failed`` 队列主流程（桩 ``enrich_vuln``，不调 LLM）。"""

    async def test_recovered_row_leaves_queue(
        self, retry_engine: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """重试成功 → 复核状态回 ``auto_pass`` + 轨迹留痕，且不再出现在队列中。"""
        await seed_rows(retry_engine, [make_needs_human("CVE-2024-3001")])
        monkeypatch.setattr(enrich_service, "enrich_vuln", stub_run(success_run("CVE-2024-3001")))
        settings = Settings(_env_file=None)

        report = await retry_failed(settings, use_llm=False)

        assert (report.scanned, report.recovered, report.retry_failed, report.permanently_failed) == (1, 1, 0, 0)
        row = await read_back(retry_engine, "CVE-2024-3001")
        assert row.review_status == "auto_pass"
        assert count_retry_attempts(row) == 1
        assert row.schema_version == "1.3"
        assert await enrich_service.load_retry_candidates(settings) == []

    async def test_third_failure_marks_permanently_failed(
        self, retry_engine: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """连续失败：第 1/2 次保留 ``needs_human``，第 3 次用尽 → ``permanently_failed``。"""
        await seed_rows(retry_engine, [make_needs_human("CVE-2024-3002")])
        monkeypatch.setattr(enrich_service, "enrich_vuln", stub_run(failure_run("CVE-2024-3002")))
        settings = Settings(_env_file=None)

        first = await retry_failed(settings, use_llm=False)
        assert (first.retry_failed, first.permanently_failed) == (1, 0)
        row = await read_back(retry_engine, "CVE-2024-3002")
        assert row.review_status == QUEUE_REVIEW_STATUS and count_retry_attempts(row) == 1

        second = await retry_failed(settings, use_llm=False)
        assert (second.retry_failed, second.permanently_failed) == (1, 0)
        assert count_retry_attempts(await read_back(retry_engine, "CVE-2024-3002")) == 2

        third = await retry_failed(settings, use_llm=False)
        assert (third.retry_failed, third.permanently_failed) == (0, 1)
        row = await read_back(retry_engine, "CVE-2024-3002")
        assert row.review_status == PERMANENT_FAILURE_STATUS
        assert row.confidence == 0.0 and count_retry_attempts(row) == 3
        assert await enrich_service.load_retry_candidates(settings) == []

    async def test_degraded_rerun_keeps_retry_counter(
        self, retry_engine: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """回归（Day23 实测缺陷）：重跑图返回「有结论但仍降级」时，重试次数必须继续累加。

        否则 ``agent_trace`` 被本轮全新轨迹覆盖 → 计数永远停在 1 → 到不了终态。
        """
        first = append_retry_step(
            make_needs_human("CVE-2024-3005"), attempt=1, status="retry_failed", digest="第 1 次失败", error="e"
        )
        await seed_rows(retry_engine, [first])
        monkeypatch.setattr(enrich_service, "enrich_vuln", stub_run(degraded_run("CVE-2024-3005")))
        settings = Settings(_env_file=None)

        report = await retry_failed(settings, use_llm=False)

        assert (report.scanned, report.retry_failed) == (1, 1)
        row = await read_back(retry_engine, "CVE-2024-3005")
        assert count_retry_attempts(row) == 2  # 1（历史）+ 1（本轮）
        assert row.review_status == QUEUE_REVIEW_STATUS
        assert any(step.agent == "extractor" for step in row.agent_trace)  # 本轮业务轨迹保留

    async def test_exhausted_candidate_is_not_rerun(
        self, retry_engine: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """已达上限仍留在队列的历史行：直接补齐终态，**不再重跑图**。"""
        entity = make_needs_human("CVE-2024-3003")
        for attempt in (1, 2, 3):
            entity = append_retry_step(entity, attempt=attempt, status="retry_failed", digest="x", error="e")
        await seed_rows(retry_engine, [entity])

        async def _boom(*args: Any, **kwargs: Any) -> EnrichmentRun:
            raise AssertionError("重试次数已耗尽时不应重跑富化图")

        monkeypatch.setattr(enrich_service, "enrich_vuln", _boom)

        report = await retry_failed(Settings(_env_file=None), use_llm=False)

        assert (report.scanned, report.permanently_failed) == (1, 1)
        row = await read_back(retry_engine, "CVE-2024-3003")
        assert row.review_status == PERMANENT_FAILURE_STATUS
        assert count_retry_attempts(row) >= MAX_RETRY_ATTEMPTS

    async def test_single_failure_is_isolated(
        self, retry_engine: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """单条重试抛异常不影响整轮（失败隔离，不向外抛）。"""
        await seed_rows(retry_engine, [make_needs_human("CVE-2024-3004")])

        async def _boom(*args: Any, **kwargs: Any) -> EnrichmentRun:
            raise RuntimeError("模拟检索崩溃")

        monkeypatch.setattr(enrich_service, "enrich_vuln", _boom)

        report = await retry_failed(Settings(_env_file=None), use_llm=False)

        assert report.scanned == 1 and report.outcomes == []
        row = await read_back(retry_engine, "CVE-2024-3004")
        assert row.review_status == QUEUE_REVIEW_STATUS  # 保持待人工，等下一轮

    async def test_empty_queue_is_noop(self, retry_engine: Any) -> None:
        """队列为空时不报错、不调 LLM，摘要说明「扫描 0 条」。"""
        report = await retry_failed(Settings(_env_file=None), use_llm=False)
        assert (report.scanned, report.recovered, report.permanently_failed) == (0, 0, 0)
        assert "扫描 0 条" in report.summary()

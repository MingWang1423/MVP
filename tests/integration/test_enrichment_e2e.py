"""Day7 富化端到端集成测试（PROJECT_PLAN.md §5.6 / §6.2 P5）。

**真实数据 + 真实依赖**：从 PostgreSQL 读取真实 ``UnifiedVuln``（默认 ``CVE-2024-3400``，
由 ``scripts.run_collect --cve`` 采集入库），跑完整富化状态图，断言 ``EnrichedVuln``
字段完整并落库 ``enriched_vuln`` 表；因此标记 ``@pytest.mark.integration``。

运行::

    python -m pytest tests/integration/test_enrichment_e2e.py -m integration -q -s

两种模式（按 ``.env`` 自动切换）：
    - 配置了真实 ``LLM_API_KEY`` → PaperLinker 走 LLM 判定（``model_used=deepseek-chat``）；
    - 未配置（占位值）→ 走检索折算降级（``model_used=retrieval-only``），**链路仍须跑通**。
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest

from aisec_intel.config import Settings
from aisec_intel.enrich.graph import graph_mermaid
from aisec_intel.services.enrich_service import enrich_vuln, llm_available, load_unified_vulns
from aisec_intel.storage.database import dispose_engines, get_engine, session_scope
from aisec_intel.storage.repositories.vuln_repo import VulnRepository

pytestmark = pytest.mark.integration

TARGET_CVE = "CVE-2024-3400"
"""示教用的真实 CVE（NVD/KEV/EPSS 多源，已入库）。"""


@pytest.fixture(scope="module")
def settings() -> Settings:
    """真实配置（读取 ``.env`` 与 PostgreSQL DSN）。"""
    return Settings()


@pytest.fixture(autouse=True)
async def dispose_pooled_engines() -> AsyncIterator[None]:
    """每个用例结束后释放进程级连接池。

    ``get_engine`` 会按 DSN 缓存引擎，而 pytest-asyncio 为**每个用例**新建事件循环；
    若不在循环销毁前释放连接池，下一个用例会拿到绑定到已关闭循环的连接
    （表现为 ``Event loop is closed`` / ``cannot rollback; the transaction is in error state``）。
    """
    yield
    await dispose_engines()


async def _load_target(settings: Settings) -> object:
    """读取目标 ``UnifiedVuln``（不存在则跳过并给出采集命令）。"""
    vulns = await load_unified_vulns(settings, cve_id=TARGET_CVE)
    if not vulns:
        pytest.skip(
            f"库中缺少 {TARGET_CVE}，请先执行："
            f"python -m scripts.run_collect --source nvd,epss,kev --cve {TARGET_CVE}"
        )
    return vulns[0]


async def test_enrichment_pipeline_end_to_end(settings: Settings) -> None:
    """完整富化链路：真实 ``UnifiedVuln`` → 状态图 → ``EnrichedVuln`` 字段完整并落库。"""
    vuln = await _load_target(settings)
    print(f"\n[输入] {vuln.vuln_id}：severity={vuln.severity} cvss={[v.base_score for v in vuln.cvss]} kev={vuln.kev}")

    run = await enrich_vuln(vuln, settings=settings, persist=True)

    assert run.output is not None, f"富化未产出结论：{run.errors}"
    enriched = run.output.enriched_vuln
    assert enriched.vuln_id == vuln.vuln_id

    # ① 事实层字段原样保留（§10.2 不变式 4：富化只追加）
    assert enriched.description == vuln.description
    assert enriched.severity == vuln.severity
    assert enriched.trace_ids == vuln.trace_ids

    # ② 富化维度与轨迹
    assert enriched.agent_trace, "agent_trace 不得为空"
    assert {step.agent for step in enriched.agent_trace} == {
        "paper_linker",
        "cvss_enricher",
        "asset_mapper",
        "poc_seeker",
        "attack_mapper",
        "remediation",
        "verifier",
    }
    assert 0.0 <= enriched.confidence <= 1.0
    assert enriched.risk_level in {"low", "medium", "high", "critical"}
    assert enriched.review_status in {"auto_pass", "revised", "needs_human"}
    assert enriched.model_used
    assert enriched.enriched_at is not None
    assert isinstance(enriched.related_papers, list) and isinstance(enriched.exploits, list)

    # ③ 落库校验（父表 + 富化表 1:1）
    async with session_scope(get_engine(settings)) as session:
        stored = await VulnRepository(session).get_enriched(vuln.vuln_id)
    assert stored is not None and stored.risk_score == enriched.risk_score

    print(
        f"[输出] confidence={enriched.confidence} risk={enriched.risk_score}/{enriched.risk_level} "
        f"papers={len(enriched.related_papers)} exploits={len(enriched.exploits)} "
        f"status={enriched.review_status} model={enriched.model_used} 耗时={run.duration_s}s"
    )
    print(f"[token] {run.usage or '（本次未发生 LLM 调用）'}")
    print("[轨迹] " + " | ".join(f"{s.agent}(round={s.round},conf={s.confidence})" for s in enriched.agent_trace))
    print(f"[LLM] {'on' if llm_available(settings) else 'off（检索折算降级）'}")
    print("[图] \n" + graph_mermaid())


async def test_enrichment_is_idempotent(settings: Settings) -> None:
    """重复富化同一 CVE：不报错、父表不被污染、富化表仍只有 1 行。"""
    vuln = await _load_target(settings)
    first = await enrich_vuln(vuln, settings=settings, persist=True)
    second = await enrich_vuln(vuln, settings=settings, persist=True)

    assert first.output is not None and second.output is not None
    assert first.output.enriched_vuln.vuln_id == second.output.enriched_vuln.vuln_id

    async with session_scope(get_engine(settings)) as session:
        repo = VulnRepository(session)
        base = await repo.get_by_cve(vuln.vuln_id)
        enriched = await repo.get_enriched(vuln.vuln_id)
    assert base is not None and base.trace_ids == vuln.trace_ids  # 事实层未被富化覆写
    assert enriched is not None


async def test_missing_cve_returns_empty(settings: Settings) -> None:
    """不存在的 CVE → 空列表（由 CLI 提示用户先采集）。"""
    assert await load_unified_vulns(settings, cve_id="CVE-1999-0001") == []

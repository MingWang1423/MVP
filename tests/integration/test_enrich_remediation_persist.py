"""Day17 任务 1：富化服务把「修复建议」写入 ``remediation_json`` 的集成测试。

不触网、不调 LLM：用**注入的假图**返回含 ``remediation`` 的最终状态，
验证 :func:`aisec_intel.services.enrich_service.enrich_vuln` 会：
    1. 把 ``Remediation`` 快照写入 ``EnrichedVuln.remediation_json``；
    2. 落库到 ``enriched_vuln``（内存 SQLite，等价迁移 0007 新列）；
    3. 同时保留 ``EnrichmentOutput.remediation``（内存态不丢字段）。
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import pytest

pytest.importorskip("sqlalchemy", reason="需要 sqlalchemy：pip install sqlalchemy[asyncio] aiosqlite")
pytest.importorskip("aiosqlite", reason="需要 aiosqlite：pip install aiosqlite")

from aisec_intel.config import Settings  # noqa: E402
from aisec_intel.models import EnrichedVuln, UnifiedVuln, utc_now  # noqa: E402
from aisec_intel.models.agent_io import Remediation  # noqa: E402
from aisec_intel.models.enriched_vuln import AgentStep  # noqa: E402
from aisec_intel.services.enrich_service import enrich_vuln  # noqa: E402
from aisec_intel.storage.database import dispose_engines, get_engine, init_models, session_scope  # noqa: E402
from aisec_intel.storage.repositories.vuln_repo import VulnRepository  # noqa: E402

MEMORY_DSN = "sqlite+aiosqlite:///:memory:"

VULN_ID = "CVE-2024-3400"


class _FakeGraph:
    """假图：直接回放预置的最终状态（避免真实跑 7 个 Agent）。"""

    def __init__(self, state: dict[str, Any]) -> None:
        self._state = state

    async def ainvoke(self, state: Any, config: Any | None = None) -> dict[str, Any]:
        """忽略入参，返回预置状态。"""
        del state, config
        return self._state


def _settings() -> Settings:
    """全离线配置（SQLite 内存库 + 降级模式，不启用 LLM）。"""
    return Settings(degraded_mode=True, database_url=MEMORY_DSN, llm_provider="deepseek", llm_api_key="")


@pytest.fixture(autouse=True)
async def _dispose_engines() -> AsyncIterator[None]:
    """释放按 DSN 缓存的引擎，避免跨用例事件循环复用连接。"""
    yield
    await dispose_engines()


def _make_vuln() -> UnifiedVuln:
    """构造待富化的事实层实体。"""
    return UnifiedVuln(
        vuln_id=VULN_ID,
        title="PAN-OS GlobalProtect command injection",
        description="GlobalProtect allows an unauthenticated attacker to execute arbitrary OS commands.",
        kev=True,
        normalized_at=utc_now(),
    )


def _make_enriched() -> EnrichedVuln:
    """构造假图返回的富化实体（尚未带修复建议）。"""
    return EnrichedVuln(
        vuln_id=VULN_ID,
        description="GlobalProtect allows an unauthenticated attacker to execute arbitrary OS commands.",
        kev=True,
        normalized_at=utc_now(),
        risk_score=96.0,
        risk_level="critical",
        confidence=0.85,
        model_used="no-llm",
        enriched_at=utc_now(),
    )


def _remediation() -> Remediation:
    """构造修复建议（确定性兜底路径的典型产物）。"""
    return Remediation(
        summary="升级 PAN-OS 至 10.2.9-h1 及以上版本",
        fixed_versions=["10.2.9-h1"],
        mitigations=["关闭 GlobalProtect 或限制来源", "启用威胁防护签名"],
        patch_urls=["https://security.paloaltonetworks.com/CVE-2024-3400"],
        confidence=0.8,
    )


async def test_enrich_vuln_persists_remediation_json() -> None:
    """富化落库时修复建议写入 ``remediation_json`` 并可从库中读回。"""
    settings = _settings()
    engine = get_engine(settings)
    await init_models(engine)
    async with session_scope(engine) as session:
        await VulnRepository(session).upsert(_make_vuln())

    remediation = _remediation()
    state: dict[str, Any] = {
        "enriched_vuln": _make_enriched(),
        "remediation": remediation,
        "agent_steps": [
            AgentStep(
                agent="remediation",
                confidence=0.8,
                latency_ms=12,
                model_used="no-llm",
                output_digest="fallback patches=1 mitigations=2",
            )
        ],
        "confidence": 0.85,
        "errors": [],
        "cvss_inferred": [],
    }
    run = await enrich_vuln(
        _make_vuln(),
        settings=settings,
        deps=None,
        graph=_FakeGraph(state),
        persist=True,
    )

    assert run.output is not None
    assert run.output.remediation == remediation
    assert run.output.enriched_vuln.remediation_json == remediation.model_dump(mode="json")

    async with session_scope(engine) as session:
        stored = await VulnRepository(session).get_enriched(VULN_ID)
    assert stored is not None
    assert stored.remediation_json is not None
    assert stored.remediation_json["summary"] == "升级 PAN-OS 至 10.2.9-h1 及以上版本"
    assert stored.remediation_json["fixed_versions"] == ["10.2.9-h1"]
    assert stored.remediation_json["patch_urls"] == ["https://security.paloaltonetworks.com/CVE-2024-3400"]


async def test_enrich_vuln_without_remediation_keeps_none() -> None:
    """未产出修复建议时列保持 ``NULL``（不影响既有数据）。"""
    settings = _settings()
    engine = get_engine(settings)
    await init_models(engine)
    async with session_scope(engine) as session:
        await VulnRepository(session).upsert(_make_vuln())

    state: dict[str, Any] = {
        "enriched_vuln": _make_enriched(),
        "remediation": None,
        "agent_steps": [],
        "confidence": 0.7,
        "errors": [],
        "cvss_inferred": [],
    }
    run = await enrich_vuln(_make_vuln(), settings=settings, graph=_FakeGraph(state), persist=True)
    assert run.output is not None
    assert run.output.enriched_vuln.remediation_json is None

    async with session_scope(engine) as session:
        stored = await VulnRepository(session).get_enriched(VULN_ID)
    assert stored is not None and stored.remediation_json is None

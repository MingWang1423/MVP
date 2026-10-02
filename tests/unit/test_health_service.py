"""Day17 任务 3.4：组件健康检查与就绪口径测试（``services/health_service.py``）。

覆盖点：
    1. ``overall_status`` 聚合口径（硬依赖 PG 不可用 → ``error``；其它组件降级 → ``degraded``）；
    2. LLM 组件为**配置检查**（未配置 Key → ``degraded``；provider=ollama → ``up``）；
    3. PostgreSQL 探针在 SQLite 内存库上返回 ``up``（本地降级可复现）；
    4. 组件状态写入 ``aisec_component_up`` 指标。
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest

pytest.importorskip("sqlalchemy", reason="需要 sqlalchemy：pip install sqlalchemy[asyncio] aiosqlite")
pytest.importorskip("aiosqlite", reason="需要 aiosqlite：pip install aiosqlite")

from aisec_intel.config import Settings  # noqa: E402
from aisec_intel.services.health_service import (  # noqa: E402
    ComponentHealth,
    check_llm,
    check_postgres,
    overall_status,
    record_component_gauges,
)
from aisec_intel.services.metrics_service import (  # noqa: E402
    M_COMPONENT_UP,
    MetricsRegistry,
)
from aisec_intel.storage.database import dispose_engines  # noqa: E402

MEMORY_DSN = "sqlite+aiosqlite:///:memory:"


@pytest.fixture(autouse=True)
async def _dispose_engines() -> AsyncIterator[None]:
    """每个用例后释放按 DSN 缓存的引擎（避免跨事件循环复用连接池）。"""
    yield
    await dispose_engines()


class TestOverallStatus:
    """聚合口径（纯函数）。"""

    def test_all_up(self) -> None:
        """全部组件可用 → ``ok``。"""
        components = [
            ComponentHealth("pg", "up", ""),
            ComponentHealth("neo4j", "up", ""),
            ComponentHealth("chroma", "up", ""),
            ComponentHealth("llm", "up", ""),
        ]
        assert overall_status(components) == "ok"

    def test_hard_dependency_down_is_error(self) -> None:
        """PostgreSQL 不可用 → ``error``（即使其它组件正常）。"""
        components = [ComponentHealth("pg", "down", "boom"), ComponentHealth("neo4j", "up", "")]
        assert overall_status(components) == "error"

    def test_soft_dependency_down_is_degraded(self) -> None:
        """仅软依赖降级（Neo4j/Chroma/LLM）→ ``degraded``（服务仍可提供降级能力）。"""
        components = [
            ComponentHealth("pg", "up", ""),
            ComponentHealth("neo4j", "down", "bolt refused"),
            ComponentHealth("chroma", "degraded", "内存后端"),
            ComponentHealth("llm", "degraded", "未配置 Key"),
        ]
        assert overall_status(components) == "degraded"

    def test_empty_is_ok(self) -> None:
        """空列表视为 ``ok``（便于探针降级场景）。"""
        assert overall_status([]) == "ok"


class TestComponentProbes:
    """单组件探针。"""

    async def test_postgres_probe_up_on_sqlite(self) -> None:
        """SQLite 降级库上 ``SELECT 1`` 成功 → ``up``。"""
        settings = Settings(degraded_mode=True, database_url=MEMORY_DSN)
        health = await check_postgres(settings)
        assert health.status == "up"
        assert health.name == "pg"
        assert health.latency_ms >= 0

    async def test_llm_probe_config_only(self) -> None:
        """LLM 探针只做配置检查：未配置 Key → ``degraded``；ollama → ``up``。"""
        degraded = await check_llm(Settings(degraded_mode=False, llm_api_key="", llm_provider="deepseek"))
        assert degraded.status == "degraded"
        assert "LLM_API_KEY" in degraded.detail

        configured = await check_llm(
            Settings(degraded_mode=False, llm_api_key="sk-unit-test-key", llm_provider="deepseek")
        )
        assert configured.status == "up"

        ollama = await check_llm(Settings(degraded_mode=False, llm_api_key="", llm_provider="ollama"))
        assert ollama.status == "up"


class TestGauges:
    """组件状态指标。"""

    def test_record_component_gauges(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """``degraded`` 视为可用（1），``down`` 记为 0。"""
        import aisec_intel.services.health_service as module

        fresh = MetricsRegistry()
        monkeypatch.setattr(module, "METRICS", fresh)
        record_component_gauges(
            [
                ComponentHealth("pg", "up", ""),
                ComponentHealth("neo4j", "down", ""),
                ComponentHealth("llm", "degraded", ""),
            ]
        )
        assert fresh.gauge(M_COMPONENT_UP, {"component": "pg"}) == 1.0
        assert fresh.gauge(M_COMPONENT_UP, {"component": "neo4j"}) == 0.0
        assert fresh.gauge(M_COMPONENT_UP, {"component": "llm"}) == 1.0

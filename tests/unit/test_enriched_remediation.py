"""Day17 任务 1：``EnrichedVuln.remediation_json`` 契约与落库往返测试。

覆盖点：
    1. 契约 v1.2：``remediation_json`` 默认 ``None``、可携带完整修复建议快照（只增不改）；
    2. ORM 往返：``upsert_enriched`` → ``get_enriched`` 后修复建议字段完整（迁移 0007 新列）。
"""

from __future__ import annotations

from typing import Any

import pytest

pytest.importorskip("sqlalchemy", reason="需要 sqlalchemy：pip install sqlalchemy[asyncio] aiosqlite")
pytest.importorskip("aiosqlite", reason="需要 aiosqlite：pip install aiosqlite")

from aisec_intel.models import ENRICHED_VULN_SCHEMA_VERSION, EnrichedVuln, UnifiedVuln, utc_now  # noqa: E402
from aisec_intel.storage.database import session_scope  # noqa: E402
from aisec_intel.storage.repositories.vuln_repo import VulnRepository  # noqa: E402

REMEDIATION_PAYLOAD: dict[str, Any] = {
    "summary": "升级 PAN-OS 至 10.2.9-h1 及以上版本",
    "fixed_versions": ["10.2.9-h1", "11.0.3-h1"],
    "mitigations": ["关闭 GlobalProtect 或限制其管理接口来源", "启用威胁防护签名"],
    "patch_urls": ["https://security.paloaltonetworks.com/CVE-2024-3400"],
    "confidence": 0.8,
    "evidence_refs": ["t-3400"],
}
"""修复建议快照样例（与 ``Remediation.model_dump(mode="json")`` 同构）。"""


def make_vuln(vuln_id: str = "CVE-2024-3400") -> UnifiedVuln:
    """构造事实层实体（测试辅助）。"""
    return UnifiedVuln(
        vuln_id=vuln_id,
        title=f"{vuln_id} title",
        description=f"{vuln_id} description",
        normalized_at=utc_now(),
    )


def make_enriched(vuln_id: str = "CVE-2024-3400", **overrides: Any) -> EnrichedVuln:
    """构造富化层实体（测试辅助）。"""
    payload: dict[str, Any] = {
        "vuln_id": vuln_id,
        "description": f"{vuln_id} description",
        "normalized_at": utc_now(),
        "risk_score": 96.0,
        "risk_level": "critical",
        "confidence": 0.85,
        "model_used": "deepseek-chat",
        "enriched_at": utc_now(),
    }
    payload.update(overrides)
    return EnrichedVuln(**payload)


class TestContract:
    """契约层（§10.3：只增不改 + schema_version 递增）。"""

    def test_default_is_none(self) -> None:
        """未产出修复建议时默认为 ``None``（向后兼容）。"""
        enriched = make_enriched()
        assert enriched.remediation_json is None
        assert enriched.schema_version == ENRICHED_VULN_SCHEMA_VERSION == "1.2"

    def test_accepts_full_payload(self) -> None:
        """可携带完整修复建议快照，且 JSON 往返不丢字段。"""
        enriched = make_enriched(remediation_json=REMEDIATION_PAYLOAD)
        dumped = enriched.model_dump(mode="json")
        assert dumped["remediation_json"]["fixed_versions"] == ["10.2.9-h1", "11.0.3-h1"]
        assert EnrichedVuln.model_validate(dumped).remediation_json == REMEDIATION_PAYLOAD

    def test_parent_fields_unchanged(self) -> None:
        """父契约 ``UnifiedVuln`` 不受影响（仍为 v1.1）。"""
        assert make_vuln().schema_version == "1.1"


class TestRepositoryRoundTrip:
    """ORM 往返（新列由迁移 0007 追加）。"""

    async def test_remediation_persisted_and_read_back(self, memory_engine: Any) -> None:
        """``upsert_enriched`` 写入的修复建议可原样读回；未刷新的旧行保持 ``None``。"""
        async with session_scope(memory_engine) as session:
            repo = VulnRepository(session)
            await repo.upsert(make_vuln("CVE-2024-3400"))
            await repo.upsert(make_vuln("CVE-2021-44228"))
            await repo.upsert_enriched(make_enriched("CVE-2024-3400", remediation_json=REMEDIATION_PAYLOAD))
            await repo.upsert_enriched(make_enriched("CVE-2021-44228"))

        async with session_scope(memory_engine) as session:
            repo = VulnRepository(session)
            with_payload = await repo.get_enriched("cve-2024-3400")
            without_payload = await repo.get_enriched("CVE-2021-44228")

        assert with_payload is not None and without_payload is not None
        assert with_payload.remediation_json == REMEDIATION_PAYLOAD
        assert with_payload.schema_version == "1.2"
        assert without_payload.remediation_json is None

    async def test_remediation_overwritten_on_re_enrich(self, memory_engine: Any) -> None:
        """重新富化时修复建议整体替换（与 ``upsert_enriched`` 既有语义一致）。"""
        async with session_scope(memory_engine) as session:
            repo = VulnRepository(session)
            await repo.upsert(make_vuln("CVE-2024-3400"))
            await repo.upsert_enriched(make_enriched("CVE-2024-3400", remediation_json=REMEDIATION_PAYLOAD))
            await repo.upsert_enriched(
                make_enriched("CVE-2024-3400", remediation_json={"summary": "已更新", "fixed_versions": []})
            )

        async with session_scope(memory_engine) as session:
            stored = await VulnRepository(session).get_enriched("CVE-2024-3400")
        assert stored is not None
        assert stored.remediation_json == {"summary": "已更新", "fixed_versions": []}

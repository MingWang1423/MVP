"""Day1 接口冻结测试：三个契约模型的实例化、校验、序列化（PROJECT_PLAN.md §10.1 / §10.2）。

覆盖点：
    1. 字段完整性（必填 / 默认值）与 ``extra="forbid"`` 行为；
    2. UTC 时间语义与 ISO8601 ``Z`` 序列化（§10.2 不变式 3）；
    3. ``trace_id`` 全链路透传（§10.2 不变式 5）；
    4. 富化「只追加不改父类」（§10.2 不变式 4）。
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest
from pydantic import ValidationError

from aisec_intel.models import (
    SCHEMA_VERSION,
    AffectedAsset,
    AgentStep,
    AttackChain,
    AttackChainStep,
    CpeMatch,
    CVSSVector,
    EnrichedVuln,
    ExploitRecord,
    PaperVulnLink,
    RawItem,
    Reference,
    UnifiedVuln,
    new_trace_id,
    utc_now,
)

SHA256_PLACEHOLDER = "a" * 64


def make_raw_item(**overrides: Any) -> RawItem:
    """构造一个合法的 ``RawItem``（可覆盖任意字段）。"""
    payload: dict[str, Any] = {
        "trace_id": new_trace_id(),
        "source": "nvd",
        "source_id": "CVE-2024-3400",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-3400",
        "raw_text": "PAN-OS GlobalProtect command injection vulnerability.",
        "fetched_at": utc_now(),
        "sha256": SHA256_PLACEHOLDER,
    }
    payload.update(overrides)
    return RawItem(**payload)


def make_unified_vuln(**overrides: Any) -> UnifiedVuln:
    """构造一个合法的 ``UnifiedVuln``（可覆盖任意字段）。"""
    payload: dict[str, Any] = {
        "vuln_id": "CVE-2024-3400",
        "description": "PAN-OS GlobalProtect command injection vulnerability.",
        "normalized_at": utc_now(),
    }
    payload.update(overrides)
    return UnifiedVuln(**payload)


def make_enriched_vuln(**overrides: Any) -> EnrichedVuln:
    """构造一个合法的 ``EnrichedVuln``（可覆盖任意字段）。"""
    payload: dict[str, Any] = {
        "vuln_id": "CVE-2024-3400",
        "description": "PAN-OS GlobalProtect command injection vulnerability.",
        "normalized_at": utc_now(),
        "risk_score": 92.5,
        "risk_level": "critical",
        "confidence": 0.86,
        "model_used": "deepseek-chat",
        "enriched_at": utc_now(),
    }
    payload.update(overrides)
    return EnrichedVuln(**payload)


class TestRawItem:
    """``RawItem`` 契约测试。"""

    def test_required_fields_and_defaults(self) -> None:
        """必填字段可构造，可选字段使用默认值。"""
        item = make_raw_item()
        assert item.schema_version == SCHEMA_VERSION
        assert item.title is None
        assert item.lang is None
        assert item.published_at is None
        assert item.meta == {}

    def test_is_frozen(self) -> None:
        """冻结模型：实例化后不可赋值。"""
        item = make_raw_item()
        with pytest.raises(ValidationError):
            item.source = "osv"  # type: ignore[misc]

    def test_extra_field_forbidden(self) -> None:
        """未声明字段直接报错（§10.2 不变式 6）。"""
        with pytest.raises(ValidationError):
            make_raw_item(llm_guess="幻觉字段")

    def test_missing_required_field(self) -> None:
        """缺少必填字段时报错。"""
        with pytest.raises(ValidationError):
            RawItem(source="nvd", source_id="x", url="u", raw_text="t", fetched_at=utc_now())

    def test_empty_identifier_rejected(self) -> None:
        """空字符串标识（trace_id）被拒绝。"""
        with pytest.raises(ValidationError):
            make_raw_item(trace_id="")

    def test_naive_datetime_normalized_to_utc(self) -> None:
        """naive 时间按 UTC 处理。"""
        item = make_raw_item(fetched_at=datetime(2024, 3, 1, 12, 0, 0))
        assert item.fetched_at.tzinfo == UTC

    def test_json_serialization_uses_iso8601_z(self) -> None:
        """JSON 序列化输出 ISO8601 ``Z`` 结尾（§10.2 不变式 3）。"""
        item = make_raw_item(
            fetched_at=datetime(2024, 3, 1, 20, 0, 0, tzinfo=timezone(timedelta(hours=8))),
            published_at=datetime(2024, 2, 29, 0, 30, 0),
        )
        dumped = item.model_dump(mode="json")
        assert dumped["fetched_at"] == "2024-03-01T12:00:00Z"
        assert dumped["published_at"] == "2024-02-29T00:30:00Z"


class TestUnifiedVuln:
    """``UnifiedVuln`` 契约测试。"""

    def test_minimal_construction(self) -> None:
        """最小构造：仅 vuln_id / description / normalized_at。"""
        vuln = make_unified_vuln()
        assert vuln.vuln_id == "CVE-2024-3400"
        assert vuln.kev is False
        assert vuln.epss_score is None
        assert vuln.sources == []
        assert vuln.trace_ids == []

    def test_nested_components(self) -> None:
        """嵌套组件（CVSS / CPE / Reference）可正常构造。"""
        vuln = make_unified_vuln(
            cvss=[
                CVSSVector(
                    version="3.1",
                    vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                    base_score=10.0,
                    severity="CRITICAL",
                )
            ],
            cpe_matches=[CpeMatch(vendor="paloaltonetworks", product="pan-os", version_end_excl="11.1.3")],
            references=[Reference(url="https://example.com/patch", source="vendor", tags=["patch"])],
            cwe_ids=["CWE-77"],
            ecosystem_packages=["PyPI:django"],
            sources=["nvd", "ghsa"],
        )
        assert vuln.cvss[0].severity == "CRITICAL"
        assert vuln.cpe_matches[0].version_end_excl == "11.1.3"
        assert vuln.references[0].tags == ["patch"]

    def test_cvss_score_out_of_range(self) -> None:
        """CVSS 基础分超出 ``[0, 10]`` 报错。"""
        with pytest.raises(ValidationError):
            CVSSVector(version="3.1", vector="x", base_score=11.0, severity="CRITICAL")

    def test_epss_score_bounds(self) -> None:
        """EPSS 概率必须在 ``[0, 1]``。"""
        with pytest.raises(ValidationError):
            make_unified_vuln(epss_score=1.5)

    def test_extra_field_forbidden(self) -> None:
        """未声明字段报错。"""
        with pytest.raises(ValidationError):
            make_unified_vuln(inferred_asset="由 LLM 猜的资产")

    def test_datetime_fields_serialized_as_utc(self) -> None:
        """published_at / modified_at / normalized_at 统一 UTC ``Z``。"""
        vuln = make_unified_vuln(
            published_at=datetime(2024, 3, 1, 20, 0, tzinfo=timezone(timedelta(hours=8))),
            modified_at=datetime(2024, 4, 1, 0, 0),
        )
        dumped = vuln.model_dump(mode="json")
        assert dumped["published_at"] == "2024-03-01T12:00:00Z"
        assert dumped["modified_at"] == "2024-04-01T00:00:00Z"


class TestEnrichedVuln:
    """``EnrichedVuln`` 契约测试。"""

    def test_five_enrichment_dimensions(self) -> None:
        """五维度字段可全部填充。"""
        enriched = make_enriched_vuln(
            affected_assets=[
                AffectedAsset(asset_type="service", name="GlobalProtect", vendor="Palo Alto", confidence=0.9)
            ],
            related_papers=[
                PaperVulnLink(paper_id="2403.01234", vuln_id="CVE-2024-3400", relation="evaluates", confidence=0.7)
            ],
            exploits=[
                ExploitRecord(source="exploitdb", url="https://example.com/1", maturity="poc", reliability=0.6)
            ],
            attack_chain=AttackChain(
                steps=[
                    AttackChainStep(
                        order=1,
                        technique_id="T1190",
                        tactic="initial-access",
                        stage="Delivery",
                        description="利用命令注入",
                        preconditions=["GlobalProtect 已启用"],
                    )
                ],
                entry_vector="network",
                privileges_required="none",
            ),
            risk_breakdown={"cvss": 60.0, "epss": 20.0, "kev": 12.5, "poc": 0.0},
        )
        assert len(enriched.affected_assets) == 1
        assert len(enriched.related_papers) == 1
        assert len(enriched.exploits) == 1
        assert enriched.attack_chain is not None
        assert enriched.attack_chain.steps[0].technique_id == "T1190"

    def test_review_status_default_and_confidence_bounds(self) -> None:
        """``review_status`` 默认 auto_pass；``confidence`` 越界报错。"""
        assert make_enriched_vuln().review_status == "auto_pass"
        with pytest.raises(ValidationError):
            make_enriched_vuln(confidence=1.01)

    def test_risk_score_bounds(self) -> None:
        """``risk_score`` 必须在 ``[0, 100]``。"""
        with pytest.raises(ValidationError):
            make_enriched_vuln(risk_score=101.0)

    def test_extra_field_forbidden(self) -> None:
        """未声明字段报错。"""
        with pytest.raises(ValidationError):
            make_enriched_vuln(unknown_dimension="x")

    def test_inherits_parent_fields_without_override(self) -> None:
        """富化只追加：父类字段与父类定义完全一致（§10.2 不变式 4）。"""
        for name, field in UnifiedVuln.model_fields.items():
            assert name in EnrichedVuln.model_fields
            assert EnrichedVuln.model_fields[name].annotation == field.annotation
        own_fields = set(EnrichedVuln.model_fields) - set(UnifiedVuln.model_fields)
        assert {"affected_assets", "related_papers", "exploits", "risk_score"} <= own_fields

    def test_agent_trace_records_steps(self) -> None:
        """``agent_trace`` 可记录 7 个 Agent 的执行步。"""
        trace = [
            AgentStep(
                agent=f"agent{i}",
                round=0,
                confidence=0.8,
                latency_ms=120,
                model_used="deepseek-chat",
                output_digest=f"digest-{i}",
            )
            for i in range(7)
        ]
        enriched = make_enriched_vuln(agent_trace=trace)
        assert len(enriched.agent_trace) == 7
        assert enriched.agent_trace[0].error is None


class TestFrozenInvariants:
    """§10.2 冻结不变式的横切测试。"""

    @pytest.mark.parametrize(
        "model_cls",
        [RawItem, UnifiedVuln, EnrichedVuln, AffectedAsset, ExploitRecord, AttackChain, AgentStep, CVSSVector],
    )
    def test_extra_forbid_enabled_everywhere(self, model_cls: type[Any]) -> None:
        """所有契约模型均开启 ``extra="forbid"``。"""
        assert model_cls.model_config.get("extra") == "forbid"

    def test_trace_id_passthrough_chain(self) -> None:
        """``RawItem.trace_id`` → ``UnifiedVuln.trace_ids`` → ``EnrichedVuln`` 证据引用。"""
        raw = make_raw_item()
        vuln = make_unified_vuln(trace_ids=[raw.trace_id])
        enriched = make_enriched_vuln(
            trace_ids=vuln.trace_ids,
            affected_assets=[
                AffectedAsset(asset_type="library", name="pan-os", confidence=0.8, evidence_refs=[raw.trace_id])
            ],
        )
        assert enriched.trace_ids == [raw.trace_id]
        assert enriched.affected_assets[0].evidence_refs == [raw.trace_id]

    def test_schema_version_default_is_frozen_value(self) -> None:
        """``schema_version`` 默认值与冻结文档一致。"""
        assert SCHEMA_VERSION == "1.0"
        assert make_raw_item().schema_version == "1.0"
        assert make_unified_vuln().schema_version == "1.0"

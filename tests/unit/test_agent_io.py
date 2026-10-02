"""Day2 Agent IO 契约测试（PROJECT_PLAN.md §3.2 / §5.2）。

覆盖点：
    1. ``EnrichmentInput`` 的一致性校验（cve_id 匹配、trace_id 必须命中链路）；
    2. ``EnrichmentOutput`` 的聚合结构与置信度边界；
    3. ``QAQuery`` 默认值与多跳上限；
    4. ``QAResponse`` 的**强制引用**约束（引用可回溯率 100%）；
    5. 所有新增契约均开启 ``extra="forbid"``。
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from aisec_intel.models import (
    AgentStep,
    Citation,
    EnrichedVuln,
    EnrichmentInput,
    EnrichmentOutput,
    QAQuery,
    QAResponse,
    ReasoningStep,
    UnifiedVuln,
)
from aisec_intel.models.base import new_trace_id, utc_now


def make_unified_vuln(**overrides: Any) -> UnifiedVuln:
    """构造一个合法的 ``UnifiedVuln``。"""
    payload: dict[str, Any] = {
        "vuln_id": "CVE-2024-3400",
        "description": "PAN-OS GlobalProtect command injection vulnerability.",
        "normalized_at": utc_now(),
    }
    payload.update(overrides)
    return UnifiedVuln(**payload)


def make_enriched_vuln(**overrides: Any) -> EnrichedVuln:
    """构造一个合法的 ``EnrichedVuln``。"""
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


def make_citation(**overrides: Any) -> Citation:
    """构造一条合法的引用。"""
    payload: dict[str, Any] = {
        "source_type": "pg",
        "locator": "unified_vuln:CVE-2024-3400",
        "quote": "PAN-OS GlobalProtect command injection vulnerability.",
    }
    payload.update(overrides)
    return Citation(**payload)


class TestCitation:
    """``Citation`` 契约测试。"""

    def test_merged_batch1(self) -> None:
        """合并用例批次 1：顺序执行 3 个子用例并汇总失败。"""
        failures: list[str] = []
        try:
            self._case_test_requires_locator()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_requires_locator: {type(exc).__name__}: {exc}")
        try:
            self._case_test_source_type_is_restricted()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_source_type_is_restricted: {type(exc).__name__}: {exc}")
        try:
            self._case_test_extra_field_forbidden()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_extra_field_forbidden: {type(exc).__name__}: {exc}")
        assert not failures, "合并用例失败：" + " | ".join(failures)
    def _case_test_requires_locator(self) -> None:
        """``locator`` 必填且非空。"""
        with pytest.raises(ValidationError):
            Citation(source_type="pg", locator="")

    def _case_test_source_type_is_restricted(self) -> None:
        """来源类型只能取四种存储之一。"""
        with pytest.raises(ValidationError):
            Citation(source_type="sqlite", locator="x")

    def _case_test_extra_field_forbidden(self) -> None:
        """未声明字段被拒绝。"""
        with pytest.raises(ValidationError):
            Citation(source_type="neo4j", locator="n1", made_up="x")


class TestEnrichmentInput:
    """``EnrichmentInput`` 契约测试。"""

    def test_merged_batch1(self) -> None:
        """合并用例批次 1：顺序执行 4 个子用例并汇总失败。"""
        failures: list[str] = []
        try:
            self._case_test_valid_input()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_valid_input: {type(exc).__name__}: {exc}")
        try:
            self._case_test_cve_id_mismatch_rejected()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_cve_id_mismatch_rejected: {type(exc).__name__}: {exc}")
        try:
            self._case_test_broken_trace_chain_rejected()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_broken_trace_chain_rejected: {type(exc).__name__}: {exc}")
        try:
            self._case_test_empty_trace_ids_allows_any_trace()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_empty_trace_ids_allows_any_trace: {type(exc).__name__}: {exc}")
        assert not failures, "合并用例失败：" + " | ".join(failures)
    def _case_test_valid_input(self) -> None:
        """cve_id 与 trace_id 一致时可构造。"""
        trace = new_trace_id()
        payload = EnrichmentInput(
            cve_id="cve-2024-3400",
            unified_vuln=make_unified_vuln(trace_ids=[trace]),
            trace_id=trace,
        )
        assert payload.schema_version == "1.0"
        assert payload.unified_vuln.vuln_id == "CVE-2024-3400"

    def _case_test_cve_id_mismatch_rejected(self) -> None:
        """``cve_id`` 与 ``unified_vuln.vuln_id`` 不一致必须报错。"""
        with pytest.raises(ValidationError, match="不一致"):
            EnrichmentInput(
                cve_id="CVE-2024-9999",
                unified_vuln=make_unified_vuln(),
                trace_id=new_trace_id(),
            )

    def _case_test_broken_trace_chain_rejected(self) -> None:
        """``trace_id`` 未命中 ``trace_ids`` 时判定链路断裂（§10.2 不变式 5）。"""
        with pytest.raises(ValidationError, match="链路已断"):
            EnrichmentInput(
                cve_id="CVE-2024-3400",
                unified_vuln=make_unified_vuln(trace_ids=["t1", "t2"]),
                trace_id="t3",
            )

    def _case_test_empty_trace_ids_allows_any_trace(self) -> None:
        """``trace_ids`` 为空（尚未采集）时不强制匹配。"""
        payload = EnrichmentInput(
            cve_id="CVE-2024-3400", unified_vuln=make_unified_vuln(), trace_id="brand-new"
        )
        assert payload.trace_id == "brand-new"


class TestEnrichmentOutput:
    """``EnrichmentOutput`` 契约测试。"""

    def test_merged_batch1(self) -> None:
        """合并用例批次 1：顺序执行 3 个子用例并汇总失败。"""
        failures: list[str] = []
        try:
            self._case_test_valid_output_with_trace()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_valid_output_with_trace: {type(exc).__name__}: {exc}")
        try:
            self._case_test_confidence_bounds()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_confidence_bounds: {type(exc).__name__}: {exc}")
        try:
            self._case_test_defaults_are_empty()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_defaults_are_empty: {type(exc).__name__}: {exc}")
        assert not failures, "合并用例失败：" + " | ".join(failures)
    def _case_test_valid_output_with_trace(self) -> None:
        """富化结果 + Agent 轨迹 + 非致命错误可同时存在。"""
        steps = [
            AgentStep(
                agent="extractor",
                confidence=0.9,
                latency_ms=1200,
                model_used="deepseek-chat",
                output_digest="抽取到 2 个受影响组件",
            )
        ]
        output = EnrichmentOutput(
            enriched_vuln=make_enriched_vuln(agent_trace=steps),
            agent_steps=steps,
            confidence=0.86,
            errors=["exploit_assessor: 外部检索超时，已降级"],
        )
        assert len(output.agent_steps) == 1
        assert output.errors[0].startswith("exploit_assessor")

    def _case_test_confidence_bounds(self) -> None:
        """``confidence`` 必须在 ``[0, 1]``。"""
        with pytest.raises(ValidationError):
            EnrichmentOutput(enriched_vuln=make_enriched_vuln(), confidence=1.2)

    def _case_test_defaults_are_empty(self) -> None:
        """``agent_steps`` 与 ``errors`` 默认为空列表。"""
        output = EnrichmentOutput(enriched_vuln=make_enriched_vuln(), confidence=0.5)
        assert output.agent_steps == []
        assert output.errors == []


class TestQAQuery:
    """``QAQuery`` 契约测试。"""

    def test_merged_batch1(self) -> None:
        """合并用例批次 1：顺序执行 3 个子用例并汇总失败。"""
        failures: list[str] = []
        try:
            self._case_test_defaults()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_defaults: {type(exc).__name__}: {exc}")
        try:
            self._case_test_empty_query_rejected()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_empty_query_rejected: {type(exc).__name__}: {exc}")
        try:
            self._case_test_max_hops_upper_bound()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_max_hops_upper_bound: {type(exc).__name__}: {exc}")
        assert not failures, "合并用例失败：" + " | ".join(failures)
    def _case_test_defaults(self) -> None:
        """默认 top_k=8、max_hops=2（≥2 跳验收要求）、session_id 为空。"""
        query = QAQuery(query="CVE-2024-3400 影响了哪些资产？", trace_id=new_trace_id())
        assert query.top_k == 8
        assert query.max_hops == 2
        assert query.session_id is None

    def _case_test_empty_query_rejected(self) -> None:
        """空问题被拒绝。"""
        with pytest.raises(ValidationError):
            QAQuery(query="", trace_id=new_trace_id())

    def _case_test_max_hops_upper_bound(self) -> None:
        """多跳上限不得超过 4（防止无限推理）。"""
        with pytest.raises(ValidationError):
            QAQuery(query="x", trace_id=new_trace_id(), max_hops=5)


class TestQAResponse:
    """``QAResponse`` 契约测试。"""

    def test_merged_batch1(self) -> None:
        """合并用例批次 1：顺序执行 6 个子用例并汇总失败。"""
        failures: list[str] = []
        try:
            self._case_test_answer_requires_citation()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_answer_requires_citation: {type(exc).__name__}: {exc}")
        try:
            self._case_test_answer_with_citation_ok()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_answer_with_citation_ok: {type(exc).__name__}: {exc}")
        try:
            self._case_test_degraded_answer_may_skip_citation()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_degraded_answer_may_skip_citation: {type(exc).__name__}: {exc}")
        try:
            self._case_test_empty_answer_without_citation_ok()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_empty_answer_without_citation_ok: {type(exc).__name__}: {exc}")
        try:
            self._case_test_reasoning_chain_and_confidence()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_reasoning_chain_and_confidence: {type(exc).__name__}: {exc}")
        try:
            self._case_test_hop_index_must_start_at_one()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_hop_index_must_start_at_one: {type(exc).__name__}: {exc}")
        assert not failures, "合并用例失败：" + " | ".join(failures)
    def _case_test_answer_requires_citation(self) -> None:
        """非降级模式下答案非空必须带引用。"""
        with pytest.raises(ValidationError, match="Citation"):
            QAResponse(answer="影响 GlobalProtect。", confidence=0.8)

    def _case_test_answer_with_citation_ok(self) -> None:
        """带引用的答案可构造。"""
        response = QAResponse(answer="影响 GlobalProtect。", citations=[make_citation()], confidence=0.8)
        assert len(response.citations) == 1

    def _case_test_degraded_answer_may_skip_citation(self) -> None:
        """降级链路（离线兜底）允许无引用。"""
        response = QAResponse(answer="离线模式下仅返回本地命中摘要。", confidence=0.3, degraded=True)
        assert response.citations == []

    def _case_test_empty_answer_without_citation_ok(self) -> None:
        """空答案（无命中）不需要引用。"""
        response = QAResponse(answer="", confidence=0.0)
        assert response.answer == ""

    def _case_test_reasoning_chain_and_confidence(self) -> None:
        """多跳推理链可构造，置信度越界报错。"""
        chain = [
            ReasoningStep(
                hop=1,
                question="该 CVE 影响哪些组件？",
                evidence=[make_citation()],
                conclusion="PAN-OS GlobalProtect",
            ),
            ReasoningStep(hop=2, question="相关论文？", evidence=[], conclusion="arXiv 2403.01234"),
        ]
        response = QAResponse(
            answer="两跳结论", citations=[make_citation()], reasoning_chain=chain, confidence=0.75
        )
        assert [step.hop for step in response.reasoning_chain] == [1, 2]
        with pytest.raises(ValidationError):
            QAResponse(answer="x", citations=[make_citation()], confidence=-0.1)

    def _case_test_hop_index_must_start_at_one(self) -> None:
        """``hop`` 从 1 开始。"""
        with pytest.raises(ValidationError):
            ReasoningStep(hop=0, question="q", conclusion="c")

    @pytest.mark.parametrize(
        "model_cls",
        [Citation, ReasoningStep, EnrichmentInput, EnrichmentOutput, QAQuery, QAResponse],
    )
    def test_extra_forbid_enabled(self, model_cls: type[Any]) -> None:
        """新增契约同样开启 ``extra="forbid"``（§10.2 不变式 6）。"""
        assert model_cls.model_config.get("extra") == "forbid"
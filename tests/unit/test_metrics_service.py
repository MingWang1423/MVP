"""Day17 任务 3.2：指标采集与 Prometheus 导出测试（``services/metrics_service.py``）。

覆盖点：
    1. 计数器 / 直方图 / 仪表盘读写与标签口径（标签排序保证输出稳定）；
    2. Prometheus 文本格式（``# HELP`` / ``# TYPE`` / ``_bucket`` / ``_sum`` / ``_count``）；
    3. 业务事件记录函数（采集 / 富化 / 问答 / LLM token）与失败率口径；
    4. 分位数估算（压测报告 P95 用）。
"""

from __future__ import annotations

import pytest

from aisec_intel.services.metrics_service import (
    M_COLLECT_DURATION,
    M_COLLECT_FAILURES,
    M_COLLECT_ITEMS,
    M_ENRICH_DURATION,
    M_ENRICH_TOTAL,
    M_LLM_TOKENS,
    MetricsRegistry,
    collect_failure_ratio,
    enrich_failure_ratio,
    record_collect,
    record_enrich,
    record_llm_failure,
    record_llm_success,
    record_llm_usage,
    record_qa,
)


@pytest.fixture()
def registry() -> MetricsRegistry:
    """每个用例一个干净注册表（不污染进程级 ``METRICS``）。"""
    return MetricsRegistry(buckets=(0.1, 0.5, 1.0))


class TestRegistryBasics:
    def test_counter_labels_and_totals(self, registry: MetricsRegistry) -> None:
        """计数器按标签独立累加，``counter_total`` 跨标签合计。"""
        registry.inc("demo_total", {"b": "2", "a": "1"})
        registry.inc("demo_total", {"a": "1", "b": "2"}, value=2)
        registry.inc("demo_total", {"a": "9"})
        assert registry.counter("demo_total", {"a": "1", "b": "2"}) == 3
        assert registry.counter_total("demo_total") == 4

    def test_histogram_buckets_are_cumulative(self, registry: MetricsRegistry) -> None:
        """直方图桶为累计计数，``_sum``/``_count`` 正确，标签顺序稳定。"""
        for value in (0.05, 0.3, 0.8, 5.0):
            registry.observe("demo_seconds", value, {"x": "1"})
        text = registry.render_prometheus()
        assert "# TYPE demo_seconds histogram" in text
        assert 'demo_seconds_bucket{x="1",le="0.1"} 1' in text
        assert 'demo_seconds_bucket{x="1",le="0.5"} 2' in text
        assert 'demo_seconds_bucket{x="1",le="1"} 3' in text
        assert 'demo_seconds_bucket{x="1",le="+Inf"} 4' in text
        assert 'demo_seconds_count{x="1"} 4' in text

    def test_gauge_and_snapshot_and_reset(self, registry: MetricsRegistry) -> None:
        """仪表盘可覆盖写入；快照含三类指标；``reset`` 清空。"""
        registry.set_gauge("demo_up", 1.0, {"component": "pg"})
        registry.set_gauge("demo_up", 0.0, {"component": "pg"})
        assert registry.gauge("demo_up", {"component": "pg"}) == 0.0
        snapshot = registry.snapshot()
        assert snapshot["gauges"]["demo_up"]
        registry.reset()
        assert registry.snapshot() == {"counters": {}, "gauges": {}, "histograms": {}}

    def test_quantile_uses_bucket_upper_bound(self, registry: MetricsRegistry) -> None:
        """分位数估算取命中桶上界（19/20 落在 0.5 桶内 → P95=0.5）。"""
        for _ in range(19):
            registry.observe("demo_seconds", 0.2)
        registry.observe("demo_seconds", 0.9)
        assert registry.histogram_quantile("demo_seconds", 0.95) == 0.5
        assert registry.histogram_quantile("demo_seconds", 1.0) == 1.0
        assert registry.histogram_count("demo_seconds") == 20


class TestBusinessRecorders:
    """业务事件记录函数（服务层实际调用的入口）。"""

    def test_collect_and_failure_ratio(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """采集条数 / 失败次数 / 耗时进入指标，失败率按「失败数 / 尝试数」计算。"""
        import aisec_intel.services.metrics_service as metrics

        fresh = MetricsRegistry()
        monkeypatch.setattr(metrics, "METRICS", fresh)
        record_collect("kev", fetched=8, failed=False, duration_s=0.4)
        record_collect("nvd", fetched=0, failed=True, duration_s=0.2)
        assert fresh.counter(M_COLLECT_ITEMS, {"source": "kev"}) == 8
        assert fresh.counter(M_COLLECT_FAILURES, {"source": "nvd"}) == 1
        assert fresh.histogram_count(M_COLLECT_DURATION) == 2
        assert collect_failure_ratio() == pytest.approx(1 / 9, rel=1e-3)

    def test_enrich_and_qa_and_llm_usage(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """富化成功/失败计数、问答降级计数、LLM token 与连续失败计数。"""
        import aisec_intel.services.metrics_service as metrics

        fresh = MetricsRegistry()
        monkeypatch.setattr(metrics, "METRICS", fresh)
        record_enrich(ok=True, duration_s=0.3)
        record_enrich(ok=False, duration_s=0.1)
        record_enrich(ok=False, duration_s=0.1)
        record_qa(ok=True, duration_s=1.2, degraded=True)
        record_llm_usage("deepseek-chat", prompt_tokens=120, completion_tokens=30)
        assert fresh.counter(M_ENRICH_TOTAL, {"status": "success"}) == 1
        assert enrich_failure_ratio() == pytest.approx(2 / 3, rel=1e-3)
        assert fresh.histogram_count(M_ENRICH_DURATION) == 3
        assert fresh.counter(M_LLM_TOKENS, {"model": "deepseek-chat", "kind": "prompt"}) == 120
        assert record_llm_failure("deepseek-chat") == 1
        assert record_llm_failure("deepseek-chat") == 2
        record_llm_success()
        assert record_llm_failure("deepseek-chat") == 1

    def test_prometheus_render_has_help_and_type(self) -> None:
        """渲染结果包含标准 ``# HELP`` / ``# TYPE`` 行且以换行结尾。"""
        fresh = MetricsRegistry()
        fresh.inc(M_COLLECT_ITEMS, {"source": "kev"}, value=3)
        text = fresh.render_prometheus()
        assert "# HELP aisec_collect_items_total" in text
        assert "# TYPE aisec_collect_items_total counter" in text
        assert 'aisec_collect_items_total{source="kev"} 3' in text
        assert text.endswith("\n")

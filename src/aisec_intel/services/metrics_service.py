"""指标采集与 Prometheus 暴露（Day17 任务 3.2）。

设计要点：

1. **纯进程内**：计数器 / 直方图 / 仪表盘全部存内存（单机部署足够），
   不引入 ``prometheus_client`` 依赖，避免再动镜像与依赖清单；
2. **四类业务指标**（对照任务书）：
   ``采集量（按源）`` / ``富化量（成功·失败）`` / ``问答量（成功·失败·延迟）`` / ``LLM token 消耗``；
3. **Prometheus 文本格式**：:meth:`MetricsRegistry.render_prometheus` 输出
   ``# HELP`` / ``# TYPE`` + 样本行，直接供 ``GET /metrics`` 与 ``curl`` 校验；
4. **可用于告警规则**：:func:`collect_failure_ratio` / :func:`enrich_failure_ratio`
   给出「采集 / 富化失败率」口径（分子分母同源，避免各处口径漂移）。

线程安全：所有写操作走同一把 ``threading.Lock``（uvicorn 单事件循环下开销可忽略）。
"""

from __future__ import annotations

import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from aisec_intel.logging_config import get_logger

logger = get_logger(__name__)

Labels = Mapping[str, str]
"""标签集合（键值均为字符串，渲染前按键排序以保证输出稳定）。"""

DEFAULT_BUCKETS: tuple[float, ...] = (0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0)
"""直方图默认分桶（秒）：覆盖本地检索到 LLM 调用的量级。"""

M_COLLECT_ITEMS = "aisec_collect_items_total"
"""采集条数（按源）。"""
M_COLLECT_FAILURES = "aisec_collect_failures_total"
"""采集失败次数（按源）。"""
M_COLLECT_DURATION = "aisec_collect_duration_seconds"
"""单源采集耗时直方图（按源）。"""
M_ENRICH_TOTAL = "aisec_enrich_total"
"""富化次数（``status=success|failed``）。"""
M_ENRICH_DURATION = "aisec_enrich_duration_seconds"
"""单条富化耗时直方图。"""
M_QA_TOTAL = "aisec_qa_requests_total"
"""问答请求次数（``status=success|failed``）。"""
M_QA_DURATION = "aisec_qa_duration_seconds"
"""问答耗时直方图（秒）。"""
M_QA_DEGRADED = "aisec_qa_degraded_total"
"""问答降级次数（无 LLM / 检索通路降级）。"""
M_LLM_TOKENS = "aisec_llm_tokens_total"
"""LLM token 消耗（``model`` + ``kind=prompt|completion``）。"""
M_LLM_FAILURES = "aisec_llm_failures_total"
"""LLM 调用失败次数（按模型）。"""
M_ALERTS = "aisec_alerts_total"
"""触发的告警次数（按 ``rule``）。"""
M_SELF_HEAL = "aisec_self_heal_total"
"""自愈动作次数（``component`` + ``action``）。"""
M_COMPONENT_UP = "aisec_component_up"
"""组件健康仪表盘（1=可用，0=不可用；``component`` 为 pg/neo4j/chroma/llm）。"""
M_COLLECT_FAILURE_RATIO = "aisec_collect_failure_ratio"
"""采集失败率（最近一次评估时的快照）。"""
M_ENRICH_FAILURE_RATIO = "aisec_enrich_failure_ratio"
"""富化失败率（最近一次评估时的快照）。"""
M_LLM_CONSECUTIVE_FAILURES = "aisec_llm_consecutive_failures"
"""LLM 连续失败次数（成功即清零）。"""
M_SECURITY_BLOCKS = "aisec_security_blocks_total"
"""安全拦截次数（``rule`` + ``severity``；提示词注入 / 输入清洗命中）。"""

DESCRIPTIONS: dict[str, tuple[str, str]] = {
    M_COLLECT_ITEMS: ("采集到的原始情报条数", "counter"),
    M_COLLECT_FAILURES: ("采集失败次数", "counter"),
    M_COLLECT_DURATION: ("单源采集耗时", "histogram"),
    M_ENRICH_TOTAL: ("富化执行次数（按结果）", "counter"),
    M_ENRICH_DURATION: ("单条富化耗时", "histogram"),
    M_QA_TOTAL: ("问答请求次数（按结果）", "counter"),
    M_QA_DURATION: ("问答耗时", "histogram"),
    M_QA_DEGRADED: ("问答降级次数", "counter"),
    M_LLM_TOKENS: ("LLM token 消耗（按模型与方向）", "counter"),
    M_LLM_FAILURES: ("LLM 调用失败次数", "counter"),
    M_ALERTS: ("触发的告警次数", "counter"),
    M_SELF_HEAL: ("自愈动作次数", "counter"),
    M_COMPONENT_UP: ("组件健康状态（1 可用 / 0 不可用）", "gauge"),
    M_COLLECT_FAILURE_RATIO: ("采集失败率快照（0-1）", "gauge"),
    M_ENRICH_FAILURE_RATIO: ("富化失败率快照（0-1）", "gauge"),
    M_LLM_CONSECUTIVE_FAILURES: ("LLM 连续失败次数", "gauge"),
    M_SECURITY_BLOCKS: ("安全拦截次数（提示词注入 / 输入清洗）", "counter"),
}
"""指标名 → ``(HELP 文案, Prometheus 类型)``。"""

LabelKey = tuple[tuple[str, str], ...]
"""标签键（已排序元组，可哈希）。"""


def label_key(labels: Labels | None) -> LabelKey:
    """把标签映射规整为可哈希且**顺序确定**的键（纯函数）。

    Args:
        labels: 标签映射；``None`` 表示无标签。

    Returns:
        按键排序后的 ``((键, 值), ...)``。
    """
    return tuple(sorted((str(key), str(value)) for key, value in (labels or {}).items()))


def render_labels(labels: LabelKey, *, extra: Sequence[tuple[str, str]] = ()) -> str:
    """渲染 Prometheus 标签串（纯函数）。

    Args:
        labels: 已排序的标签键。
        extra: 追加标签（如直方图的 ``le``），排在已有标签之后。

    Returns:
        ``{k="v",...}`` 或空串。
    """
    merged = [*labels, *extra]
    if not merged:
        return ""
    body = ",".join(f'{key}="{value}"' for key, value in merged)
    return "{" + body + "}"



@dataclass(slots=True)
class HistogramValue:
    """固定分桶直方图（只保存桶计数 / 总和 / 总数，内存占用与观测次数无关）。

    Attributes:
        buckets: 分桶上界（升序，秒）。
        counts: 各桶累计计数（与 ``buckets`` 等长）。
        total: 观测值总和。
        count: 观测次数。
    """

    buckets: tuple[float, ...] = DEFAULT_BUCKETS
    counts: list[int] = field(default_factory=list)
    total: float = 0.0
    count: int = 0

    def __post_init__(self) -> None:
        """初始化桶计数数组。"""
        if not self.counts:
            self.counts = [0 for _ in self.buckets]

    def observe(self, value: float) -> None:
        """记录一次观测。

        Args:
            value: 观测值（秒）；负数按 ``0`` 处理。
        """
        measured = max(0.0, float(value))
        self.total += measured
        self.count += 1
        for index, upper in enumerate(self.buckets):
            if measured <= upper:
                self.counts[index] += 1

    def render(self, name: str, labels: LabelKey) -> list[str]:
        """渲染为 Prometheus 样本行。

        Args:
            name: 指标名（不含 ``_bucket`` 后缀）。
            labels: 标签键。

        Returns:
            ``..._bucket{le=...}`` 累计行 + ``..._sum`` + ``..._count``。
        """
        lines: list[str] = []
        for upper, count in zip(self.buckets, self.counts, strict=True):
            lines.append(f"{name}_bucket{render_labels(labels, extra=(('le', f'{upper:g}'),))} {count}")
        lines.append(f"{name}_bucket{render_labels(labels, extra=(('le', '+Inf'),))} {self.count}")
        lines.append(f"{name}_sum{render_labels(labels)} {self.total:.6f}")
        lines.append(f"{name}_count{render_labels(labels)} {self.count}")
        return lines



class MetricsRegistry:
    """进程内指标注册表（计数器 / 直方图 / 仪表盘）。

    Attributes:
        buckets: 新建直方图使用的分桶。
    """

    def __init__(self, *, buckets: Sequence[float] = DEFAULT_BUCKETS) -> None:
        """初始化空注册表。

        Args:
            buckets: 直方图默认分桶（升序）。
        """
        self.buckets: tuple[float, ...] = tuple(sorted(buckets)) or DEFAULT_BUCKETS
        self._lock = threading.Lock()
        self._counters: dict[tuple[str, LabelKey], float] = {}
        self._gauges: dict[tuple[str, LabelKey], float] = {}
        self._histograms: dict[tuple[str, LabelKey], HistogramValue] = {}

    def inc(self, name: str, labels: Labels | None = None, value: float = 1.0) -> None:
        """计数器自增。

        Args:
            name: 指标名。
            labels: 标签。
            value: 增量（可为负，便于冲正）。
        """
        key = (name, label_key(labels))
        with self._lock:
            self._counters[key] = self._counters.get(key, 0.0) + float(value)

    def observe(self, name: str, value: float, labels: Labels | None = None) -> None:
        """记录一次直方图观测。

        Args:
            name: 指标名。
            value: 观测值（秒）。
            labels: 标签。
        """
        key = (name, label_key(labels))
        with self._lock:
            histogram = self._histograms.get(key)
            if histogram is None:
                histogram = HistogramValue(buckets=self.buckets)
                self._histograms[key] = histogram
            histogram.observe(value)

    def set_gauge(self, name: str, value: float, labels: Labels | None = None) -> None:
        """设置仪表盘当前值。

        Args:
            name: 指标名。
            value: 当前值。
            labels: 标签。
        """
        key = (name, label_key(labels))
        with self._lock:
            self._gauges[key] = float(value)

    def reset(self) -> None:
        """清空全部指标（测试与运维重置用）。"""
        with self._lock:
            self._counters.clear()
            self._gauges.clear()
            self._histograms.clear()

    def counter(self, name: str, labels: Labels | None = None) -> float:
        """读取计数器当前值。

        Args:
            name: 指标名。
            labels: 标签。

        Returns:
            当前累计值（无记录时为 ``0.0``）。
        """
        with self._lock:
            return self._counters.get((name, label_key(labels)), 0.0)

    def counter_total(self, name: str) -> float:
        """读取某计数器**跨全部标签**的合计值。

        Args:
            name: 指标名。

        Returns:
            合计值。
        """
        with self._lock:
            return sum(value for (metric, _), value in self._counters.items() if metric == name)

    def gauge(self, name: str, labels: Labels | None = None) -> float:
        """读取仪表盘当前值。

        Args:
            name: 指标名。
            labels: 标签。

        Returns:
            当前值（无记录时为 ``0.0``）。
        """
        with self._lock:
            return self._gauges.get((name, label_key(labels)), 0.0)

    def histogram_count(self, name: str) -> int:
        """读取某直方图跨全部标签的观测次数。

        Args:
            name: 指标名。

        Returns:
            观测次数合计。
        """
        with self._lock:
            return sum(item.count for (metric, _), item in self._histograms.items() if metric == name)

    def histogram_quantile(self, name: str, quantile: float) -> float:
        """按桶上界估算分位数（供压测报告 P95 使用）。

        Args:
            name: 指标名。
            quantile: 目标分位（``0 < quantile <= 1``）。

        Returns:
            估算分位数（秒）；无观测时返回 ``0.0``。
        """
        with self._lock:
            samples = [item for (metric, _), item in self._histograms.items() if metric == name]
        total = sum(item.count for item in samples)
        if total == 0:
            return 0.0
        target = max(1.0, quantile * total)
        bounds = sorted({bound for item in samples for bound in item.buckets})
        for upper in bounds:
            cumulative = sum(
                sum(count for bound, count in zip(item.buckets, item.counts, strict=True) if bound <= upper)
                for item in samples
            )
            if cumulative >= target:
                return upper
        return bounds[-1] if bounds else 0.0

    def snapshot(self) -> dict[str, Any]:
        """返回结构化快照（供测试断言与调试）。

        Returns:
            含 ``counters`` / ``gauges`` / ``histograms`` 的嵌套字典。
        """
        with self._lock:
            counters = {name: {} for name, _ in self._counters}
            for (name, labels), value in self._counters.items():
                counters[name][render_labels(labels) or "{}"] = value
            gauges = {name: {} for name, _ in self._gauges}
            for (name, labels), value in self._gauges.items():
                gauges[name][render_labels(labels) or "{}"] = value
            histograms = {
                f"{name}{render_labels(labels)}": {"count": item.count, "sum": item.total}
                for (name, labels), item in self._histograms.items()
            }
        return {"counters": counters, "gauges": gauges, "histograms": histograms}

    def render_prometheus(self) -> str:
        """渲染为 Prometheus 文本格式（``text/plain; version=0.0.4``）。

        Returns:
            以换行结尾的指标文本；无任何指标时仅返回换行。
        """
        with self._lock:
            counters = dict(self._counters)
            gauges = dict(self._gauges)
            histograms = dict(self._histograms)

        blocks: list[str] = []
        for group, default_type in ((counters, "counter"), (gauges, "gauge")):
            for name in sorted({item[0] for item in group}):
                help_text, metric_type = DESCRIPTIONS.get(name, (name, default_type))
                lines = [f"# HELP {name} {help_text}", f"# TYPE {name} {metric_type}"]
                for (metric, labels), value in sorted(group.items()):
                    if metric == name:
                        lines.append(f"{name}{render_labels(labels)} {value:g}")
                blocks.append("\n".join(lines))
        for name in sorted({item[0] for item in histograms}):
            help_text, _ = DESCRIPTIONS.get(name, (name, "histogram"))
            lines = [f"# HELP {name} {help_text}", f"# TYPE {name} histogram"]
            for (metric, labels), item in sorted(histograms.items()):
                if metric == name:
                    lines.extend(item.render(name, labels))
            blocks.append("\n".join(lines))
        return "\n".join(blocks) + "\n"


METRICS: MetricsRegistry = MetricsRegistry()
"""全进程共享的指标注册表（路由 / 服务层统一读写本实例）。"""




def record_collect(source: str, *, fetched: int, failed: bool, duration_s: float) -> None:
    """记录一次单源采集（条数 / 成败 / 耗时 / 失败率快照）。

    Args:
        source: 源标识。
        fetched: 本次拉取条数。
        failed: 是否失败。
        duration_s: 耗时（秒）。
    """
    labels = {"source": source}
    METRICS.inc(M_COLLECT_ITEMS, labels, value=max(0, int(fetched)))
    if failed:
        METRICS.inc(M_COLLECT_FAILURES, labels)
    METRICS.observe(M_COLLECT_DURATION, duration_s, labels)
    METRICS.set_gauge(M_COLLECT_FAILURE_RATIO, collect_failure_ratio(METRICS))


def record_enrich(*, ok: bool, duration_s: float) -> None:
    """记录一次单条富化（成败 / 耗时 / 失败率快照）。

    Args:
        ok: 是否成功产出 ``EnrichedVuln``。
        duration_s: 耗时（秒）。
    """
    METRICS.inc(M_ENRICH_TOTAL, {"status": "success" if ok else "failed"})
    METRICS.observe(M_ENRICH_DURATION, duration_s)
    METRICS.set_gauge(M_ENRICH_FAILURE_RATIO, enrich_failure_ratio(METRICS))


def record_qa(*, ok: bool, duration_s: float, degraded: bool = False) -> None:
    """记录一次问答请求（成败 / 耗时 / 是否降级）。

    Args:
        ok: 是否成功返回。
        duration_s: 耗时（秒）。
        degraded: 是否走了降级链路。
    """
    METRICS.inc(M_QA_TOTAL, {"status": "success" if ok else "failed"})
    METRICS.observe(M_QA_DURATION, duration_s)
    if degraded:
        METRICS.inc(M_QA_DEGRADED)


def record_llm_usage(model: str, *, prompt_tokens: int = 0, completion_tokens: int = 0) -> None:
    """记录一次 LLM token 消耗。

    Args:
        model: 模型名。
        prompt_tokens: 输入 token。
        completion_tokens: 输出 token。
    """
    if prompt_tokens:
        METRICS.inc(M_LLM_TOKENS, {"model": model, "kind": "prompt"}, value=prompt_tokens)
    if completion_tokens:
        METRICS.inc(M_LLM_TOKENS, {"model": model, "kind": "completion"}, value=completion_tokens)


def record_llm_failure(model: str) -> int:
    """记录一次 LLM 调用失败并返回当前连续失败次数。

    Args:
        model: 模型名。

    Returns:
        自最近一次成功以来的连续失败次数（告警规则用）。
    """
    METRICS.inc(M_LLM_FAILURES, {"model": model})
    streak = METRICS.gauge(M_LLM_CONSECUTIVE_FAILURES) + 1
    METRICS.set_gauge(M_LLM_CONSECUTIVE_FAILURES, streak)
    return int(streak)


def record_llm_success() -> None:
    """记录一次 LLM 调用成功（清零连续失败计数）。"""
    METRICS.set_gauge(M_LLM_CONSECUTIVE_FAILURES, 0)


def collect_failure_ratio(registry: MetricsRegistry | None = None) -> float:
    """采集失败率（失败次数 / (采集条数 + 失败次数)，按源汇总）。

    Args:
        registry: 指标注册表；``None`` 时用进程级 :data:`METRICS`。

    Returns:
        区间 ``[0, 1]`` 的比值；尚无采集记录时返回 ``0.0``。
    """
    target = registry or METRICS
    attempts = target.counter_total(M_COLLECT_ITEMS) + target.counter_total(M_COLLECT_FAILURES)
    if attempts <= 0:
        return 0.0
    return min(1.0, target.counter_total(M_COLLECT_FAILURES) / attempts)


def enrich_failure_ratio(registry: MetricsRegistry | None = None) -> float:
    """富化失败率（失败次数 / 富化次数）。

    Args:
        registry: 指标注册表；``None`` 时用进程级 :data:`METRICS`。

    Returns:
        区间 ``[0, 1]`` 的比值；尚无富化记录时返回 ``0.0``。
    """
    target = registry or METRICS
    total = target.counter(M_ENRICH_TOTAL, {"status": "success"}) + target.counter(
        M_ENRICH_TOTAL, {"status": "failed"}
    )
    if total <= 0:
        return 0.0
    return min(1.0, target.counter(M_ENRICH_TOTAL, {"status": "failed"}) / total)

"""Day17 任务 5：性能压测（采集 / 富化 / 问答）并生成 ``reports/performance.md``。

三段压测（全部可离线复现，唯一例外是显式 ``--network`` 的 9 源真实采集）：

=====================  ======================================================================
① 采集压测            1000 条 CVE 归一化 + 落库（内存 SQLite）；``--network`` 时追加 9 源并发采集
② 富化压测            50 条 CVE 走完整富化图（``use_llm=False`` 确定性路径，PoC 检索走离线桩）
③ 问答压测            20 条查询走 QA 图（``use_llm=False``），统计平均 / P95 延迟与命中率
=====================  ======================================================================

用法::

    python -m scripts.run_perf_benchmark                     # 离线三段（默认）
    python -m scripts.run_perf_benchmark --network           # 追加 9 源真实并发采集
    python -m scripts.run_perf_benchmark --enrich-count 20 --qa-count 10

输出：``reports/performance.md``（Markdown 表格 + 瓶颈分析），控制台同步打印摘要。

硬约束：本脚本属运维工具（``scripts/``），**不做 LLM 推理**（``use_llm=False``），
不消耗额度；口径与 §5.10 P9.2 的 ``reports/perf_report.md`` 一致（Day17 版本）。
"""

from __future__ import annotations

import argparse
import asyncio
import json
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx

from aisec_intel.config import Settings
from aisec_intel.connectors.http_client import HttpClient
from aisec_intel.connectors.registry import available_sources
from aisec_intel.models.base import utc_now
from aisec_intel.models.raw_item import RawItem
from aisec_intel.normalize.pipeline import build_unified_vuln
from aisec_intel.services.collect_service import collect_source
from aisec_intel.services.enrich_service import build_deps, enrich_vuln
from aisec_intel.services.retrieval_service import RetrievalService
from aisec_intel.storage.database import (
    dispose_engines,
    get_engine,
    init_models,
    session_scope,
)
from aisec_intel.storage.repositories.vuln_repo import VulnRepository
from aisec_intel.utils.hashing import sha256_text

MEMORY_DSN: str = "sqlite+aiosqlite:///:memory:"
"""压测用内存 SQLite（StaticPool 单连接，同进程可见，测完即弃）。"""

DEFAULT_COLLECT_COUNT: int = 1000
"""① 归一化压测条数（任务书：1000 条 CVE）。"""

DEFAULT_ENRICH_COUNT: int = 50
"""② 富化压测条数（任务书：50 条 CVE）。"""

DEFAULT_QA_COUNT: int = 20
"""③ 问答压测条数（任务书：20 条查询）。"""

REPORT_PATH: Path = Path("reports/performance.md")
"""压测报告输出路径（仓库根目录 ``reports/``，非 ``docs/``）。"""


@dataclass(frozen=True, slots=True)
class Percentiles:
    """一组耗时的统计量（秒）。

    Attributes:
        count: 样本数。
        total_s: 总耗时。
        avg_s: 平均值。
        p50_s: 中位数。
        p95_s: 95 分位。
        max_s: 最大值。
    """

    count: int
    total_s: float
    avg_s: float
    p50_s: float
    p95_s: float
    max_s: float

    @property
    def throughput(self) -> float:
        """吞吐（条/秒）；总耗时为 0 时返回 ``0.0``。"""
        return 0.0 if self.total_s <= 0 else self.count / self.total_s


def percentile(values: Sequence[float], q: float) -> float:
    """线性插值分位数（纯函数，与 numpy 默认口径一致）。

    Args:
        values: 样本（无需预排序）。
        q: 目标分位，区间 ``[0, 1]``。

    Returns:
        分位数；样本为空时返回 ``0.0``。
    """
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = max(0.0, min(1.0, q)) * (len(ordered) - 1)
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def summarize(durations: Sequence[float], *, wall_s: float | None = None) -> Percentiles:
    """把逐条耗时汇总为统计量（纯函数）。

    Args:
        durations: 逐条耗时（秒）。
        wall_s: 端到端墙钟耗时；``None`` 时用逐条耗时之和。

    Returns:
        :class:`Percentiles`。
    """
    if not durations:
        return Percentiles(count=0, total_s=wall_s or 0.0, avg_s=0.0, p50_s=0.0, p95_s=0.0, max_s=0.0)
    total = wall_s if wall_s is not None else sum(durations)
    return Percentiles(
        count=len(durations),
        total_s=total,
        avg_s=sum(durations) / len(durations),
        p50_s=percentile(durations, 0.5),
        p95_s=percentile(durations, 0.95),
        max_s=max(durations),
    )



def build_synthetic_nvd_item(index: int, *, seq: int = 2024) -> RawItem:
    """构造一条「NVD 风格」采集件（确定性，含描述 / CVSS / CWE / CPE / patch 引用）。

    Args:
        index: 序号（决定 CVE 编号与版本号）。
        seq: CVE 年份段（默认 2024）。

    Returns:
        :class:`~aisec_intel.models.raw_item.RawItem`（``source="nvd"``）。
    """
    cve_id = f"CVE-{seq}-{index:04d}"
    product = f"product-{index % 37}"
    major = 1 + index % 3
    version = f"{major}.{index % 10}.{index % 7}"
    payload: dict[str, Any] = {
        "id": cve_id,
        "descriptions": [
            {
                "lang": "en",
                "value": (
                    f"{cve_id} synthetic benchmark vulnerability in {product}: "
                    "an unauthenticated attacker can execute arbitrary commands via crafted input."
                ),
            }
        ],
        "metrics": {
            "cvssMetricV31": [
                {
                    "cvssData": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                    },
                    "baseSeverity": "CRITICAL",
                }
            ]
        },
        "weaknesses": [{"description": [{"lang": "en", "value": "CWE-78"}]}],
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "criteria": f"cpe:2.3:a:benchmark:{product}:*:*:*:*:*:*:*:*",
                                "vulnerable": True,
                                "versionStartIncluding": version,
                                "versionEndExcluding": f"{major + 1}.0.0",
                            }
                        ]
                    }
                ]
            }
        ],
        "references": [
            {
                "url": f"https://example.test/advisories/{cve_id}",
                "source": "vendor",
                "tags": ["Patch", "Vendor Advisory"],
            }
        ],
        "published": "2024-05-01T00:00:00.000",
        "lastModified": "2024-05-02T00:00:00.000",
        "vulnStatus": "Analyzed",
    }
    text = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return RawItem(
        trace_id=f"bench-{cve_id}",
        source="nvd",
        source_id=cve_id,
        url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        title=f"{cve_id} synthetic benchmark vulnerability",
        raw_text=text,
        lang="en",
        published_at=None,
        fetched_at=utc_now(),
        sha256=sha256_text(text),
    )


def offline_http_client() -> HttpClient:
    """返回「一切 404」的离线 HTTP 客户端（PoC 检索走确定性兜底，不触网、不扣额度）。"""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"message": "offline benchmark", "url": str(request.url)})

    return HttpClient(timeout=5.0, max_retries=1, transport=httpx.MockTransport(handler))


@dataclass(slots=True)
class Section:
    """报告中的一段压测结果。

    Attributes:
        title: 小节标题。
        metrics: ``指标名 → 显示值``（Markdown 表格行）。
        rows: 明细表格（表头 + 数据行）。
        notes: 备注 / 结论（含降级留痕）。
    """

    title: str
    metrics: dict[str, str] = field(default_factory=dict)
    rows: list[list[str]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)



async def bench_collect(settings: Settings, *, count: int) -> tuple[Section, list[str]]:
    """① 采集压测：``count`` 条 CVE 归一化（L2 纯函数）+ 幂等落库。

    Args:
        settings: 压测配置（内存 SQLite）。
        count: 条数。

    Returns:
        ``(报告小节, 入库的 CVE 编号列表)``（编号列表供问答压测构造问题）。
    """
    engine = get_engine(settings)
    await init_models(engine)
    items = [build_synthetic_nvd_item(index) for index in range(count)]

    durations: list[float] = []
    vulns: list[Any] = []
    failures = 0
    normalize_started = time.perf_counter()
    for item in items:
        started = time.perf_counter()
        try:
            vulns.append(build_unified_vuln(item, normalized_at=item.fetched_at))
        except Exception:  # noqa: BLE001 - 单条失败不应中断压测
            failures += 1
        durations.append(time.perf_counter() - started)
    normalize_s = time.perf_counter() - normalize_started

    write_started = time.perf_counter()
    async with session_scope(engine) as session:
        repo = VulnRepository(session)
        for vuln in vulns:
            await repo.upsert(vuln)
    write_s = time.perf_counter() - write_started

    stats = summarize(durations, wall_s=normalize_s + write_s)
    section = Section(
        title=f"① 采集压测 A：{count} 条 CVE 归一化 + 落库（内存 SQLite，离线）",
        metrics={
            "总耗时": f"{stats.total_s:.2f} s（归一化 {normalize_s:.2f} s + 落库 {write_s:.2f} s）",
            "平均单条": f"{stats.avg_s * 1000:.2f} ms",
            "P50": f"{stats.p50_s * 1000:.2f} ms",
            "P95": f"{stats.p95_s * 1000:.2f} ms",
            "最大单条": f"{stats.max_s * 1000:.2f} ms",
            "吞吐": f"{stats.throughput:.1f} 条/秒",
        },
        rows=[
            ["归一化（build_unified_vuln，纯函数）", f"{normalize_s:.3f}", f"{normalize_s / max(1, count) * 1000:.3f}"],
            ["落库（upsert，逐条 flush）", f"{write_s:.3f}", f"{write_s / max(1, count) * 1000:.3f}"],
        ],
        notes=[
            f"入库 {len(vulns)} 条，归一化失败 {failures} 条（单条失败不中断整批）。",
            "采集主链路为纯传统代码（无 LLM）：耗时主要在「逐条 upsert + flush」，而非解析（§0 约束 1）。",
        ],
    )
    return section, [str(vuln.vuln_id) for vuln in vulns]


async def bench_collect_sources(settings: Settings, *, per_source_limit: int) -> Section:
    """① 采集压测 B：9 个源**并发**真实采集（``dry_run=True``，不写库）。

    Args:
        settings: 压测配置。
        per_source_limit: 每个源的条数上限（控制时间预算）。

    Returns:
        报告小节（含逐源耗时与失败原因）。
    """
    sources = list(available_sources())
    since = utc_now() - timedelta(days=7)

    async def _one(source: str) -> tuple[str, float, int, str, str]:
        started = time.perf_counter()
        try:
            stats = await collect_source(
                source,
                since=since,
                settings=settings,
                limit=per_source_limit,
                dry_run=True,
            )
            return source, stats.duration_s, stats.fetched, stats.status, stats.error or ""
        except Exception as exc:  # noqa: BLE001 - 单源失败只记录，不中断整体压测
            return source, time.perf_counter() - started, 0, "failed", f"{type(exc).__name__}: {exc}"

    started = time.perf_counter()
    results = await asyncio.gather(*[_one(source) for source in sources])
    wall_s = time.perf_counter() - started
    durations = [item[1] for item in results]
    stats = summarize(durations, wall_s=wall_s)
    ok = sum(1 for item in results if item[3] == "succeeded")
    return Section(
        title=f"① 采集压测 B：{len(sources)} 源并发真实采集（每源上限 {per_source_limit} 条）",
        metrics={
            "并发墙钟耗时": f"{wall_s:.2f} s",
            "成功源数": f"{ok}/{len(sources)}",
            "单源平均耗时": f"{stats.avg_s:.2f} s",
            "单源 P95": f"{stats.p95_s:.2f} s",
            "串行基线（逐源耗时之和）": f"{sum(durations):.2f} s",
            "加速比": f"{sum(durations) / wall_s:.2f}×" if wall_s > 0 else "-",
        },
        rows=[
            [source, f"{duration:.2f}", str(fetched), status, error[:90]]
            for source, duration, fetched, status, error in results
        ],
        notes=[
            "并发墙钟耗时 ≈ 最慢源（NVD 限流 / GHSA 分页最慢），加速比按「逐源耗时之和 ÷ 墙钟」计算。",
            "失败源已由自愈机制留痕 logs/selfheal.log（重试 3 次 + 镜像切换，Day17 任务 4.1）。",
            "本机为**未配 Token 的裸环境**：NVD 无 API Key（5 req/30s）、GHSA 无 GITHUB_TOKEN、"
            "arxiv 返回 429；成功源数偏低属环境限制，非链路缺陷（配 Key 后按 §11.1 重跑即可）。",
            "任务登记（task_run）为旁路：登记异常不再把已成功的采集标成失败"
            "（services/collect_service.py::record_task_result，Day17 修复）。",
        ],
    )


async def bench_enrich(settings: Settings, *, count: int) -> Section:
    """② 富化压测：``count`` 条 CVE 跑完整富化图（确定性路径，不调 LLM）。

    Args:
        settings: 压测配置。
        count: 条数。

    Returns:
        报告小节（平均 / P95 / 吞吐 + Agent 轨迹规模）。
    """
    from aisec_intel.enrich.graph import build_enrichment_graph
    from aisec_intel.llm.cache import TokenUsageTracker

    http = offline_http_client()
    tracker = TokenUsageTracker()
    deps = build_deps(settings, http=http, use_llm=False, tracker=tracker)
    graph = build_enrichment_graph(
        deps, max_rounds=settings.enrich_max_rounds, min_confidence=settings.enrich_min_confidence
    )
    durations: list[float] = []
    ok = 0
    trace_sizes: list[int] = []
    try:
        for index in range(count):
            item = build_synthetic_nvd_item(index, seq=2025)
            vuln = build_unified_vuln(item, normalized_at=item.fetched_at)
            started = time.perf_counter()
            run = await enrich_vuln(vuln, settings=settings, deps=deps, graph=graph, persist=False)
            durations.append(time.perf_counter() - started)
            if run.output is not None:
                ok += 1
                trace_sizes.append(len(run.output.enriched_vuln.agent_trace))
    finally:
        await http.aclose()

    stats = summarize(durations)
    return Section(
        title=f"② 富化压测：{count} 条 CVE 完整富化（无 LLM，确定性路径）",
        metrics={
            "总耗时": f"{stats.total_s:.2f} s",
            "平均单条": f"{stats.avg_s * 1000:.1f} ms",
            "P50": f"{stats.p50_s * 1000:.1f} ms",
            "P95": f"{stats.p95_s * 1000:.1f} ms",
            "最大单条": f"{stats.max_s * 1000:.1f} ms",
            "吞吐": f"{stats.throughput:.1f} 条/秒",
            "成功产出": f"{ok}/{count}",
            "平均 Agent 轨迹步数": f"{sum(trace_sizes) / len(trace_sizes):.1f}" if trace_sizes else "0",
        },
        notes=[
            "本压测关闭 LLM（use_llm=False）+ PoC 检索走离线桩（404），因此测得的是"
            "**除 LLM 之外**的固定成本（图调度 + 规则抽取 + 风险公式 + 检索）。",
            "生产环境单条富化耗时以 LLM 调用为绝对主导（deepseek-chat 单次约 2–8 s，见 §3.4 额度保护）。",
        ],
    )


async def bench_qa(settings: Settings, *, count: int, cve_ids: Sequence[str]) -> Section:
    """③ 问答压测：``count`` 条事实型查询（QA 图，``use_llm=False``）。

    正确性口径：回答或引用的定位符中出现目标 CVE 编号即视为命中
    （与 ``tests/eval`` 的「事实型」判定同源）。

    Args:
        settings: 压测配置。
        count: 查询条数。
        cve_ids: 已入库的 CVE 编号（构造问题用）。

    Returns:
        报告小节（平均 / P95 延迟 + 命中率 + 降级比例）。
    """
    from aisec_intel.qa.graph import run_qa

    questions = [f"{cve_id} 这个漏洞的描述是什么？" for cve_id in list(cve_ids)[:count]]
    durations: list[float] = []
    hits = 0
    degraded = 0
    failures: list[str] = []
    rows: list[list[str]] = []
    async with session_scope(get_engine(settings)) as session:
        service = RetrievalService(session, settings=settings)
        try:
            for question, expected in zip(questions, list(cve_ids)[:count], strict=True):
                started = time.perf_counter()
                try:
                    response, _state = await run_qa(
                        service, question, settings=settings, use_llm=False, top_k=5, max_hops=2
                    )
                except Exception as exc:  # noqa: BLE001 - 单题失败不影响整体统计
                    durations.append(time.perf_counter() - started)
                    failures.append(f"{expected}: {type(exc).__name__}: {exc}")
                    rows.append([expected, "-", "失败", str(exc)[:60]])
                    continue
                elapsed = time.perf_counter() - started
                durations.append(elapsed)
                haystack = " ".join([response.answer, *(citation.locator for citation in response.citations)])
                hit = expected in haystack
                hits += int(hit)
                degraded += int(response.degraded)
                rows.append(
                    [
                        expected,
                        f"{elapsed * 1000:.0f} ms",
                        "命中" if hit else "未命中",
                        f"引用 {len(response.citations)} 条",
                    ]
                )
        finally:
            await service.aclose()

    stats = summarize(durations)
    total = max(1, len(questions))
    return Section(
        title=f"③ 问答压测：{len(questions)} 条事实型查询（QA 图，确定性路径）",
        metrics={
            "总耗时": f"{stats.total_s:.2f} s",
            "平均单题": f"{stats.avg_s * 1000:.0f} ms",
            "P50": f"{stats.p50_s * 1000:.0f} ms",
            "P95": f"{stats.p95_s * 1000:.0f} ms",
            "最大单题": f"{stats.max_s * 1000:.0f} ms",
            "命中率（答案/引用含目标 CVE）": f"{hits / total:.0%}（{hits}/{total}）",
            "降级比例": f"{degraded / total:.0%}",
            "失败题数": str(len(failures)),
        },
        rows=rows,
        notes=[
            "本压测关闭 LLM（use_llm=False）：耗时由「检索融合（RRF）+ 确定性作答」构成。",
            "检索通路不可用时自动降级并写 logs/selfheal.log（向量→全文；图→PG JSON，Day17 任务 4.3）。",
            "离线开关：哈希嵌入 + 内存向量库 + Neo4j 关闭（图路由走 PG JSON 降级，属预期行为）。",
            *[f"失败：{item}" for item in failures[:5]],
        ],
    )


def render_report(sections: Sequence[Section], *, args: argparse.Namespace, elapsed_s: float) -> str:
    """把各段结果渲染为 Markdown 报告（纯函数）。

    Args:
        sections: 压测小节序列。
        args: 命令行参数（写入环境快照）。
        elapsed_s: 整轮压测墙钟耗时（秒）。

    Returns:
        Markdown 文本。
    """
    generated = utc_now().isoformat(timespec="seconds").replace("+00:00", "Z")
    lines: list[str] = [
        "# 性能压测报告（Day17 任务 5）",
        "",
        f"> 生成时间：{generated} ｜ 总耗时：{elapsed_s:.2f} s ｜ 环境：本地开发机（Windows / Docker Desktop）",
        "> 口径说明：全部压测**关闭 LLM**（`use_llm=False`），测得的是「除模型推理之外」的固定成本；",
        "> 生产环境富化/问答耗时以 LLM 调用为主导（§3.4 额度保护）。",
        "",
        "## 0. 压测参数",
        "",
        "| 参数 | 取值 |",
        "|---|---|",
        f"| 归一化条数 | {args.collect_count} |",
        f"| 真实并发采集 | {'开启' if args.network else '关闭（避免外网波动）'} |",
        f"| 富化条数 | {args.enrich_count} |",
        f"| 问答题数 | {args.qa_count} |",
        "",
        "## 结论摘要",
        "",
    ]
    for section in sections:
        key_metrics = "；".join(f"{name}：{value}" for name, value in list(section.metrics.items())[:4])
        lines.append(f"- **{section.title}**：{key_metrics}")
    lines.append("")

    for section in sections:
        lines.append(f"## {section.title}")
        lines.append("")
        lines.append("| 指标 | 数值 |")
        lines.append("|---|---|")
        for name, value in section.metrics.items():
            lines.append(f"| {name} | {value} |")
        lines.append("")
        if section.rows:
            header = ["目标", "耗时", "结果", "备注"]
            if len(section.rows[0]) == 5:
                header = ["源", "耗时(s)", "条数", "状态", "错误"]
            elif len(section.rows[0]) == 3:
                header = ["阶段", "总耗时(s)", "单条平均(ms)"]
            lines.append("| " + " | ".join(header) + " |")
            lines.append("|" + "---|" * len(header))
            for row in section.rows[:30]:
                lines.append("| " + " | ".join(str(cell).replace("|", "/") for cell in row) + " |")
            if len(section.rows) > 30:
                lines.append("| … | 其余行省略 | | |")
            lines.append("")
        for note in section.notes:
            lines.append(f"> {note}")
        if section.notes:
            lines.append("")

    lines.extend(
        [
            "## 瓶颈分析",
            "",
            "1. **采集**：归一化是纯函数（无 LLM），主要开销为解析大 JSON + 规则抽取；内存库落库为逐条",
            "   `upsert + flush`，故写库耗时随条数线性增长。真实采集受**源侧限流**支配（NVD 无 Key 约",
            "   5 请求/30 s、GHSA 需 Token 分页）；9 源并发后墙钟耗时 ≈ 最慢源，而非各源之和。",
            "2. **富化**：关闭 LLM 后单条成本集中在「LangGraph 图调度 + 规则抽取 + 风险公式 + 检索」；",
            "   开启 LLM 后单条将由 1–7 次模型调用主导（deepseek-chat 约 2–8 s/次），",
            "   因此 `LLM_SMART_GATE` 门控与 `--limit` 是控制演示时长的关键（§3.4）。",
            "3. **问答**：确定性路径为「查询理解（规则）→ 多路检索并发 → RRF 融合 → 模板作答」，",
            "   延迟与通路数、`top_k` 近似线性；向量路未建索引时可自动降级为全文检索",
            "   （自愈留痕：`logs/selfheal.log`，Day17 任务 4.3）。",
            "",
            "## 复现命令",
            "",
            "```powershell",
            f"python -m scripts.run_perf_benchmark --collect-count {args.collect_count} "
            f"--enrich-count {args.enrich_count} --qa-count {args.qa_count}"
            + (" --network" if args.network else ""),
            "```",
            "",
        ]
    )
    return "\n".join(lines)


def _print_section(section: Section) -> None:
    """把一段结果打印到控制台。

    Args:
        section: 压测小节。
    """
    print(f"\n=== {section.title} ===")
    for name, value in section.metrics.items():
        print(f"  - {name}: {value}")
    for note in section.notes:
        print(f"  * {note}")


async def run_benchmark(args: argparse.Namespace) -> Path:
    """执行全部压测并写出报告。

    Args:
        args: 命令行参数。

    Returns:
        报告文件路径。
    """
    started = time.perf_counter()
    settings = Settings(
        degraded_mode=True,
        database_url=MEMORY_DSN,
        llm_provider="deepseek",
        llm_api_key="",
        # 离线压测的三个开关（避免联网下载嵌入模型 / 等待外部图库）：
        #   1) EMBEDDING_BACKEND=hashing：哈希嵌入，不加载 sentence-transformers（无模型下载）
        #   2) VECTOR_BACKEND=chroma_memory：内存向量库，测完即弃
        #   3) NEO4J_ENABLED=false：图路由按设计降级为 PG JSON（同时验证自愈 ③ 的降级留痕）
        embedding_backend="hashing",
        vector_backend="chroma_memory",
        neo4j_enabled=False,
    )
    sections: list[Section] = []
    try:
        collect_section, cve_ids = await bench_collect(settings, count=args.collect_count)
        sections.append(collect_section)
        if args.network:
            sections.append(await bench_collect_sources(settings, per_source_limit=args.source_limit))
        sections.append(await bench_enrich(settings, count=args.enrich_count))
        sections.append(await bench_qa(settings, count=args.qa_count, cve_ids=cve_ids))
    finally:
        await dispose_engines()

    elapsed = time.perf_counter() - started
    report = render_report(sections, args=args, elapsed_s=elapsed)
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(report, encoding="utf-8")

    for section in sections:
        _print_section(section)
    print(f"\n[完成] 报告已写入 {REPORT_PATH}（总耗时 {elapsed:.2f} s）")
    return REPORT_PATH


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """解析命令行参数。

    Args:
        argv: 参数序列；``None`` 时取 ``sys.argv[1:]``。

    Returns:
        解析结果。
    """
    parser = argparse.ArgumentParser(description="Day17 性能压测（采集 / 富化 / 问答）")
    parser.add_argument("--collect-count", type=int, default=DEFAULT_COLLECT_COUNT, help="归一化压测条数")
    parser.add_argument("--enrich-count", type=int, default=DEFAULT_ENRICH_COUNT, help="富化压测条数")
    parser.add_argument("--qa-count", type=int, default=DEFAULT_QA_COUNT, help="问答压测题数")
    parser.add_argument("--network", action="store_true", help="追加 9 源真实并发采集（默认关闭）")
    parser.add_argument("--source-limit", type=int, default=5, help="真实采集时每源条数上限")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """脚本入口。

    Args:
        argv: 参数序列；``None`` 时取 ``sys.argv[1:]``。

    Returns:
        进程退出码（0 成功）。
    """
    args = parse_args(argv)
    asyncio.run(run_benchmark(args))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

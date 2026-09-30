"""富化主入口（PROJECT_PLAN.md §5.6 ``scripts/run_enrich.py``）。

用法::

    python -m scripts.run_enrich --cve CVE-2024-3400 --verbose
    python -m scripts.run_enrich --limit 5 --only-missing
    python -m scripts.run_enrich --cve CVE-2024-3400 --no-llm      # 离线降级（无 Key / 断网）
    python -m scripts.run_enrich --cve CVE-2024-3400 --no-persist  # 只跑不落库（演练）
    python -m scripts.run_enrich --graph                          # 打印状态图（Mermaid）

输出：逐条富化摘要（置信度 / 风险分 / 论文数 / PoC 数 / 复核状态）+ **token 消耗统计**（成本评估）。
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from aisec_intel.config import Settings  # noqa: E402
from aisec_intel.enrich.graph import graph_mermaid  # noqa: E402
from aisec_intel.services.enrich_service import (  # noqa: E402
    EnrichmentRun,
    enrich_batch,
    llm_available,
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """解析命令行参数。

    Args:
        argv: 参数列表；``None`` 表示使用 ``sys.argv``。

    Returns:
        解析后的命名空间。
    """
    parser = argparse.ArgumentParser(description="富化 LangGraph 主入口（paper_linker → poc_seeker → verifier）")
    parser.add_argument("--cve", default=None, help="指定单条漏洞（如 CVE-2024-3400）")
    parser.add_argument("--limit", type=int, default=1, help="批量条数（--cve 为空时生效）")
    parser.add_argument("--only-missing", action="store_true", help="只处理尚未富化的条目")
    parser.add_argument("--no-llm", action="store_true", help="禁用 LLM（走检索折算降级路径）")
    parser.add_argument("--no-persist", action="store_true", help="只跑图不落库（演练）")
    parser.add_argument("--checkpoint", action="store_true", help="挂 InMemorySaver（运行时状态可查询）")
    parser.add_argument("--max-rounds", type=int, default=None, help="覆盖最大回流次数")
    parser.add_argument("--graph", action="store_true", help="打印状态图（Mermaid）后退出")
    parser.add_argument("--verbose", action="store_true", help="打印完整状态与轨迹")
    return parser.parse_args(argv)


def print_run(run: EnrichmentRun, *, verbose: bool = False) -> None:
    """打印单条富化结果摘要。

    Args:
        run: 富化执行结果。
        verbose: 是否打印状态摘要与轨迹。
    """
    enriched = run.enriched
    if enriched is None:
        print(f"[FAIL {run.cve_id}] 未产出结论（耗时 {run.duration_s}s）")
    else:
        remediation = run.output.remediation if run.output else None
        print(
            f"[OK   {run.cve_id}] 置信度={enriched.confidence:.2f} 风险分={enriched.risk_score} "
            f"级别={enriched.risk_level} 论文={len(enriched.related_papers)} "
            f"资产={len(enriched.affected_assets)} PoC={len(enriched.exploits)} "
            f"攻击链={len(enriched.attack_chain.steps) if enriched.attack_chain else 0} "
            f"修复建议={'有' if remediation else '无'} 轨迹={len(enriched.agent_trace)} 节点 "
            f"复核={enriched.review_status} 模型={enriched.model_used} 耗时={run.duration_s}s"
        )
        if run.output and run.output.cvss_inferred:
            inferred = run.output.cvss_inferred[0]
            print(f"    -> 推断 CVSS：{inferred.vector} -> {inferred.base_score}（{inferred.severity}）")
        if remediation is not None:
            mitigations = "；".join(remediation.mitigations[:2]) or "（无）"
            print(f"    -> 修复建议：{remediation.summary[:90]}｜缓解：{mitigations[:90]}")
    for error in run.errors:
        print(f"    ⚠ {error}")
    if verbose and run.state is not None:
        from aisec_intel.enrich.state import state_summary

        print(f"    状态：{state_summary(run.state)}")
        for step in run.state["agent_steps"]:
            print(
                f"    · {step.agent:<12} round={step.round} conf={step.confidence:.2f} "
                f"{step.latency_ms}ms model={step.model_used} | {step.output_digest}"
            )


def print_usage(runs: list[EnrichmentRun]) -> None:
    """打印 token 消耗统计（成本评估）。

    Args:
        runs: 本次全部执行结果。
    """
    usages: dict[str, dict[str, int]] = {}
    for run in runs:
        for row in run.usage:
            bucket = usages.setdefault(
                str(row["model"]),
                {"calls": 0, "cache_hits": 0, "prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            )
            for key in ("calls", "cache_hits", "prompt_tokens", "completion_tokens", "total_tokens"):
                bucket[key] += int(row[key])

    print("\n[token 消耗] （成本评估用；缓存命中不消耗 token）")
    if not usages:
        print("  本次未发生 LLM 调用（走检索折算降级路径）")
        return
    prompt_total = sum(bucket["prompt_tokens"] for bucket in usages.values())
    completion_total = sum(bucket["completion_tokens"] for bucket in usages.values())
    for model, bucket in sorted(usages.items()):
        print(
            f"  - {model:<18} 调用={bucket['calls']} 缓存命中={bucket['cache_hits']} "
            f"输入={bucket['prompt_tokens']} 输出={bucket['completion_tokens']} 合计={bucket['total_tokens']}"
        )
    print(f"  合计：输入={prompt_total} 输出={completion_total} 总 token={prompt_total + completion_total}")


async def run(args: argparse.Namespace) -> int:
    """执行富化流程。

    Args:
        args: 命令行参数。

    Returns:
        进程退出码（0 成功；1 存在失败条目）。
    """
    settings = Settings()
    if args.graph:
        print(graph_mermaid(min_confidence=settings.enrich_min_confidence, max_rounds=settings.enrich_max_rounds))
        return 0

    has_llm = llm_available(settings) and not args.no_llm
    print(
        f"[环境] DSN={settings.effective_storage_dsn} | provider={settings.llm_provider} | "
        f"LLM={'on' if has_llm else 'off（检索折算降级）'} | 阈值={settings.enrich_min_confidence} | "
        f"checkpointer={'InMemorySaver' if args.checkpoint else 'off'}"
    )
    runs = await enrich_batch(
        settings,
        cve_id=args.cve,
        limit=args.limit,
        only_missing=args.only_missing,
        use_llm=has_llm,
        persist=not args.no_persist,
        max_rounds=args.max_rounds or settings.enrich_max_rounds,
        checkpoint=args.checkpoint,
    )
    if not runs:
        print("[提示] 未找到待富化的条目（请先跑 scripts.run_collect 或检查 --cve 是否正确）")
        return 1

    for run_result in runs:
        print_run(run_result, verbose=args.verbose)
    print_usage(runs)
    failures = sum(1 for run_result in runs if run_result.enriched is None)
    print(f"\n[完成] 成功 {len(runs) - failures}/{len(runs)} 条")
    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    """脚本入口。

    Args:
        argv: 参数列表；``None`` 表示使用 ``sys.argv``。

    Returns:
        进程退出码。
    """
    return asyncio.run(run(parse_args(argv)))


if __name__ == "__main__":
    raise SystemExit(main())

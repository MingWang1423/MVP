"""问答命令行入口（Day11 任务 7；PROJECT_PLAN.md §5.8 ``qa/graph.py`` 的 CLI 封装）。

用法::

    python -m scripts.qa_ask "CVE-2024-3400 影响哪些资产"
    python -m scripts.qa_ask "和 T1190 相关的漏洞" --top-k 5 --max-hops 2
    python -m scripts.qa_ask "..." --no-llm            # 强制确定性降级路径（断网演练）
    python -m scripts.qa_ask "..." --graph             # 打印问答图 Mermaid 后退出

输出：答案正文 + 引用列表（来源 / 定位 / 链接）+ 推理链 + 检索命中统计 + 耗时。
退出码：``0`` = 正常返回；``1`` = 未产出答案。
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import time
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from aisec_intel.config import get_settings  # noqa: E402
from aisec_intel.logging_config import get_logger  # noqa: E402
from aisec_intel.qa.graph import graph_mermaid, run_qa  # noqa: E402
from aisec_intel.services.retrieval_service import RetrievalService  # noqa: E402
from aisec_intel.storage.database import get_engine, session_scope  # noqa: E402

logger = get_logger(__name__)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """解析命令行参数。

    Args:
        argv: 参数列表；``None`` 表示使用 ``sys.argv``。

    Returns:
        解析后的命名空间。
    """
    parser = argparse.ArgumentParser(
        description="问答端到端（query_understander → supervisor → reasoner → synthesizer）"
    )
    parser.add_argument("question", nargs="?", default="CVE-2024-3400 影响哪些资产", help="自然语言问题")
    parser.add_argument("--top-k", type=int, default=8, help="单路召回条数（默认 8）")
    parser.add_argument("--max-hops", type=int, default=2, help="多跳上限（默认 2）")
    parser.add_argument("--no-llm", action="store_true", help="强制确定性降级路径（无 LLM）")
    parser.add_argument("--graph", action="store_true", help="打印问答图（Mermaid）后退出")
    return parser.parse_args(argv)


async def run(args: argparse.Namespace) -> int:
    """执行一次问答并打印可读结果。

    Args:
        args: 命令行参数。

    Returns:
        进程退出码（``0`` 正常；``1`` 未产出答案）。
    """
    if args.graph:
        print(graph_mermaid())
        return 0

    settings = get_settings()
    use_llm = False if args.no_llm else None
    print(
        f"[环境] DSN={settings.effective_storage_dsn} | neo4j={settings.neo4j_enabled} "
        f"| vector={settings.effective_vector_backend} | llm={settings.llm_provider}"
        f"({settings.effective_llm_model_fast}/{settings.effective_llm_model_smart}) use_llm={use_llm}"
    )
    started = time.perf_counter()
    async with session_scope(get_engine(settings)) as session:
        service = RetrievalService(session, settings=settings)
        try:
            response, state = await run_qa(
                service,
                args.question,
                settings=settings,
                use_llm=use_llm,
                top_k=max(1, args.top_k),
                max_hops=max(1, args.max_hops),
            )
        finally:
            await service.aclose()
    elapsed = time.perf_counter() - started

    print(f"\n[问题] {args.question}")
    print(f"[意图] {state.get('intent').intent if state.get('intent') else '-'}")
    print(f"[检索] 融合结果={len(state.get('fused') or [])} 条；耗时={elapsed:.2f}s；degraded={response.degraded}")
    print("\n[答案]")
    print(response.answer)
    print(f"\n[引用] {len(response.citations)} 条")
    for index, citation in enumerate(response.citations, start=1):
        print(
            f"  {index}. [{citation.source_type}] {citation.locator}"
            f"{' | cve=' + citation.cve_id if citation.cve_id else ''}"
            f"{' | ' + citation.url if citation.url else ''}"
        )
    print(f"\n[推理链] {len(response.reasoning_chain)} 步")
    for step in response.reasoning_chain:
        print(f"  跳{step.hop}｜{step.question}")
        print(f"        ⇒ {step.conclusion[:120]}")
        print(f"        证据：{', '.join(item.locator for item in step.evidence) or '无'}")
    if state.get("errors"):
        print(f"\n[降级留痕] {len(state['errors'])} 条")
        for item in state["errors"][:5]:
            print(f"  - {item}")
    return 0 if response.answer else 1


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

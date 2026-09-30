"""全链路健康检查脚本（PROJECT_PLAN.md §5.4 / §6.2 P3）。

一次性检查三方可用性，并打印可直接贴进报告的结论表：

1. **中间件**：PostgreSQL（``SELECT 1`` 反射表）、Neo4j（``RETURN 1``）、ChromaDB（heartbeat）；
2. **数据源**：逐个源调用 ``health_check()``（NVD / OSV / GHSA / KEV / EPSS）；
3. **LLM**：``build_provider()`` 配置与依赖是否就绪（**不发起真实补全请求**，避免耗额度）。

用法::

    python -m scripts.health_check              # 全部检查
    python -m scripts.health_check --sources    # 只查数据源
    python -m scripts.health_check --infra      # 只查中间件

退出码：0 = 全部健康；1 = 存在不可用项（详细见输出）。
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
from aisec_intel.connectors import available_sources, create_connector  # noqa: E402
from aisec_intel.llm import LLMError, build_provider  # noqa: E402
from aisec_intel.storage.database import get_engine, ping  # noqa: E402

OK = "[OK  ]"
FAIL = "[FAIL]"
SKIP = "[SKIP]"


async def check_database(settings: Settings) -> tuple[bool, str]:
    """检查结构化存储连通性。

    Args:
        settings: 全局配置。

    Returns:
        ``(是否健康, 说明)``。
    """
    try:
        engine = get_engine(settings)
        if not await ping(engine):
            return False, "无法执行 SELECT 1"
    except Exception as exc:  # noqa: BLE001 - 健康检查需给出原因而非抛出
        return False, f"{type(exc).__name__}: {exc}"
    return True, f"{settings.effective_storage_backend} 连接可用"


async def check_neo4j(settings: Settings) -> tuple[bool, str]:
    """检查 Neo4j 连通性（未装驱动或未启用时按「跳过」处理）。

    Args:
        settings: 全局配置。

    Returns:
        ``(是否健康, 说明)``。
    """
    if not settings.neo4j_enabled:
        return True, "NEO4J_ENABLED=false（按设计跳过）"
    try:
        from neo4j import AsyncGraphDatabase
    except ImportError:
        return True, "未安装 neo4j 驱动（P6 再装，跳过）"
    try:
        driver = AsyncGraphDatabase.driver(
            settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_password.get_secret_value())
        )
        async with driver.session() as session:
            await session.run("RETURN 1 AS ok")
        await driver.close()
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"
    return True, f"{settings.neo4j_uri} 连接可用"


async def check_chroma(settings: Settings) -> tuple[bool, str]:
    """检查 ChromaDB 可用性（未装依赖时按「跳过」处理）。

    Args:
        settings: 全局配置。

    Returns:
        ``(是否健康, 说明)``。
    """
    try:
        import chromadb
    except ImportError:
        return True, "未安装 chromadb（P6 再装，跳过）"
    try:
        if settings.vector_backend == "chroma_persistent":
            client = chromadb.PersistentClient(path=settings.chroma_path)
        else:
            client = chromadb.EphemeralClient()
        client.heartbeat()
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"
    return True, f"{settings.vector_backend} 可用"


def check_llm(settings: Settings) -> tuple[bool, str]:
    """检查 LLM Provider 配置（不发起真实请求）。

    Args:
        settings: 全局配置。

    Returns:
        ``(是否健康, 说明)``。
    """
    try:
        provider = build_provider(settings)
    except LLMError as exc:
        return False, str(exc)
    return True, f"provider={provider.name} fast={provider.model_for('fast')} smart={provider.model_for('smart')}"


async def check_sources(settings: Settings, *, only: list[str] | None = None) -> list[tuple[str, bool, str]]:
    """逐个源执行 ``health_check()``。

    Args:
        settings: 全局配置。
        only: 仅检查指定源；``None`` 表示全部已注册源。

    Returns:
        ``[(源名, 是否健康, 说明), ...]``。
    """
    results: list[tuple[str, bool, str]] = []
    for name in only or available_sources():
        connector = create_connector(name, settings=settings)
        try:
            if not connector.enabled:
                results.append((name, True, "未启用（如缺少 Token），跳过"))
                continue
            healthy = await connector.health_check()
            results.append((name, healthy, "探活成功" if healthy else "探活失败"))
        except Exception as exc:  # noqa: BLE001 - 健康检查需给出原因而非抛出
            results.append((name, False, f"{type(exc).__name__}: {exc}"))
        finally:
            await connector.aclose()
    return results


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """解析命令行参数。

    Args:
        argv: 参数列表；``None`` 表示使用 ``sys.argv``。

    Returns:
        解析后的命名空间。
    """
    parser = argparse.ArgumentParser(description="全链路健康检查（中间件 / 数据源 / LLM）")
    parser.add_argument("--infra", action="store_true", help="只检查中间件与 LLM")
    parser.add_argument("--sources", action="store_true", help="只检查数据源")
    parser.add_argument("--source", default=None, help="只检查指定源（逗号分隔）")
    return parser.parse_args(argv)


async def run(args: argparse.Namespace) -> int:
    """执行健康检查。

    Args:
        args: 命令行参数。

    Returns:
        进程退出码（0 全部健康；1 存在失败项）。
    """
    settings = Settings()
    check_infra = args.infra or not args.sources
    check_src = args.sources or not args.infra
    failures = 0

    print(f"[环境] DSN={settings.effective_storage_dsn} | degraded={settings.degraded_mode}")

    if check_infra:
        print("\n== 中间件 / LLM ==")
        checks: list[tuple[str, tuple[bool, str]]] = [
            ("postgres/sqlite", await check_database(settings)),
            ("neo4j", await check_neo4j(settings)),
            ("chromadb", await check_chroma(settings)),
            ("llm", check_llm(settings)),
        ]
        for label, (healthy, detail) in checks:
            print(f"{OK if healthy else FAIL} {label:<16} {detail}")
            failures += int(not healthy)

    if check_src:
        print("\n== 数据源 ==")
        only = [part.strip().lower() for part in args.source.split(",")] if args.source else None
        for name, healthy, detail in await check_sources(settings, only=only):
            print(f"{OK if healthy else FAIL} {name:<16} {detail}")
            failures += int(not healthy)

    print(f"\n[结论] {'全部健康' if failures == 0 else f'{failures} 项异常'}")
    return 0 if failures == 0 else 1


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

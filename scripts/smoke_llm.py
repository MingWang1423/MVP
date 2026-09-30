"""LLM 连通性冒烟脚本（PROJECT_PLAN.md §3.1 / §3.3 / §5.1）。

用途：验证 ``LLM_API_KEY`` / ``LLM_BASE_URL`` / 模型名是否可用，并确认
``with_structured_output`` 在当前 provider 上可绑定、**可实际产出结构化结果**（§3.2 闸门 ①）。

用法::

    python -m scripts.smoke_llm                          # 默认 provider，发 "ping"
    python -m scripts.smoke_llm --message "你好" --role smart
    python -m scripts.smoke_llm --provider ollama        # 离线兜底链路
    python -m scripts.smoke_llm --check-only             # 只校验配置与依赖，不发请求
    python -m scripts.smoke_llm --structured             # 真调一次结构化输出（含 token 计量）
    python -m scripts.smoke_llm --probe-methods          # 实测 3 种 method 的支持度矩阵

Note:
    ``--probe-methods`` 是排查「400 This response_format type is unavailable now」类问题的
    标准手段（该错误的根因即 langchain-openai 默认 ``method="json_schema"`` 在 DeepSeek 上不可用）。

退出码：0 成功；1 配置错误（缺 Key / 未支持的 provider）；2 调用失败（网络 / 模型侧错误）。
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

# 允许在未执行 `pip install -e .` 的情况下直接以 `python -m scripts.smoke_llm` 运行
_SRC = Path(__file__).resolve().parents[1] / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from pydantic import BaseModel, Field  # noqa: E402

from aisec_intel.config import Settings  # noqa: E402
from aisec_intel.llm import (  # noqa: E402
    STRUCTURED_METHODS,
    LLMConfigError,
    LLMError,
    build_provider,
    resolve_structured_method,
)
from aisec_intel.llm.cache import TokenUsageTracker, wrap_with_cache  # noqa: E402

DEFAULT_MESSAGE = "ping"
"""默认探活消息（保持极短以节省 token）。"""


class PingResult(BaseModel):
    """结构化输出探活结果（同时验证 ``with_structured_output``）。"""

    reply: str = Field(description="模型对探活消息的回复")
    provider_ok: bool = Field(default=True, description="模型是否正常应答")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """解析命令行参数。

    Args:
        argv: 参数列表；``None`` 表示使用 ``sys.argv``。

    Returns:
        解析后的参数命名空间。
    """
    parser = argparse.ArgumentParser(description="LLM 连通性冒烟测试")
    parser.add_argument("--message", default=DEFAULT_MESSAGE, help="探活消息（默认 ping）")
    parser.add_argument("--role", choices=("fast", "smart"), default="fast", help="模型角色（默认 fast）")
    parser.add_argument(
        "--provider",
        default=None,
        help="覆盖 LLM_PROVIDER（deepseek / qwen / zhipu / ollama）；不传则读 .env",
    )
    parser.add_argument("--structured", action="store_true", help="真调一次结构化输出（含 token 计量）")
    parser.add_argument("--method", default=None, help="覆盖结构化方式（function_calling / json_mode / json_schema）")
    parser.add_argument("--probe-methods", action="store_true", help="实测三种 method 的支持度并打印矩阵")
    parser.add_argument("--check-only", action="store_true", help="只校验配置与依赖，不发起网络请求")
    return parser.parse_args(argv)


async def probe_methods(settings: Settings, role: str) -> int:
    """实测三种结构化输出方式在当前 provider / 模型上的可用性。

    逐种方式真调一次（会产生少量 token），用于定位 400 类「response_format 不支持」问题。

    Args:
        settings: 全局配置。
        role: 模型角色（``fast`` / ``smart``）。

    Returns:
        进程退出码（0 表示至少一种方式可用）。
    """
    provider = build_provider(settings)
    model = provider.model_for(role)  # type: ignore[arg-type]
    print(f"[探针] provider={provider.name} model={model}（三种 method 各真调一次，会产生少量 token）")
    messages = [("system", "只输出 JSON 对象。"), ("human", '输出：{"reply": "pong", "provider_ok": true}')]
    ok_count = 0
    for method in STRUCTURED_METHODS:
        try:
            runnable = provider.structured(PingResult, role=role, max_tokens=128, method=method)  # type: ignore[arg-type]
            result = await runnable.ainvoke(messages)
            print(f"  [OK  ] method={method:16s} -> {result!r}")
            ok_count += 1
        except Exception as exc:  # noqa: BLE001 - 探针需汇总所有失败原因
            status = getattr(exc, "status_code", None)
            detail = str(exc).replace("\n", " ")[:160]
            print(f"  [FAIL] method={method:16s} status={status} {type(exc).__name__}: {detail}")
    auto = resolve_structured_method(provider=provider.name, model=model, configured=settings.llm_structured_method)
    print(f"[探针结论] 可用方式 {ok_count}/{len(STRUCTURED_METHODS)}；自动裁决结果={auto}")
    print("[提示] 思考型模型不支持 function_calling，请将 LLM_STRUCTURED_METHOD 设为 json_mode。")
    return 0 if ok_count else 2



async def run(args: argparse.Namespace) -> int:
    """执行冒烟测试。

    Args:
        args: 命令行参数。

    Returns:
        进程退出码（0/1/2，含义见模块 docstring）。
    """
    overrides = {"llm_provider": args.provider} if args.provider else {}
    settings = Settings(**overrides)

    print("[配置] " + str(settings.masked()))
    print(f"[模型] provider={settings.llm_provider} role={args.role} model={settings.effective_llm_model_fast}")

    provider = build_provider(settings)
    print(
        f"[Provider] 名称={provider.name} base_url={getattr(provider, 'base_url', '(n/a)')} "
        f"结构化方式={getattr(provider, 'structured_method_for', lambda role='fast': 'n/a')(args.role)}"
    )

    if not settings.has_llm_api_key and settings.llm_provider != "ollama":
        print("[错误] 未配置 LLM_API_KEY：请在 .env 中填写，或改用 --provider ollama 走离线兜底。")
        return 1

    if args.check_only:
        print("[完成] --check-only：配置与依赖校验通过，未发送网络请求。")
        return 0

    if args.probe_methods:
        return await probe_methods(settings, args.role)

    chat_model = provider.chat(role=args.role, temperature=0.0, max_tokens=64)
    response = await chat_model.ainvoke(args.message)
    content = getattr(response, "content", response)
    print(f"[响应] {content}")

    if args.structured or args.method:
        tracker = TokenUsageTracker()
        runnable = provider.structured_with_usage(PingResult, role=args.role, max_tokens=128, method=args.method)
        runner = wrap_with_cache(
            runnable,
            schema=PingResult,
            model=provider.model_for(args.role),
            provider=provider.name,
            tracker=tracker,
        )
        messages = [("system", "只输出 JSON 对象。"), ("human", '输出：{"reply": "pong", "provider_ok": true}')]
        bound = await runner.ainvoke(messages)
        print(f"[结构化] 结果={bound!r}")
        print(f"[token] {tracker.summary() or '（未取到用量信息）'}")

    print("[完成] LLM 连通性正常。")
    return 0


def main(argv: list[str] | None = None) -> int:
    """脚本入口。

    Args:
        argv: 参数列表；``None`` 表示使用 ``sys.argv``。

    Returns:
        进程退出码。
    """
    args = parse_args(argv)
    try:
        return asyncio.run(run(args))
    except LLMConfigError as exc:
        print(f"[配置错误] {exc}")
        return 1
    except LLMError as exc:
        print(f"[LLM 错误] {exc}")
        return 2
    except Exception as exc:  # noqa: BLE001 - 冒烟脚本需给出明确失败原因
        print(f"[失败] {type(exc).__name__}: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

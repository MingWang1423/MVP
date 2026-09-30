"""LLM 连通性冒烟脚本（PROJECT_PLAN.md §3.1 / §3.3 / §5.1）。

用途：验证 ``LLM_API_KEY`` / ``LLM_BASE_URL`` / 模型名是否可用，并确认
``with_structured_output`` 在当前 provider 上可绑定（§3.2 闸门 ①）。

用法::

    python -m scripts.smoke_llm                          # 默认 provider，发 "ping"
    python -m scripts.smoke_llm --message "你好" --role smart
    python -m scripts.smoke_llm --provider ollama        # 离线兜底链路
    python -m scripts.smoke_llm --check-only             # 只校验配置与依赖，不发请求

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
from aisec_intel.llm import LLMConfigError, LLMError, build_provider  # noqa: E402

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
    parser.add_argument("--structured", action="store_true", help="额外验证 with_structured_output 绑定")
    parser.add_argument("--check-only", action="store_true", help="只校验配置与依赖，不发起网络请求")
    return parser.parse_args(argv)


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
    print(f"[Provider] 名称={provider.name} base_url={getattr(provider, 'base_url', '(n/a)')}")

    if not settings.has_llm_api_key and settings.llm_provider != "ollama":
        print("[错误] 未配置 LLM_API_KEY：请在 .env 中填写，或改用 --provider ollama 走离线兜底。")
        return 1

    if args.check_only:
        print("[完成] --check-only：配置与依赖校验通过，未发送网络请求。")
        return 0

    chat_model = provider.chat(role=args.role, temperature=0.0, max_tokens=64)
    response = await chat_model.ainvoke(args.message)
    content = getattr(response, "content", response)
    print(f"[响应] {content}")

    if args.structured:
        bound = provider.structured(PingResult, role=args.role)
        print(f"[结构化] with_structured_output 绑定成功：{type(bound).__name__}")

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

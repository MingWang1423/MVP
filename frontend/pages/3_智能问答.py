"""页面③：智能问答（``frontend/pages/3_智能问答.py``，Day13 任务 5）。

展示答案 + 引用卡片（可回溯定位）+ 推理链；同一会话 ID 支持多轮追问（Day12 任务 6）。
"""

from __future__ import annotations

import sys
from pathlib import Path

_FRONTEND_DIR = Path(__file__).resolve().parents[1]
if str(_FRONTEND_DIR) not in sys.path:
    sys.path.insert(0, str(_FRONTEND_DIR))

from ui import bootstrap, page_qa  # noqa: E402

bootstrap("智能问答")
page_qa()

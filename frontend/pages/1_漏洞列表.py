"""页面①：漏洞列表（``frontend/pages/1_漏洞列表.py``，Day13 任务 5）。

Streamlit 多页面机制：页面脚本独立执行，共享逻辑在 ``frontend/ui.py``。
"""

from __future__ import annotations

import sys
from pathlib import Path

_FRONTEND_DIR = Path(__file__).resolve().parents[1]
if str(_FRONTEND_DIR) not in sys.path:
    sys.path.insert(0, str(_FRONTEND_DIR))

from ui import bootstrap, page_list  # noqa: E402

bootstrap("漏洞列表")
page_list()

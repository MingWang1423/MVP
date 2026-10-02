"""页面④：数据质量（``frontend/pages/4_数据质量.py``，Day13 任务 5）。

直接渲染 ``reports/data_quality.md``（采集质量）与 ``reports/graph_stats.md``（图谱规模）。
"""

from __future__ import annotations

import sys
from pathlib import Path

_FRONTEND_DIR = Path(__file__).resolve().parents[1]
if str(_FRONTEND_DIR) not in sys.path:
    sys.path.insert(0, str(_FRONTEND_DIR))

from ui import bootstrap, page_quality  # noqa: E402

bootstrap("数据质量")
page_quality()

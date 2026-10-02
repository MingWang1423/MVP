"""页面②：漏洞详情（``frontend/pages/2_漏洞详情.py``，Day13 任务 5）。

展示 7 维富化结论（资产 / 论文 / PoC / 风险 / 攻击链 / CVSS / 修复）与 pyvis 知识子图。
"""

from __future__ import annotations

import sys
from pathlib import Path

_FRONTEND_DIR = Path(__file__).resolve().parents[1]
if str(_FRONTEND_DIR) not in sys.path:
    sys.path.insert(0, str(_FRONTEND_DIR))

from ui import bootstrap, page_detail  # noqa: E402

bootstrap("漏洞详情")
page_detail()

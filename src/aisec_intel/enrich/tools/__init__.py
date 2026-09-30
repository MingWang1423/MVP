"""富化检索工具（PROJECT_PLAN.md §5.6 ``enrich/tools/``）。

- 论文检索：``search_papers`` / ``paper_search_keywords``（只读 ``raw_item``）；
- PoC 检索：``search_github_poc`` / ``search_exploitdb`` / ``search_nuclei``
  （**URL 程序化构造，禁止 LLM 生成**）；
- 可达性：``check_url_reachable``（Verifier 交叉验证用）。
"""

from __future__ import annotations

from aisec_intel.enrich.tools.search_tools import (
    build_exploitdb_search_url,
    build_github_poc_query,
    build_nuclei_template_url,
    check_url_reachable,
    looks_like_poc,
    paper_search_keywords,
    search_exploitdb,
    search_github_poc,
    search_nuclei,
    search_papers,
)

__all__ = [
    "build_exploitdb_search_url",
    "build_github_poc_query",
    "build_nuclei_template_url",
    "check_url_reachable",
    "looks_like_poc",
    "paper_search_keywords",
    "search_exploitdb",
    "search_github_poc",
    "search_nuclei",
    "search_papers",
]


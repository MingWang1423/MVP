"""富化检索工具（PROJECT_PLAN.md §5.6 ``enrich/tools/search_tools.py``）。

本模块是**工具层**（无 LLM 决策，只做确定性抓取）：

论文检索（PaperLinker 用）：
    - :func:`paper_search_keywords`：由 ``cwe_ids`` + ``title`` + ``description`` 生成关键词（纯函数）；
    - :func:`search_papers`：调用只读 :class:`~aisec_intel.storage.repositories.paper_repo.PaperRepository`
      检索 ``raw_item`` 中的 arXiv / OpenAlex 论文。

PoC 检索（PoCSeeker 用）——**URL 一律程序化构造，禁止 LLM 生成**：
    - :func:`build_github_poc_query` / :func:`build_exploitdb_search_url` /
      :func:`build_nuclei_template_url`（纯函数）；
    - :func:`search_github_poc` / :func:`search_exploitdb` / :func:`search_nuclei`（异步抓取）。

可达性检查（Verifier 用）：
    - :func:`check_url_reachable`：HEAD/GET 探活，返回 ``(可达, 状态码)``。
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any

from aisec_intel.config import Settings, get_settings
from aisec_intel.connectors.http_client import HttpClient
from aisec_intel.logging_config import get_logger
from aisec_intel.models.enriched_vuln import ExploitRecord
from aisec_intel.storage.database import get_engine, session_scope
from aisec_intel.storage.repositories.paper_repo import DEFAULT_SCAN_LIMIT, PaperHit, PaperRepository

logger = get_logger(__name__)

GITHUB_SEARCH_URL: str = "https://api.github.com/search/repositories"
"""GitHub 仓库检索 API（程序化构造查询串）。"""

GITHUB_REPO_URL_TEMPLATE: str = "https://github.com/{full_name}"
"""仓库主页模板。"""

EXPLOITDB_SEARCH_URL_TEMPLATE: str = "https://www.exploit-db.com/search?cve={cve_id}"
"""ExploitDB 官方网站检索页（CVE 维度）。"""

EXPLOITDB_DETAIL_URL_TEMPLATE: str = "https://www.exploit-db.com/exploits/{exploit_id}"
"""ExploitDB 条目详情页模板。"""

NUCLEI_TEMPLATE_URL_TEMPLATE: str = (
    "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/http/cves/{year}/{cve_id}.yaml"
)
"""Nuclei 官方模板 raw 地址模板（``http/cves/<年>/<CVE>.yaml``）。"""

NUCLEI_HTML_URL_TEMPLATE: str = (
    "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/{year}/{cve_id}.yaml"
)
"""Nuclei 模板的可读链接（引用回溯用）。"""

POC_HINTS: tuple[str, ...] = ("poc", "cve", "exploit", "vulnerability", "rce")
"""判定「仓库名/描述像 PoC」的关键词（确定性启发式，非 LLM）。"""

_EXPLOIT_ID_PATTERN: re.Pattern[str] = re.compile(r"/exploits/(?P<id>\d+)")
"""从 ExploitDB 链接中提取条目 ID。"""

CVE_YEAR_PATTERN: re.Pattern[str] = re.compile(r"^CVE-(?P<year>\d{4})-\d{4,}$", re.IGNORECASE)
"""CVE 编号中的年份（Nuclei 模板按年分目录）。"""

REACHABLE_STATUS: frozenset[int] = frozenset({200, 204, 301, 302, 307, 308, 401, 403, 405, 429})
"""视为「资源存在但可能需要鉴权 / 反爬」的状态码（不判定为失效）。"""

MISSING_STATUS: frozenset[int] = frozenset({404, 410})
"""资源确实不存在的状态码（判定为不可达）。"""


def paper_search_keywords(
    *,
    cwe_ids: Sequence[str],
    title: str | None,
    description: str,
    max_keywords: int = 6,
) -> list[str]:
    """由漏洞事实生成论文检索关键词（纯函数，确定性）。

    权重顺序：CWE 编号 → 标题实词 → 描述中的长词。CWE 编号转为可检索写法
    （``CWE-77`` → ``cwe-77``）。

    Args:
        cwe_ids: CWE 编号列表（如 ``["CWE-77"]``）。
        title: 漏洞标题。
        description: 漏洞描述。
        max_keywords: 关键词上限。

    Returns:
        去重保序的关键词列表（可能为空）。
    """
    keywords: list[str] = []

    def _push(value: str) -> None:
        cleaned = value.strip().lower()
        if cleaned and cleaned not in keywords and len(cleaned) > 2:
            keywords.append(cleaned)

    for cwe in cwe_ids:
        _push(cwe.replace("CWE-", "cwe-"))
    for token in re.findall(r"[A-Za-z][A-Za-z0-9_.\-]{2,}", title or ""):
        _push(token)
    for token in re.findall(r"[A-Za-z][A-Za-z0-9_.\-]{4,}", description)[:20]:
        _push(token)
    return keywords[: max(1, max_keywords)]


async def search_papers(
    keywords: Sequence[str],
    *,
    limit: int = 5,
    session: Any | None = None,
    settings: Settings | None = None,
    scan_limit: int = DEFAULT_SCAN_LIMIT,
) -> list[PaperHit]:
    """检索论文（arXiv / OpenAlex，只读）。

    Args:
        keywords: 关键词（可含短语，语义见 ``PaperRepository.search``）。
        limit: 返回条数上限。
        session: 已打开的异步会话；``None`` 时自行开启（使用 ``settings`` 的引擎）。
        settings: 全局配置；``session`` 为 ``None`` 时用于建连。
        scan_limit: 最大扫描行数（保护大库）。

    Returns:
        :class:`PaperHit` 列表（按命中数降序）。

    Raises:
        Exception: 数据库不可用时上抛（由 Agent 捕获并降级为空结果）。
    """
    if session is not None:
        return await PaperRepository(session).search(list(keywords), limit=limit, scan_limit=scan_limit)
    resolved = settings or get_settings()
    async with session_scope(get_engine(resolved)) as own_session:
        return await PaperRepository(own_session).search(list(keywords), limit=limit, scan_limit=scan_limit)


def build_github_poc_query(cve_id: str) -> str:
    """构造 GitHub 仓库检索查询串（纯函数）。

    Args:
        cve_id: CVE 编号。

    Returns:
        形如 ``CVE-2024-3400 poc in:name,description,readme`` 的查询串。
    """
    return f"{cve_id.strip().upper()} poc in:name,description,readme"


def build_exploitdb_search_url(cve_id: str) -> str:
    """构造 ExploitDB 检索页 URL（纯函数）。

    Args:
        cve_id: CVE 编号。

    Returns:
        官方网站检索页地址。
    """
    return EXPLOITDB_SEARCH_URL_TEMPLATE.format(cve_id=cve_id.strip().upper())


def build_nuclei_template_url(cve_id: str) -> tuple[str, str]:
    """构造 Nuclei 官方模板地址（纯函数）。

    Args:
        cve_id: CVE 编号。

    Returns:
        ``(raw_yaml_url, html_url)``；CVE 编号不含年份时两者均为空串（无法定位目录）。
    """
    match = CVE_YEAR_PATTERN.match(cve_id.strip())
    if match is None:
        return "", ""
    year = match.group("year")
    normalized = cve_id.strip().upper()
    return (
        NUCLEI_TEMPLATE_URL_TEMPLATE.format(year=year, cve_id=normalized),
        NUCLEI_HTML_URL_TEMPLATE.format(year=year, cve_id=normalized),
    )


def looks_like_poc(*texts: str) -> bool:
    """判断文本是否像 PoC（确定性关键词命中，用于成熟度启发式）。

    Args:
        *texts: 待判定文本（仓库名 / 描述 / 模板内容）。

    Returns:
        命中任一提示词返回 ``True``。
    """
    lowered = " ".join(text for text in texts if text).lower()
    return any(hint in lowered for hint in POC_HINTS)


async def check_url_reachable(url: str, *, http: HttpClient, method: str = "HEAD") -> tuple[bool, int | None]:
    """URL 可达性检查（Verifier 交叉验证第 1 项）。

    先 ``HEAD``；不少站点不支持 HEAD（405 / 403）时退回 ``GET``，避免把「存在但反爬」误判为失效。

    Args:
        url: 待检查地址。
        http: 注入的 HTTP 客户端（统一超时 / 重试 / UA）。
        method: 首次请求方法（默认 ``HEAD``）。

    Returns:
        ``(是否可达, 状态码)``；网络异常返回 ``(False, None)``。

    Note:
        ``HttpClient`` 对非可重试 4xx 会抛 :class:`~aisec_intel.connectors.http_client.HttpStatusError`，
        因此这里显式捕获并按状态码语义判定（403/405 属「存在但反爬」→ 可达）。
    """
    from aisec_intel.connectors.http_client import HttpClientError, HttpStatusError

    for candidate in (method, "GET"):
        try:
            response = await http.request(candidate, url)
        except HttpStatusError as exc:
            if exc.status_code in REACHABLE_STATUS:
                return True, exc.status_code
            if exc.status_code in MISSING_STATUS:
                return False, exc.status_code
            logger.warning(f"URL 可达性检查异常状态：{candidate} {url} → HTTP {exc.status_code}")
            continue
        except HttpClientError as exc:
            logger.warning(f"URL 可达性检查失败：{candidate} {url} → {exc}")
            continue
        if response.status_code in REACHABLE_STATUS:
            return True, response.status_code
    return False, None


async def search_github_poc(
    cve_id: str,
    *,
    http: HttpClient,
    token: str | None = None,
    limit: int = 5,
) -> list[ExploitRecord]:
    """检索 GitHub 上的 PoC 仓库（URL 程序化构造，不经过 LLM）。

    Args:
        cve_id: CVE 编号。
        http: HTTP 客户端。
        token: GitHub Token（可选；有则走鉴权提高配额）。
        limit: 返回条数上限。

    Returns:
        :class:`ExploitRecord` 列表（``verified=False``：尚未逐条人工确认）。

    Raises:
        Exception: 网络 / 结构异常上抛，由 Agent 捕获后降级（不阻断整条链路）。
    """
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    payload = await http.get_json(
        GITHUB_SEARCH_URL,
        params={"q": build_github_poc_query(cve_id), "sort": "stars", "per_page": max(1, limit)},
        headers=headers,
    )
    items = payload.get("items") if isinstance(payload, dict) else None
    if not isinstance(items, list):
        raise ValueError("GitHub 检索响应缺少 items 数组")

    records: list[ExploitRecord] = []
    for entry in items:
        if not isinstance(entry, dict):
            continue
        full_name = str(entry.get("full_name") or "").strip()
        if not full_name:
            continue
        description = str(entry.get("description") or "")
        poc_like = looks_like_poc(full_name, description)
        records.append(
            ExploitRecord(
                source="github",
                url=GITHUB_REPO_URL_TEMPLATE.format(full_name=full_name),
                exploit_type="poc" if poc_like else "unknown",
                maturity="poc" if poc_like else "none",
                reliability=0.6,
                verified=False,
                evidence_refs=[f"stars={entry.get('stargazers_count', 0)}", description[:200]],
            )
        )
    logger.info(f"GitHub PoC 检索 {cve_id}：命中 {len(records)} 条")
    return records[:limit]


async def search_exploitdb(cve_id: str, *, http: HttpClient, limit: int = 5) -> list[ExploitRecord]:
    """检索 ExploitDB（官网 JSON 接口优先，失败退化为「检索入口候选」）。

    Note:
        ExploitDB 无公开 API：本工具先尝试其站点内部 JSON（``X-Requested-With`` 头），
        失败时**不解析 HTML**（脆弱），而是返回一条 ``maturity="none"`` 的**检索入口候选**，
        并明确标记 ``verified=False``，避免把「检索页」当成「已确认的 PoC」。

    Args:
        cve_id: CVE 编号。
        http: HTTP 客户端。
        limit: 返回条数上限。

    Returns:
        :class:`ExploitRecord` 列表（至少 1 条候选；接口不可用时为检索入口）。
    """
    search_url = build_exploitdb_search_url(cve_id)
    records: list[ExploitRecord] = []
    try:
        payload = await http.get_json(
            search_url, headers={"X-Requested-With": "XMLHttpRequest", "Accept": "application/json"}
        )
    except Exception as exc:  # noqa: BLE001 - 接口不可用时退化为检索入口候选
        logger.info(f"ExploitDB JSON 接口不可用（{type(exc).__name__}），退化为检索入口候选")
        payload = None

    rows = payload.get("data") if isinstance(payload, dict) else None
    if isinstance(rows, list):
        for row in rows:
            if not isinstance(row, dict):
                continue
            exploit_id = str(row.get("id") or "").strip()
            if not exploit_id.isdigit():
                continue
            description = str(row.get("description") or "")
            records.append(
                ExploitRecord(
                    source="exploitdb",
                    url=EXPLOITDB_DETAIL_URL_TEMPLATE.format(exploit_id=exploit_id),
                    exploit_type="poc",
                    maturity="poc" if looks_like_poc(description, cve_id) else "none",
                    reliability=0.55,
                    verified=False,
                    evidence_refs=[description[:200]],
                )
            )

    if not records:
        records.append(
            ExploitRecord(
                source="exploitdb-search",
                url=search_url,
                exploit_type="unknown",
                maturity="none",
                reliability=0.3,
                verified=False,
                evidence_refs=["候选检索入口（未解析页面内容，不得当作已确认 PoC）"],
            )
        )
    logger.info(f"ExploitDB 检索 {cve_id}：产出 {len(records)} 条候选")
    return records[:limit]


async def search_nuclei(cve_id: str, *, http: HttpClient, limit: int = 3) -> list[ExploitRecord]:
    """检查官方 Nuclei 模板是否存在该 CVE（模板路径程序化构造）。

    Args:
        cve_id: CVE 编号。
        http: HTTP 客户端。
        limit: 返回条数上限（模板通常 1 条）。

    Returns:
        命中时返回 1 条 ``source="nuclei"`` 记录（``verified=True``：存在性由 HTTP 200 证实），
        否则空列表。
    """
    raw_url, html_url = build_nuclei_template_url(cve_id)
    if not raw_url:
        logger.info(f"Nuclei 模板检索跳过：{cve_id} 不是合法 CVE 编号")
        return []

    try:
        response = await http.request("GET", raw_url)
    except Exception as exc:  # noqa: BLE001 - 模板不存在 / 网络异常均视为未命中
        logger.info(f"Nuclei 模板未命中（{type(exc).__name__}）：{raw_url}")
        return []
    if response.status_code != 200:
        logger.info(f"Nuclei 模板未命中（HTTP {response.status_code}）：{raw_url}")
        return []

    body = response.text or ""
    return [
        ExploitRecord(
            source="nuclei",
            url=html_url,
            exploit_type="poc",
            maturity="functional" if looks_like_poc(body) else "poc",
            reliability=0.8,
            verified=True,
            evidence_refs=[raw_url, f"template_bytes={len(body)}"],
        )
    ][:limit]

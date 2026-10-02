"""Day17 任务 2：``GET /api/v1/papers/{paper_id}`` 集成测试。

用 SQLite 内存库 + ``dependency_overrides`` 覆盖 ``get_paper_repo``，
**不需要 PostgreSQL / 网络** 即可验证「论文关联 Tab 点击卡片 → 加载标题 / 作者 / 摘要」通路：

- 命中：返回 ``paper_id / title / authors / abstract / arxiv_url / published_at``；
- 兼容：容忍 arXiv 版本号后缀（``2404.12345v2``）；
- 未命中：404 且给出可读提示。
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime
from typing import Any

import pytest

pytest.importorskip("sqlalchemy", reason="需要 sqlalchemy：pip install sqlalchemy[asyncio] aiosqlite")
pytest.importorskip("aiosqlite", reason="需要 aiosqlite：pip install aiosqlite")

from fastapi.testclient import TestClient  # noqa: E402

from aisec_intel.api.deps import get_paper_repo  # noqa: E402
from aisec_intel.api.main import create_app  # noqa: E402
from aisec_intel.api.schemas.paper import arxiv_url_of  # noqa: E402
from aisec_intel.models.paper import Paper  # noqa: E402
from aisec_intel.models.raw_item import RawItem  # noqa: E402
from aisec_intel.storage.database import (  # noqa: E402
    create_engine,
    create_session_factory,
    init_models,
    session_scope,
)
from aisec_intel.storage.repositories.paper_repo import PaperRepository  # noqa: E402
from aisec_intel.storage.repositories.raw_repo import RawRepository  # noqa: E402
from aisec_intel.utils.hashing import sha256_text  # noqa: E402

MEMORY_DSN = "sqlite+aiosqlite:///:memory:"

PAPER_ID = "2404.12345"
"""arXiv 论文主键（与富化 ``PaperVulnLink.paper_id`` 同口径）。"""

ARXIV_PAYLOAD: dict[str, Any] = {
    "arxiv_id": PAPER_ID,
    "title": "Prompt Injection Attacks against LLM Agents: A Survey",
    "authors": ["Alice Researcher", "Bob Engineer"],
    "summary": "We survey prompt injection attacks against LLM agents and propose defenses.",
    "published": "2024-04-18T00:00:00Z",
    "abstract_url": f"https://arxiv.org/abs/{PAPER_ID}",
}
"""arXiv 条目样例（``raw_text`` 为条目级保真 JSON）。"""


def make_paper_item(*, source_id: str = PAPER_ID, source: str = "arxiv") -> RawItem:
    """构造论文源 ``RawItem``（测试辅助）。"""
    text = json.dumps(ARXIV_PAYLOAD, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return RawItem(
        trace_id="trace-paper-0001",
        source=source,
        source_id=source_id,
        url=f"https://arxiv.org/abs/{source_id}",
        title=str(ARXIV_PAYLOAD["title"]),
        raw_text=text,
        lang="en",
        published_at=None,
        fetched_at=datetime(2024, 4, 19, tzinfo=UTC),
        sha256=sha256_text(text),
    )


async def seed(engine: Any) -> None:
    """写入一条 arXiv 论文（版本号后缀场景另用不同主键写入）。"""
    async with session_scope(engine) as session:
        await RawRepository(session).upsert(make_paper_item())


@pytest.fixture()
def client() -> Iterator[TestClient]:
    """构造注入了内存库论文仓储的测试客户端。"""
    import asyncio

    engine = create_engine(MEMORY_DSN)
    asyncio.run(init_models(engine))
    asyncio.run(seed(engine))
    factory = create_session_factory(engine)

    async def override_repo() -> AsyncIterator[PaperRepository]:
        async with factory() as session:
            yield PaperRepository(session)

    app = create_app()
    app.dependency_overrides[get_paper_repo] = override_repo
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
    asyncio.run(engine.dispose())


class TestPaperEndpoint:
    """论文详情端点。"""

    def test_detail_returns_metadata(self, client: TestClient) -> None:
        """命中时返回标题 / 作者 / 摘要 / 链接 / 发布时间（前端卡片直接渲染）。"""
        response = client.get(f"/api/v1/papers/{PAPER_ID}")
        assert response.status_code == 200
        payload = response.json()
        assert payload["paper_id"] == PAPER_ID
        assert payload["title"] == ARXIV_PAYLOAD["title"]
        assert payload["authors"] == ARXIV_PAYLOAD["authors"]
        assert "prompt injection" in payload["abstract"].lower()
        assert payload["arxiv_url"] == ARXIV_PAYLOAD["abstract_url"]
        assert payload["source"] == "arxiv"
        assert payload["trace_ids"] == ["trace-paper-0001"]

    def test_detail_tolerates_arxiv_version_suffix(self, client: TestClient) -> None:
        """``2404.12345v2`` 这类带版本号的主键同样命中（PaperLinker 常直接取 URL）。"""
        payload = client.get(f"/api/v1/papers/{PAPER_ID}v2").json()
        assert payload["paper_id"] == PAPER_ID

    def test_unknown_paper_returns_404(self, client: TestClient) -> None:
        """库中不存在时返回 404 并提示先采集论文源。"""
        response = client.get("/api/v1/papers/9999.99999")
        assert response.status_code == 404
        assert "未找到论文" in response.json()["detail"]


class TestArxivUrlFallback:
    """``arxiv_url_of`` 纯函数（OpenAlex 无 url 时的降级口径）。"""

    def test_prefers_collected_url(self) -> None:
        """采集到的 ``url`` 优先（arXiv / OpenAlex / DOI 均适用）。"""
        paper = Paper(paper_id="W123", source="openalex", title="t", url="https://openalex.org/W123")
        assert arxiv_url_of(paper) == "https://openalex.org/W123"

    def test_falls_back_to_arxiv_template(self) -> None:
        """arXiv 来源且缺 ``url`` 时回退 ``https://arxiv.org/abs/<id>``。"""
        paper = Paper(paper_id=PAPER_ID, source="arxiv", title="t")
        assert arxiv_url_of(paper) == f"https://arxiv.org/abs/{PAPER_ID}"

    def test_returns_none_without_any_link(self) -> None:
        """非 arXiv 来源且无 ``url`` 时返回 ``None``（前端隐藏链接）。"""
        assert arxiv_url_of(Paper(paper_id="W1", source="openalex", title="t")) is None

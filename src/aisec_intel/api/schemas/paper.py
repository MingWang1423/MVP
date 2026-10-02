"""论文详情 API 的数据传输契约（Day17 任务 2；PROJECT_PLAN.md §5.8 ``api/routers/paper.py``）。

设计原则（与 ``api/schemas/vuln.py`` 一致）：**不复制冻结模型**——
本模块只定义「论文详情」这一展示型 DTO，字段来源于冻结契约
:class:`~aisec_intel.models.paper.Paper`，可随前端需求调整（不是跨层契约）。
"""

from __future__ import annotations

from datetime import datetime

from pydantic import ConfigDict, Field

from aisec_intel.models.base import IntelBaseModel
from aisec_intel.models.paper import Paper, PaperSource

ARXIV_ABS_TEMPLATE: str = "https://arxiv.org/abs/{paper_id}"
"""arXiv 摘要页地址模板（论文 Tab 的「在 arXiv 查看」入口）。"""


def arxiv_url_of(paper: Paper) -> str | None:
    """推导论文可点击地址（纯函数）。

    规则：优先使用采集到的 ``Paper.url``（OpenAlex / DOI 均有值）；
    缺失且来源为 ``arxiv`` 时回退 :data:`ARXIV_ABS_TEMPLATE`。

    Args:
        paper: 论文实体。

    Returns:
        论文链接；既无 ``url`` 又非 arXiv 来源时返回 ``None``。
    """
    if paper.url:
        return paper.url
    if paper.source == "arxiv":
        return ARXIV_ABS_TEMPLATE.format(paper_id=paper.paper_id)
    return None


class PaperDetailResponse(IntelBaseModel):
    """``GET /papers/{paper_id}`` 的响应体（论文详情卡片）。

    Attributes:
        paper_id: 论文主键（arXiv ID / OpenAlex Work ID）。
        title: 标题。
        authors: 作者列表。
        abstract: 摘要（前端 Markdown 展示）。
        arxiv_url: 论文链接（arXiv 摘要页 / DOI / OpenAlex）。
        published_at: 发布时间（UTC）。
        source: 来源（``arxiv`` / ``openalex`` / ``doi`` / ``other``）。
        venue: 发表期刊 / 会议。
        trace_ids: 关联的 ``RawItem.trace_id``（引用可回溯）。
    """

    model_config = ConfigDict(extra="forbid")

    paper_id: str = Field(description="论文主键（arXiv ID / OpenAlex Work ID）")
    title: str = Field(description="标题")
    authors: list[str] = Field(default_factory=list, description="作者列表")
    abstract: str | None = Field(default=None, description="摘要")
    arxiv_url: str | None = Field(default=None, description="论文链接（arXiv 摘要页 / DOI）")
    published_at: datetime | None = Field(default=None, description="发布时间（UTC）")
    source: PaperSource = Field(default="arxiv", description="来源")
    venue: str | None = Field(default=None, description="发表期刊 / 会议")
    trace_ids: list[str] = Field(default_factory=list, description="关联 trace_id（引用可回溯）")

    @classmethod
    def from_paper(cls, paper: Paper) -> PaperDetailResponse:
        """由冻结契约 ``Paper`` 构造响应（纯函数）。

        Args:
            paper: 论文实体。

        Returns:
            :class:`PaperDetailResponse`。
        """
        return cls(
            paper_id=paper.paper_id,
            title=paper.title,
            authors=list(paper.authors),
            abstract=paper.abstract,
            arxiv_url=arxiv_url_of(paper),
            published_at=paper.published_at,
            source=paper.source,
            venue=paper.venue,
            trace_ids=list(paper.trace_ids),
        )

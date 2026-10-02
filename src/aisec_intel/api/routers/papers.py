"""论文详情路由（Day17 任务 2；PROJECT_PLAN.md §5.8 ``api/routers/paper.py``）。

端点：

===========================  ==================================================
``GET /papers/{paper_id}``   论文详情（标题 / 作者 / 摘要 / arXiv 链接 / 发布时间）
===========================  ==================================================

数据来源（沿既有架构，不新增存储）：

1. 优先查 ``paper`` 起源数据 —— 论文实体当前统一投影自 ``raw_item`` 表的论文源行
   （``arxiv`` / ``openalex``，:class:`~aisec_intel.storage.repositories.paper_repo.PaperRepository`）；
2. ``paper_id`` 大小写与 **arXiv 版本号后缀**（``2404.12345v2``）均被容忍。

该端点补齐了「论文关联 Tab」此前只能外链 arXiv 的信息缺口（见
``reports/INTERFACE_FREEZE.md`` §6 修订记录 v1.3）。
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from aisec_intel.api.deps import get_paper_repo
from aisec_intel.api.schemas.paper import PaperDetailResponse
from aisec_intel.logging_config import get_logger
from aisec_intel.storage.repositories.paper_repo import PaperRepository

logger = get_logger(__name__)

router = APIRouter(prefix="/papers", tags=["papers"])
"""论文路由（挂载后路径为 ``/api/v1/papers/...``）。"""


@router.get(
    "/{paper_id}",
    response_model=PaperDetailResponse,
    summary="论文详情（标题 / 作者 / 摘要 / 链接）",
)
async def get_paper(
    paper_id: str,
    repo: PaperRepository = Depends(get_paper_repo),
) -> PaperDetailResponse:
    """返回单篇论文的元数据与摘要。

    Args:
        paper_id: 论文主键（arXiv ID / OpenAlex Work ID，容忍版本号后缀）。
        repo: 论文只读仓储（请求级会话）。

    Returns:
        :class:`~aisec_intel.api.schemas.paper.PaperDetailResponse`。

    Raises:
        HTTPException: 404 —— 库中不存在该论文（需先采集 arxiv / openalex 源）。
    """
    paper = await repo.get(paper_id)
    if paper is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"未找到论文 {paper_id}（请先采集 arxiv / openalex 源）",
        )
    logger.info(f"论文详情：paper_id={paper.paper_id} source={paper.source} 作者数={len(paper.authors)}")
    return PaperDetailResponse.from_paper(paper)

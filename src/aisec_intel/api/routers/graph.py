"""知识图谱子图路由（Day15 任务 4）。

端点：

=============================  ==================================================
``GET /graph/{cve_id}``        以该 CVE 为中心的 1 跳子图（React Flow 格式）
=============================  ==================================================

设计要点：

- 数据源优先 Neo4j，不可用 / 图中无该节点时**自动降级**为冻结契约推导
  （响应中的 ``backend`` 字段明示来源，便于前端提示与排查）；
- 不含任何 LLM 调用（L5 服务层，见 §2.1）；
- 库中不存在该 CVE 时返回 404（与详情端点一致）。
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status

from aisec_intel.api.deps import get_graph_service
from aisec_intel.api.schemas.graph import (
    GraphEdgeDto,
    GraphNodeDto,
    GraphOverviewResponse,
    GraphResponse,
)
from aisec_intel.logging_config import get_logger
from aisec_intel.models.base import utc_now
from aisec_intel.services.graph_service import (
    DEFAULT_OVERVIEW_MAX_NODES,
    DEFAULT_OVERVIEW_VULN_LIMIT,
    DEFAULT_SUBGRAPH_LIMIT,
    GraphService,
    SubgraphEdge,
    SubgraphNode,
)

logger = get_logger(__name__)

router = APIRouter(prefix="/graph", tags=["graph"])
"""图谱路由（挂载后路径为 ``/api/v1/graph/...``）。"""

MAX_SUBGRAPH_LIMIT: int = 300
"""单次子图邻居行数上限（防止超级节点把前端渲染打满）。"""

MAX_OVERVIEW_VULN_LIMIT: int = 100
"""全图概览可合并的漏洞条数上限。"""

MAX_OVERVIEW_NODES: int = 600
"""全图概览节点上限（超出即裁剪，``truncated=true``）。"""


def _to_node_dto(node: SubgraphNode) -> GraphNodeDto:
    """把服务层节点映射为 API DTO（纯函数）。

    Args:
        node: :class:`~aisec_intel.services.graph_service.SubgraphNode`。

    Returns:
        :class:`GraphNodeDto`。
    """
    return GraphNodeDto(id=node.id, type=node.type, label=node.label, properties=node.properties)


def _to_edge_dto(edge: SubgraphEdge) -> GraphEdgeDto:
    """把服务层边映射为 API DTO（纯函数）。

    Args:
        edge: :class:`~aisec_intel.services.graph_service.SubgraphEdge`。

    Returns:
        :class:`GraphEdgeDto`。
    """
    return GraphEdgeDto(
        id=edge.id, source=edge.source, target=edge.target, relation=edge.relation
    )


@router.get(
    "",
    response_model=GraphOverviewResponse,
    summary="全图概览（多 CVE 合并，无中心 CVE）",
)
async def get_overview(
    limit: int = Query(
        default=DEFAULT_OVERVIEW_VULN_LIMIT,
        ge=1,
        le=MAX_OVERVIEW_VULN_LIMIT,
        description="参与合并的漏洞条数（按富化风险分倒序）",
    ),
    max_nodes: int = Query(
        default=DEFAULT_OVERVIEW_MAX_NODES,
        ge=1,
        le=MAX_OVERVIEW_NODES,
        description="合并后节点上限（超出即裁剪）",
    ),
    service: GraphService = Depends(get_graph_service),
) -> GraphOverviewResponse:
    """返回多 CVE 合并后的全图概览（前端「图谱」页默认视图）。

    Args:
        limit: 参与合并的漏洞条数上限。
        max_nodes: 合并后的节点上限。
        service: 图谱服务（请求级会话）。

    Returns:
        :class:`GraphOverviewResponse`。
    """
    overview = await service.overview(vuln_limit=limit, max_nodes=max_nodes)
    logger.info(
        f"图谱概览：漏洞={len(overview.cve_ids)} 节点={len(overview.nodes)} "
        f"边={len(overview.edges)} truncated={overview.truncated}"
    )
    return GraphOverviewResponse(
        backend=overview.backend,
        cve_ids=list(overview.cve_ids),
        nodes=[_to_node_dto(node) for node in overview.nodes],
        edges=[_to_edge_dto(edge) for edge in overview.edges],
        node_count=len(overview.nodes),
        edge_count=len(overview.edges),
        truncated=overview.truncated,
        generated_at=utc_now(),
    )


@router.get(
    "/{cve_id}",
    response_model=GraphResponse,
    summary="CVE 1 跳图谱子图（React Flow 格式）",
)
async def get_subgraph(
    cve_id: str,
    limit: int = Query(
        default=DEFAULT_SUBGRAPH_LIMIT,
        ge=1,
        le=MAX_SUBGRAPH_LIMIT,
        description="邻居行数上限（超出则 truncated=true）",
    ),
    service: GraphService = Depends(get_graph_service),
) -> GraphResponse:
    """返回以该漏洞为中心的 1 跳子图（节点按类型着色由前端完成）。

    Args:
        cve_id: 漏洞主键（大小写不敏感）。
        limit: 邻居行数上限。
        service: 图谱子图服务（请求级会话）。

    Returns:
        :class:`~aisec_intel.api.schemas.graph.GraphResponse`。

    Raises:
        HTTPException: 404 —— 库中不存在该漏洞。
    """
    subgraph = await service.subgraph(cve_id, limit=limit)
    if subgraph is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"未找到漏洞 {cve_id}")

    logger.info(
        f"图谱子图：{subgraph.cve_id} backend={subgraph.backend} "
        f"节点={len(subgraph.nodes)} 边={len(subgraph.edges)} truncated={subgraph.truncated}"
    )
    return GraphResponse(
        cve_id=subgraph.cve_id,
        backend=subgraph.backend,
        nodes=[_to_node_dto(node) for node in subgraph.nodes],
        edges=[_to_edge_dto(edge) for edge in subgraph.edges],
        node_count=len(subgraph.nodes),
        edge_count=len(subgraph.edges),
        truncated=subgraph.truncated,
    )

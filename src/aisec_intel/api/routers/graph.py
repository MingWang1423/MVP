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
from aisec_intel.api.schemas.graph import GraphEdgeDto, GraphNodeDto, GraphResponse
from aisec_intel.logging_config import get_logger
from aisec_intel.services.graph_service import DEFAULT_SUBGRAPH_LIMIT, GraphService

logger = get_logger(__name__)

router = APIRouter(prefix="/graph", tags=["graph"])
"""图谱路由（挂载后路径为 ``/api/v1/graph/...``）。"""

MAX_SUBGRAPH_LIMIT: int = 300
"""单次子图邻居行数上限（防止超级节点把前端渲染打满）。"""


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
        nodes=[
            GraphNodeDto(
                id=node.id, type=node.type, label=node.label, properties=node.properties
            )
            for node in subgraph.nodes
        ],
        edges=[
            GraphEdgeDto(
                id=edge.id, source=edge.source, target=edge.target, relation=edge.relation
            )
            for edge in subgraph.edges
        ],
        node_count=len(subgraph.nodes),
        edge_count=len(subgraph.edges),
        truncated=subgraph.truncated,
    )

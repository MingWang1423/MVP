"""知识图谱子图 API 的数据传输契约（Day15 任务 4）。

``GET /api/v1/graph/{cve_id}`` 直接返回 **React Flow 可消费**的 ``nodes`` / ``edges``，
前端不需要再写一层转换；节点 ``type`` 为 6 类之一（前端按类型取设计 token 着色）：

====================  ==============================  ==========
``type``              含义                            设计色
====================  ==============================  ==========
``vulnerability``     漏洞（CVE）                     ``critical`` #d62728
``component``         受影响组件 / 生态包             ``primary``  #1f77b4
``asset``             受影响资产                      ``low``      #2ca02c
``technique``         MITRE ATT&CK 技术               ``high``     #ff7f0e
``paper``             关联论文                        #17becf
``patch``             补丁 / 厂商公告                 #9467bd
====================  ==============================  ==========
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import ConfigDict, Field

from aisec_intel.models.base import IntelBaseModel


class GraphNodeDto(IntelBaseModel):
    """React Flow 节点。

    Attributes:
        id: 全局唯一 ID（``标签:键``）。
        type: 节点类型（见模块 docstring 的 6 类）。
        label: 展示名（如 ``CVE-2024-3400`` / ``T1190``）。
        properties: 原始属性（tooltip / 侧栏展示用）。
    """

    model_config = ConfigDict(extra="forbid")

    id: str = Field(description="节点唯一 ID（标签:键）")
    type: str = Field(description="节点类型：vulnerability/component/asset/technique/paper/patch")
    label: str = Field(description="展示名")
    properties: dict[str, Any] = Field(default_factory=dict, description="节点原始属性")


class GraphEdgeDto(IntelBaseModel):
    """React Flow 边。

    Attributes:
        id: 边 ID（``源-关系->目标``）。
        source: 起点节点 ID。
        target: 终点节点 ID。
        relation: 关系类型（``AFFECTS`` / ``INSTALLED_ON`` / ``RELATED_TO`` /
            ``EXPLOITS`` / ``FIXED_BY``）。
    """

    model_config = ConfigDict(extra="forbid")

    id: str = Field(description="边唯一 ID")
    source: str = Field(description="起点节点 ID")
    target: str = Field(description="终点节点 ID")
    relation: str = Field(description="关系类型")


class GraphResponse(IntelBaseModel):
    """``GET /graph/{cve_id}`` 的响应体。

    Attributes:
        cve_id: 中心漏洞主键。
        backend: 数据来源（``neo4j`` 图数据库 / ``postgres`` 冻结契约推导降级路径）。
        nodes: 节点列表（含中心节点）。
        edges: 边列表。
        node_count: 节点数（前端展示用，避免重复计算）。
        edge_count: 边数。
        truncated: 是否因 ``limit`` 截断。
    """

    model_config = ConfigDict(extra="forbid")

    cve_id: str = Field(description="中心漏洞主键")
    backend: Literal["neo4j", "postgres"] = Field(description="子图数据来源")
    nodes: list[GraphNodeDto] = Field(default_factory=list, description="节点列表")
    edges: list[GraphEdgeDto] = Field(default_factory=list, description="边列表")
    node_count: int = Field(default=0, ge=0, description="节点数")
    edge_count: int = Field(default=0, ge=0, description="边数")
    truncated: bool = Field(default=False, description="是否因行数上限截断")


__all__ = ["GraphEdgeDto", "GraphNodeDto", "GraphResponse"]

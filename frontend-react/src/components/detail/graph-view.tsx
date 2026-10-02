/**
 * 知识图谱子图渲染（React Flow，Day16 任务 2.2 Tab 7）。
 *
 * 数据来源：后端 ``GET /api/v1/graph/{cve_id}`` 已返回 React Flow 形态的 ``nodes`` / ``edges``；
 * 本组件只负责 **布局**（以中心漏洞为圆心做放射状分布，避免引入布局引擎）与 **按类型着色**。
 */

import "@xyflow/react/dist/style.css";

import {
  Background,
  Controls,
  MarkerType,
  MiniMap,
  ReactFlow,
  type Edge,
  type Node,
  type NodeProps,
} from "@xyflow/react";
import { useMemo } from "react";

import type { GraphNodeDto, GraphNodeType, GraphResponse } from "@/lib/types";
import { GRAPH_NODE_META, normalizeNodeType } from "@/lib/graph-meta";

export { GRAPH_NODE_META, normalizeNodeType };

/** 节点数据（``props.data``）。 */
interface GraphNodeData extends Record<string, unknown> {
  /** 展示名。 */
  label: string;
  /** 节点类型。 */
  nodeType: GraphNodeType;
}

/** 放射布局参数。 */
const RADIUS = 220;

/**
 * 计算放射状布局（纯函数）。
 *
 * 中心 = 漏洞节点（``(0,0)``），其余节点按类型分环均匀排布，环半径随数量自适应，
 * 保证同一 CVE 的子图每次渲染位置一致（便于截图对比）。
 *
 * @param nodes 后端节点列表。
 * @returns id → ``{x, y}`` 坐标表。
 */
export function layoutRadial(nodes: GraphNodeDto[]): Record<string, { x: number; y: number }> {
  const positions: Record<string, { x: number; y: number }> = {};
  const center = nodes.find((node) => normalizeNodeType(node.type) === "vulnerability");
  if (center) {
    positions[center.id] = { x: 0, y: 0 };
  }
  const others = nodes.filter((node) => node.id !== center?.id);
  const radius = others.length > 10 ? RADIUS * 1.35 : RADIUS;
  others.forEach((node, index) => {
    const angle = (2 * Math.PI * index) / Math.max(1, others.length) - Math.PI / 2;
    positions[node.id] = {
      x: Math.round(radius * Math.cos(angle)),
      y: Math.round(radius * Math.sin(angle)),
    };
  });
  return positions;
}

/**
 * 自定义节点：按类型着色的胶囊（React Flow 默认节点无法直接上设计 token）。
 *
 * @param props React Flow 节点属性。
 * @returns 节点元素。
 */
function GraphPillNode({ data }: NodeProps<Node<GraphNodeData>>): JSX.Element {
  const meta = GRAPH_NODE_META[data.nodeType];
  return (
    <div
      className="max-w-[180px] truncate rounded-lg border bg-card px-3 py-1.5 text-xs font-medium shadow-sm"
      style={{ borderColor: meta.color, color: meta.color }}
      title={data.label}
    >
      <span className="mr-1 opacity-70">[{meta.label}]</span>
      {data.label}
    </div>
  );
}

/** 组件属性。 */
export interface GraphViewProps {
  /** 后端子图响应。 */
  graph: GraphResponse;
  /** 画布高度（像素）。 */
  height?: number;
}

/**
 * 渲染子图。
 *
 * @param props 见 :interface:`GraphViewProps`。
 * @returns React Flow 画布。
 */
export function GraphView({ graph, height = 520 }: GraphViewProps): JSX.Element {
  const nodeTypes = useMemo(() => ({ pill: GraphPillNode }), []);

  const nodes = useMemo<Node<GraphNodeData>[]>(() => {
    const positions = layoutRadial(graph.nodes);
    return graph.nodes.map((node) => {
      const nodeType = normalizeNodeType(node.type);
      return {
        id: node.id,
        type: "pill",
        position: positions[node.id] ?? { x: 0, y: 0 },
        data: { label: node.label, nodeType },
        style: {
          borderColor: GRAPH_NODE_META[nodeType].color,
        },
      };
    });
  }, [graph.nodes]);

  const edges = useMemo<Edge[]>(
    () =>
      graph.edges.map((edge) => ({
        id: edge.id,
        source: edge.source,
        target: edge.target,
        label: edge.relation,
        animated: false,
        style: { stroke: "#94a3b8" },
        labelStyle: { fontSize: 10, fill: "#64748b" },
        markerEnd: { type: MarkerType.ArrowClosed, color: "#94a3b8" },
      })),
    [graph.edges],
  );

  if (graph.nodes.length <= 1) {
    return (
      <div className="flex h-[240px] items-center justify-center rounded-xl border border-dashed text-sm text-muted-foreground">
        该漏洞暂无图谱关系（可能未富化，或缺少 CPE / 资产 / 技术数据）
      </div>
    );
  }

  return (
    <div className="overflow-hidden rounded-xl border" style={{ height }}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        fitView
        minZoom={0.3}
        maxZoom={1.8}
        proOptions={{ hideAttribution: true }}
        nodesDraggable
        nodesConnectable={false}
        edgesFocusable={false}
      >
        <Background gap={16} size={1} color="#cbd5e1" />
        <Controls showInteractive={false} />
        <MiniMap pannable zoomable nodeColor={(node) => {
          const data = node.data as GraphNodeData;
          return GRAPH_NODE_META[data.nodeType]?.color ?? "#94a3b8";
        }} />
      </ReactFlow>
    </div>
  );
}

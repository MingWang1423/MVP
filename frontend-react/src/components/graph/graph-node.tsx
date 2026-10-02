/**
 * 图谱节点外观与 React Flow 数据装配（Day16 任务 1.1 / 1.3）。
 *
 * 设计要点：
 * - 节点为**圆形**：直径由风险分决定（漏洞节点，§1.1「节点大小按风险分」），
 *   其余类型固定直径；边框与底色取类型色（与 :data:`GRAPH_NODE_META` 单一事实来源）；
 * - 节点右上角的 ``+ / -`` 徽标用于**展开 / 折叠**邻居（§1.3），折叠时显示被隐藏的邻居数；
 * - 搜索未命中的节点降透明度（``dimmed``），命中节点加高亮描边（``matched``）。
 */

import { MarkerType, type Edge, type Node, type NodeProps } from "@xyflow/react";
import { Minus, Plus } from "lucide-react";

import { GRAPH_NODE_META, normalizeNodeType } from "@/lib/graph-meta";
import { hexToRgba } from "@/lib/graph-export";
import type { GraphEdgeDto, GraphNodeDto, GraphNodeType } from "@/lib/types";
import { cn } from "@/lib/utils";

/** 漏洞节点直径区间（按风险分线性映射）。 */
export const VULN_DIAMETER_MIN = 76;
export const VULN_DIAMETER_MAX = 132;

/** 非漏洞节点直径。 */
export const PLAIN_DIAMETER = 74;

/** 节点数据（``props.data``）。 */
export interface GraphNodeData extends Record<string, unknown> {
  /** 展示名。 */
  label: string;
  /** 归一化后的节点类型。 */
  nodeType: GraphNodeType;
  /** 关联的漏洞主键（漏洞节点必有；其它类型从 ``properties.cve_id`` 取，可能为空）。 */
  cveId: string;
  /** 风险分（非漏洞节点为 0）。 */
  riskScore: number;
  /** 是否存在邻居（决定是否显示折叠徽标）。 */
  hasNeighbours: boolean;
  /** 是否已折叠。 */
  collapsed: boolean;
  /** 被隐藏的邻居数（折叠时显示）。 */
  hiddenCount: number;
  /** 是否命中检索词。 */
  matched: boolean;
  /** 是否被检索 / 筛选排除（降透明度）。 */
  dimmed: boolean;
  /** 折叠开关回调。 */
  onToggleCollapse: (nodeId: string) => void;
}

/**
 * 计算节点直径（纯函数）。
 *
 * @param nodeType 节点类型。
 * @param riskScore 风险分（0-100）。
 * @returns 直径（像素）。
 */
export function nodeDiameter(nodeType: GraphNodeType, riskScore: number): number {
  if (nodeType !== "vulnerability") {
    return PLAIN_DIAMETER;
  }
  const score = Math.max(0, Math.min(100, riskScore));
  return Math.round(VULN_DIAMETER_MIN + ((VULN_DIAMETER_MAX - VULN_DIAMETER_MIN) * score) / 100);
}

/**
 * 自定义节点组件（圆形 + 类型色 + 折叠徽标）。
 *
 * @param props React Flow 节点属性。
 * @returns 节点元素。
 */
export function GraphCircleNode({ id, data, selected }: NodeProps<Node<GraphNodeData>>): JSX.Element {
  const meta = GRAPH_NODE_META[data.nodeType];
  return (
    <div
      className={cn(
        "relative flex size-full items-center justify-center rounded-full border-2 px-1 text-center transition-opacity",
        data.dimmed ? "opacity-30" : "opacity-100",
        selected ? "ring-2 ring-ring ring-offset-2 ring-offset-background" : "",
      )}
      style={{
        borderColor: meta.color,
        backgroundColor: hexToRgba(meta.color, 0.14),
        boxShadow:
          data.matched && !data.dimmed ? `0 0 0 3px ${hexToRgba(meta.color, 0.25)}` : undefined,
      }}
      title={`${meta.label}：${data.label}`}
    >
      <span className="line-clamp-4 break-all px-1 text-[11px] font-medium leading-tight text-foreground">
        {data.label}
      </span>

      {data.nodeType === "vulnerability" ? (
        <span className="absolute bottom-1.5 text-[10px] font-semibold tabular-nums text-muted-foreground">
          风险 {data.riskScore.toFixed(0)}
        </span>
      ) : null}

      {data.hasNeighbours ? (
        <button
          type="button"
          className="nodrag absolute -right-1 -top-1 flex size-5 items-center justify-center rounded-full border bg-card text-muted-foreground shadow-sm hover:text-foreground"
          aria-label={data.collapsed ? `展开 ${data.label} 的邻居` : `折叠 ${data.label} 的邻居`}
          title={data.collapsed ? "展开邻居" : "折叠邻居"}
          onClick={(event) => {
            event.stopPropagation();
            data.onToggleCollapse(id);
          }}
        >
          {data.collapsed ? (
            <Plus className="size-3" aria-hidden />
          ) : (
            <Minus className="size-3" aria-hidden />
          )}
        </button>
      ) : null}

      {data.collapsed && data.hiddenCount > 0 ? (
        <span className="absolute -bottom-1 rounded-full border bg-card px-1.5 text-[9px] text-muted-foreground shadow-sm">
          +{data.hiddenCount}
        </span>
      ) : null}
    </div>
  );
}

/** 构建 React Flow 节点所需的上下文。 */
export interface BuildNodesContext {
  /** 全部节点的风险分（用于定尺寸 / 显示）。 */
  riskScores: Map<string, number>;
  /** 邻居数表（决定是否显示折叠徽标）。 */
  neighbourCounts: Map<string, number>;
  /** 被折叠的节点集合。 */
  collapsed: Set<string>;
  /** 被隐藏的邻居数（折叠状态下的展示值）。 */
  hiddenCounts: Map<string, number>;
  /** 命中检索的节点集合。 */
  matchedIds: Set<string>;
  /** 是否启用检索高亮。 */
  highlight: boolean;
  /** 折叠开关回调。 */
  onToggleCollapse: (nodeId: string) => void;
}

/**
 * 把后端节点 + 布局坐标装配为 React Flow 节点（纯函数）。
 *
 * @param nodes 后端节点列表。
 * @param positions 节点 ID → 坐标。
 * @param context 展示上下文（风险分 / 折叠 / 检索）。
 * @returns React Flow 节点数组。
 */
export function buildFlowNodes(
  nodes: GraphNodeDto[],
  positions: Record<string, { x: number; y: number }>,
  context: BuildNodesContext,
): Node<GraphNodeData>[] {
  return nodes.map((node) => {
    const nodeType = normalizeNodeType(node.type);
    const riskScore = context.riskScores.get(node.id) ?? 0;
    const diameter = nodeDiameter(nodeType, riskScore);
    const matched = context.matchedIds.has(node.id);
    return {
      id: node.id,
      type: "aisecNode",
      position: positions[node.id] ?? { x: 0, y: 0 },
      data: {
        label: node.label,
        nodeType,
        cveId:
          String(node.properties?.cve_id ?? "") ||
          (nodeType === "vulnerability" ? node.label : ""),
        riskScore,
        hasNeighbours: (context.neighbourCounts.get(node.id) ?? 0) > 0,
        collapsed: context.collapsed.has(node.id),
        hiddenCount: context.hiddenCounts.get(node.id) ?? 0,
        matched,
        dimmed: context.highlight && !matched,
        onToggleCollapse: context.onToggleCollapse,
      },
      style: { width: diameter, height: diameter },
      // React Flow 需要节点尺寸来计算连线端点（不能只给 CSS 宽高）
      width: diameter,
      height: diameter,
    };
  });
}

/**
 * 把后端边装配为 React Flow 边（纯函数，带关系标签与箭头）。
 *
 * @param edges 后端边列表。
 * @returns React Flow 边数组。
 */
export function buildFlowEdges(edges: GraphEdgeDto[]): Edge[] {
  return edges.map((edge) => ({
    id: edge.id,
    source: edge.source,
    target: edge.target,
    label: edge.relation,
    animated: false,
    style: { stroke: "#94a3b8", strokeWidth: 1.2 },
    labelStyle: { fontSize: 9, fill: "#64748b" },
    labelBgStyle: { fill: "rgba(255,255,255,0.75)" },
    labelBgPadding: [3, 2] as [number, number],
    labelBgBorderRadius: 4,
    markerEnd: { type: MarkerType.ArrowClosed, color: "#94a3b8", width: 14, height: 14 },
  }));
}

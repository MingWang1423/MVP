/**
 * 图谱画布（React Flow 封装，Day16 任务 1.1 / 1.3）。
 *
 * 能力：
 * - 全屏画布（占满主内容区），拖拽 / 缩放（滚轮 + Controls + MiniMap）由 React Flow 提供；
 * - ``fitView`` + 「适应画布」按钮（数据视图切换后重新取景）；
 * - 单双击语义：单击选中（侧栏显示属性）、双击漏洞节点跳详情页；
 * - 顶部 / 右下角为覆盖层插槽（工具栏、图例），不参与图布局。
 */

import "@xyflow/react/dist/style.css";

import {
  Background,
  BackgroundVariant,
  Controls,
  MiniMap,
  ReactFlow,
  ReactFlowProvider,
  useReactFlow,
  type Edge,
  type Node,
  type NodeTypes,
} from "@xyflow/react";
import { Maximize2 } from "lucide-react";
import { useEffect, useMemo, type ReactNode } from "react";
import { useNavigate } from "react-router-dom";

import { GraphCircleNode, type GraphNodeData } from "@/components/graph/graph-node";
import { Button } from "@/components/ui/button";
import { GRAPH_NODE_META } from "@/lib/graph-meta";
import { cn } from "@/lib/utils";

/** 组件属性。 */
export interface GraphCanvasProps {
  /** React Flow 节点。 */
  nodes: Node<GraphNodeData>[];
  /** React Flow 边。 */
  edges: Edge[];
  /** 选中节点变化（``null`` = 取消选中）。 */
  onSelectNode: (nodeId: string | null) => void;
  /** 视图标识（切换时重新取景；如 ``overview`` / CVE 编号）。 */
  viewKey: string;
  /** 顶部覆盖层（工具栏）。 */
  toolbar?: ReactNode;
  /** 右下角覆盖层（图例）。 */
  legend?: ReactNode;
  /** 是否显示骨架（加载中）。 */
  loading?: boolean;
  /** 空态提示。 */
  emptyHint?: string;
  /** 附加类名。 */
  className?: string;
}

/**
 * 画布内部实现（需要位于 :class:`ReactFlowProvider` 内才能使用 ``useReactFlow``）。
 *
 * @param props 见 :interface:`GraphCanvasProps`。
 * @returns 画布元素。
 */
function CanvasInner({
  nodes,
  edges,
  onSelectNode,
  viewKey,
  toolbar,
  legend,
  loading = false,
  emptyHint,
  className,
}: GraphCanvasProps): JSX.Element {
  const navigate = useNavigate();
  const { fitView } = useReactFlow();
  const nodeTypes = useMemo<NodeTypes>(() => ({ aisecNode: GraphCircleNode }), []);

  // 视图切换（概览 ↔ 某 CVE 子图）后自动重新取景，避免停在旧坐标
  useEffect(() => {
    const timer = window.setTimeout(() => {
      void fitView({ padding: 0.22, duration: 320 });
    }, 60);
    return () => window.clearTimeout(timer);
  }, [fitView, viewKey, nodes.length]);

  const isEmpty = !loading && nodes.length === 0;

  return (
    <div className={cn("relative h-full w-full overflow-hidden", className)}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        fitView
        minZoom={0.15}
        maxZoom={2.4}
        proOptions={{ hideAttribution: true }}
        nodesDraggable
        nodesConnectable={false}
        edgesFocusable={false}
        onNodeClick={(_, node) => onSelectNode(node.id)}
        onPaneClick={() => onSelectNode(null)}
        onNodeDoubleClick={(_, node) => {
          const data = node.data as GraphNodeData;
          // 双击漏洞节点 → 跳详情页；其它类型节点只做选中 + 取景（§1.3 交互约定）
          if (data.cveId) {
            navigate(`/vulnerabilities/${encodeURIComponent(data.cveId)}`);
            return;
          }
          onSelectNode(node.id);
          void fitView({ nodes: [node], padding: 1.6, duration: 320 });
        }}
      >
        <Background variant={BackgroundVariant.Dots} gap={18} size={1} color="#cbd5e1" />
        <Controls
          showInteractive={false}
          className="!bottom-4 !left-4 overflow-hidden rounded-lg border shadow-sm"
        />
        <MiniMap
          pannable
          zoomable
          style={{ width: 132, height: 92 }}
          className="!bottom-4 !right-4 rounded-lg border opacity-90 shadow-sm"
          maskColor="rgba(148, 163, 184, 0.15)"
          nodeColor={(node) => GRAPH_NODE_META[(node.data as GraphNodeData).nodeType].color}
          nodeStrokeWidth={2}
        />
      </ReactFlow>

      <div className="pointer-events-none absolute inset-x-0 top-0 flex flex-wrap items-center gap-2 p-3">
        <div className="pointer-events-auto flex flex-wrap items-center gap-2 rounded-lg border bg-card/95 p-2 shadow-card backdrop-blur">
          {toolbar}
        </div>
      </div>

      <div className="absolute right-4 top-16 flex flex-col gap-2">
        <Button
          variant="outline"
          size="sm"
          className="bg-card/95 backdrop-blur"
          onClick={() => void fitView({ padding: 0.22, duration: 320 })}
          title="适应画布"
        >
          <Maximize2 className="mr-1.5 size-3.5" aria-hidden />
          适应画布
        </Button>
      </div>

      {legend ? (
        <div className="pointer-events-auto absolute bottom-4 left-1/2 -translate-x-1/2 rounded-lg border bg-card/95 px-3 py-2 shadow-card backdrop-blur">
          {legend}
        </div>
      ) : null}

      {loading ? (
        <div className="absolute inset-0 flex items-center justify-center bg-background/70 backdrop-blur-sm">
          <div className="flex flex-col items-center gap-2 text-sm text-muted-foreground">
            <span className="size-6 animate-spin rounded-full border-2 border-primary border-t-transparent" />
            正在加载图谱数据…
          </div>
        </div>
      ) : null}

      {isEmpty ? (
        <div className="absolute inset-0 flex items-center justify-center p-6">
          <div className="max-w-sm rounded-xl border border-dashed bg-card/95 p-6 text-center shadow-card">
            <p className="text-sm font-medium">{emptyHint ?? "当前筛选条件下没有可展示的节点"}</p>
            <p className="mt-1 text-xs text-muted-foreground">
              可放宽类型 / 风险分区间，或先在「漏洞」页触发富化后再查看图谱。
            </p>
          </div>
        </div>
      ) : null}
    </div>
  );
}

/**
 * 图谱画布（自带 :class:`ReactFlowProvider`，可直接嵌入页面）。
 *
 * @param props 见 :interface:`GraphCanvasProps`。
 * @returns 画布元素。
 */
export function GraphCanvas(props: GraphCanvasProps): JSX.Element {
  return (
    <ReactFlowProvider>
      <CanvasInner {...props} />
    </ReactFlowProvider>
  );
}

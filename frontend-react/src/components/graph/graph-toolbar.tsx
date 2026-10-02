/**
 * 图谱覆盖层工具栏（Day16 任务 1.3）：视图说明 + 展开 / 折叠 + 导出 PNG。
 *
 * 与画布解耦：工具栏只发命令，状态全部由页面持有（便于 URL / 截图复现）。
 */

import { Download, Share2 } from "lucide-react";

import { Button } from "@/components/ui/button";

/** 组件属性。 */
export interface GraphToolbarProps {
  /** 视图名（``全图概览`` 或 CVE 编号）。 */
  viewLabel: string;
  /** 当前节点数。 */
  nodeCount: number;
  /** 当前边数。 */
  edgeCount: number;
  /** 因折叠被隐藏的节点数。 */
  hiddenCount: number;
  /** 是否存在可折叠的漏洞节点（决定「折叠到漏洞层」是否可用）。 */
  canCollapse: boolean;
  /** 展开全部。 */
  onExpandAll: () => void;
  /** 折叠到漏洞层。 */
  onCollapseAll: () => void;
  /** 导出当前视图为 PNG。 */
  onExport: () => void;
}

/**
 * 渲染工具栏（放在画布左上角的半透明卡片内）。
 *
 * @param props 见 :interface:`GraphToolbarProps`。
 * @returns 工具栏元素。
 */
export function GraphToolbar({
  viewLabel,
  nodeCount,
  edgeCount,
  hiddenCount,
  canCollapse,
  onExpandAll,
  onCollapseAll,
  onExport,
}: GraphToolbarProps): JSX.Element {
  return (
    <>
      <Share2 className="size-3.5 text-muted-foreground" aria-hidden />
      <span className="text-xs text-muted-foreground">
        {viewLabel} · {nodeCount} 节点 / {edgeCount} 边
        {hiddenCount > 0 ? ` · 已折叠 ${hiddenCount}` : ""}
      </span>
      <Button
        variant="ghost"
        size="sm"
        className="h-7 px-2 text-xs"
        onClick={onExpandAll}
        disabled={hiddenCount === 0}
      >
        全部展开
      </Button>
      <Button
        variant="ghost"
        size="sm"
        className="h-7 px-2 text-xs"
        onClick={onCollapseAll}
        disabled={!canCollapse}
      >
        折叠到漏洞层
      </Button>
      <Button variant="ghost" size="sm" className="h-7 px-2 text-xs" onClick={onExport}>
        <Download className="mr-1 size-3.5" aria-hidden />
        导出 PNG
      </Button>
    </>
  );
}

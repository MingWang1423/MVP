/**
 * 严重度徽标（列表 / 表格 / 卡片共用）。
 *
 * 颜色取自 ``lib/format.ts`` 的 :data:`LEVEL_META`，禁止在组件内写死颜色。
 */

import { Badge } from "@/components/ui/badge";
import { severityMeta } from "@/lib/format";
import type { Severity } from "@/lib/types";
import { cn } from "@/lib/utils";

/** 组件属性。 */
export interface SeverityBadgeProps {
  /** 事实层严重度；``null`` 表示源未提供（渲染为「未定级」）。 */
  severity: Severity | null | undefined;
  /** 附加类名。 */
  className?: string;
}

/**
 * 渲染严重度徽标。
 *
 * @param props 见 :interface:`SeverityBadgeProps`。
 * @returns 徽标元素。
 */
export function SeverityBadge({ severity, className }: SeverityBadgeProps): JSX.Element {
  const meta = severityMeta(severity);
  return (
    <Badge className={cn("border-transparent font-medium", meta.badgeClass, className)}>
      {meta.label}
    </Badge>
  );
}

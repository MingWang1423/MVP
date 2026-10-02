/**
 * 图表容器卡片（统一标题 / 描述 / 操作区与内边距）。
 */

import type { ReactNode } from "react";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";

/** 组件属性。 */
export interface ChartCardProps {
  /** 标题。 */
  title: string;
  /** 副标题 / 口径说明。 */
  description?: string;
  /** 右上角操作区。 */
  action?: ReactNode;
  /** 图表主体。 */
  children: ReactNode;
  /** 附加类名。 */
  className?: string;
}

/**
 * 渲染图表卡片。
 *
 * @param props 见 :interface:`ChartCardProps`。
 * @returns 卡片元素。
 */
export function ChartCard({
  title,
  description,
  action,
  children,
  className,
}: ChartCardProps): JSX.Element {
  return (
    <Card className={cn("shadow-card", className)}>
      <CardHeader className="flex-row items-start justify-between gap-3 space-y-0 pb-2">
        <div className="space-y-1">
          <CardTitle className="text-base">{title}</CardTitle>
          {description ? <CardDescription>{description}</CardDescription> : null}
        </div>
        {action}
      </CardHeader>
      <CardContent className="pt-2">{children}</CardContent>
    </Card>
  );
}

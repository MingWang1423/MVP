/**
 * 统一页头（Day16 任务 4：间距 / 圆角 / 阴影一致）。
 *
 * 全站页头统一为「标题 + 口径说明 + 右侧操作区」，间距 ``space-y-1``、
 * 标题 ``text-2xl font-semibold tracking-tight``、说明 ``text-sm muted``，
 * 与首页 / 列表页既有写法保持同一份视觉语言。
 */

import type { ReactNode } from "react";

import { cn } from "@/lib/utils";

/** 组件属性。 */
export interface PageHeaderProps {
  /** 页面标题。 */
  title: string;
  /** 口径 / 说明文案。 */
  description?: ReactNode;
  /** 右侧操作区（按钮 / 切换器）。 */
  actions?: ReactNode;
  /** 附加类名。 */
  className?: string;
}

/**
 * 渲染页头。
 *
 * @param props 见 :interface:`PageHeaderProps`。
 * @returns 页头元素（窄屏纵向堆叠，宽屏左右分布）。
 */
export function PageHeader({ title, description, actions, className }: PageHeaderProps): JSX.Element {
  return (
    <header
      className={cn(
        "flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between",
        className,
      )}
    >
      <div className="min-w-0 space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
        {description ? (
          <div className="text-sm text-muted-foreground">{description}</div>
        ) : null}
      </div>
      {actions ? <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div> : null}
    </header>
  );
}

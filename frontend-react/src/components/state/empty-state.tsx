/**
 * 统一空态（Day16 任务 4：所有页面「无数据」提示）。
 *
 * 与 :component:`ErrorState` 成对使用：空态说明「为什么没有数据 + 下一步能做什么」，
 * 错误态负责「重试」。两者共用同一套圆角 / 间距（``Card`` + ``border-dashed``）。
 */

import { Inbox, type LucideIcon } from "lucide-react";
import type { ReactNode } from "react";

import { cn } from "@/lib/utils";

/** 组件属性。 */
export interface EmptyStateProps {
  /** 标题（一句话说明当前没有数据）。 */
  title: string;
  /** 补充说明（口径 / 可能原因）。 */
  description?: string;
  /** 图标（默认收件箱）。 */
  icon?: LucideIcon;
  /** 行动区（按钮 / 链接）。 */
  action?: ReactNode;
  /** 额外类名。 */
  className?: string;
}

/**
 * 渲染空态。
 *
 * @param props 见 :interface:`EmptyStateProps`。
 * @returns 空态元素。
 */
export function EmptyState({
  title,
  description,
  icon: Icon = Inbox,
  action,
  className,
}: EmptyStateProps): JSX.Element {
  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center gap-2 rounded-xl border border-dashed px-6 py-12 text-center",
        className,
      )}
      role="status"
    >
      <span className="flex size-11 items-center justify-center rounded-full bg-muted text-muted-foreground">
        <Icon className="size-5" aria-hidden />
      </span>
      <p className="text-sm font-medium">{title}</p>
      {description ? (
        <p className="max-w-md text-xs leading-relaxed text-muted-foreground">{description}</p>
      ) : null}
      {action ? <div className="mt-2">{action}</div> : null}
    </div>
  );
}

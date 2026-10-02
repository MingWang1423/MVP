/**
 * shadcn/ui · Skeleton（等价于 `npx shadcn@latest add skeleton` 生成的源码）。
 */

import * as React from "react";

import { cn } from "@/lib/utils";

/**
 * 骨架屏占位块。
 *
 * @param props 标准 ``div`` 属性。
 * @returns 带脉冲动画的占位块。
 */
function Skeleton({ className, ...props }: React.HTMLAttributes<HTMLDivElement>): JSX.Element {
  return <div className={cn("animate-pulse rounded-md bg-muted", className)} {...props} />;
}

export { Skeleton };

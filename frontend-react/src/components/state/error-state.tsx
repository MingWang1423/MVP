/**
 * 统一错误态（Day16 任务 4：网络失败时的重试入口）。
 *
 * 口径：
 * - 文案优先用 :class:`~@/lib/api.ApiError` 的中文 ``detail``（拦截器已做映射），
 *   否则回退 ``Error.message``；
 * - 「重试」按钮由调用方注入（TanStack Query 的 ``refetch``）；
 * - 与 :component:`EmptyState` 视觉同源，页面之间不再各写一套。
 */

import { AlertTriangle, RefreshCw } from "lucide-react";

import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

/** 组件属性。 */
export interface ErrorStateProps {
  /** 标题（默认「数据加载失败」）。 */
  title?: string;
  /** 错误对象（取 ``message`` 作为详情）。 */
  error?: unknown;
  /** 重试回调；缺省时不渲染按钮。 */
  onRetry?: () => void;
  /** 是否正在重试（按钮转圈 + 禁用）。 */
  retrying?: boolean;
  /** 附加类名。 */
  className?: string;
}

/**
 * 渲染错误态。
 *
 * @param props 见 :interface:`ErrorStateProps`。
 * @returns 错误态元素。
 */
export function ErrorState({
  title = "数据加载失败",
  error,
  onRetry,
  retrying = false,
  className,
}: ErrorStateProps): JSX.Element {
  const detail =
    error instanceof Error && error.message ? error.message : "未知错误，请查看后端服务日志";

  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center gap-2 rounded-xl border border-destructive/40 bg-destructive/5 px-6 py-12 text-center",
        className,
      )}
      role="alert"
    >
      <span className="flex size-11 items-center justify-center rounded-full bg-destructive/10 text-destructive">
        <AlertTriangle className="size-5" aria-hidden />
      </span>
      <p className="text-sm font-medium text-destructive">{title}</p>
      <p className="max-w-md text-xs leading-relaxed text-muted-foreground">{detail}</p>
      {onRetry ? (
        <Button className="mt-2" size="sm" onClick={onRetry} disabled={retrying}>
          <RefreshCw className={retrying ? "mr-2 size-4 animate-spin" : "mr-2 size-4"} aria-hidden />
          重试
        </Button>
      ) : null}
    </div>
  );
}

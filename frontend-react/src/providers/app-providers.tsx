/**
 * 应用级 Provider 组合（Day14 任务 1 / 任务 5）。
 *
 * - :class:`QueryClientProvider`：TanStack Query v5 全局客户端；
 * - :class:`ThemeProvider`：深色模式；
 * - :class:`Toaster`：Sonner Toast 容器（与 ``lib/api.ts`` 的错误提示联动）。
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";

import { ThemeProvider } from "@/components/theme-provider";
import { Toaster } from "@/components/ui/sonner";

/** 全局查询客户端：默认不重试（后端不可用时快速失败并提示），窗口聚焦刷新由各 Hook 决定。 */
export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
      staleTime: 30_000,
    },
    mutations: {
      retry: 0,
    },
  },
});

/**
 * 包裹应用的 Provider 组合。
 *
 * @param props.children 应用的组件树。
 * @returns 已注入全部上下文的元素。
 */
export function AppProviders({ children }: { children: ReactNode }): JSX.Element {
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        {children}
        <Toaster richColors closeButton position="top-right" />
      </ThemeProvider>
    </QueryClientProvider>
  );
}

/**
 * shadcn/ui · Sonner Toaster（等价于 `npx shadcn@latest add sonner`）。
 *
 * 与官方源码的差异：主题来源改为本项目的 :func:`useTheme`（不引入 next-themes，
 * 因为本工程是纯 Vite SPA）。
 */

import { Toaster as Sonner, type ToasterProps } from "sonner";

import { useTheme } from "@/components/theme-provider";

/**
 * 全局 Toast 容器。
 *
 * @param props Sonner 原生属性（含 ``richColors`` / ``position`` / ``closeButton``）。
 * @returns Toast 容器元素。
 */
const Toaster = ({ ...props }: ToasterProps): JSX.Element => {
  const { resolvedTheme } = useTheme();

  return (
    <Sonner
      theme={resolvedTheme}
      className="toaster group"
      toastOptions={{
        classNames: {
          toast:
            "group toast group-[.toaster]:bg-background group-[.toaster]:text-foreground group-[.toaster]:border-border group-[.toaster]:shadow-lg",
          description: "group-[.toast]:text-muted-foreground",
          actionButton: "group-[.toast]:bg-primary group-[.toast]:text-primary-foreground",
          cancelButton: "group-[.toast]:bg-muted group-[.toast]:text-muted-foreground",
        },
      }}
      {...props}
    />
  );
};

export { Toaster };

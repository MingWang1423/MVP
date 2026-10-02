import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

/**
 * 合并 Tailwind 类名（shadcn/ui 标准工具函数）。
 *
 * Args:
 *   inputs: 任意数量的类名片段 / 条件对象 / 数组。
 *
 * Returns:
 *   去重且后者优先的类名字符串。
 */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}

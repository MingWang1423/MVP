/**
 * 应用布局骨架（Day14 任务 3）。
 *
 * 结构：
 * - 顶部导航：Logo + 五个主菜单 + 全局搜索 + 深色模式切换 + 侧边栏开关；
 * - 侧边栏：**默认折叠**，展开后展示带图标的纵向导航与系统说明；
 * - 主内容区：``max-w-7xl`` 居中；
 * - 底部：简洁 footer（版本 / 数据来源）。
 */

import { AnimatePresence, motion } from "framer-motion";
import {
  Bug,
  Gauge,
  LayoutDashboard,
  Menu,
  MessagesSquare,
  Share2,
  ShieldAlert,
  X,
} from "lucide-react";
import { useEffect, useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";

import { GlobalSearch } from "@/components/global-search";
import { ThemeToggle } from "@/components/theme-toggle";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

/** 导航项定义。 */
interface NavItem {
  /** 路由路径。 */
  to: string;
  /** 菜单文案。 */
  label: string;
  /** 图标。 */
  icon: typeof LayoutDashboard;
  /** 是否精确匹配（首页需要）。 */
  end?: boolean;
}

/** 主菜单（顺序即展示顺序）。 */
const NAV_ITEMS: NavItem[] = [
  { to: "/", label: "首页", icon: LayoutDashboard, end: true },
  { to: "/vulnerabilities", label: "漏洞", icon: Bug },
  { to: "/qa", label: "问答", icon: MessagesSquare },
  { to: "/graph", label: "图谱", icon: Share2 },
  { to: "/quality", label: "质量", icon: Gauge },
];

/** 应用版本（与后端 ``FastAPI(version=...)`` 对齐）。 */
const APP_VERSION = "0.1.0";

/**
 * 应用布局。
 *
 * @returns 布局元素（含 ``<Outlet />`` 子路由出口）。
 */
export function Layout(): JSX.Element {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const location = useLocation();

  useEffect(() => {
    setSidebarOpen(false);
  }, [location.pathname]);

  return (
    <div className="flex min-h-screen flex-col bg-background">
      <header className="sticky top-0 z-40 w-full border-b border-border/70 bg-background/85 backdrop-blur supports-[backdrop-filter]:bg-background/70">
        <div className="mx-auto flex h-14 w-full max-w-7xl items-center gap-3 px-4 sm:px-6 lg:px-8">
          <Button
            variant="ghost"
            size="icon"
            className="md:hidden"
            aria-label="打开导航"
            onClick={() => setSidebarOpen(true)}
          >
            <Menu className="size-5" aria-hidden />
          </Button>

          <NavLink to="/" className="flex items-center gap-2 font-semibold">
            <span className="flex size-8 items-center justify-center rounded-lg bg-primary text-primary-foreground">
              <ShieldAlert className="size-5" aria-hidden />
            </span>
            <span className="hidden text-sm leading-tight sm:block">
              AI 安全知识情报系统
              <span className="block text-[11px] font-normal text-muted-foreground">
                Vulnerability Intelligence Console
              </span>
            </span>
          </NavLink>

          <nav className="hidden flex-1 items-center gap-1 md:flex" aria-label="主导航">
            {NAV_ITEMS.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                className={({ isActive }) =>
                  cn(
                    "rounded-md px-3 py-1.5 text-sm font-medium transition-colors",
                    isActive
                      ? "bg-primary/10 text-primary"
                      : "text-muted-foreground hover:bg-accent hover:text-foreground",
                  )
                }
              >
                {item.label}
              </NavLink>
            ))}
          </nav>

          <div className="ml-auto flex items-center gap-1 md:ml-0">
            <GlobalSearch />
            <Button
              variant="ghost"
              size="icon"
              className="hidden md:inline-flex"
              aria-label="展开侧边栏"
              title="展开侧边栏"
              onClick={() => setSidebarOpen(true)}
            >
              <Menu className="size-5" aria-hidden />
            </Button>
            <ThemeToggle />
          </div>
        </div>
      </header>

      <div className="mx-auto flex w-full max-w-7xl flex-1 gap-6 px-4 py-6 sm:px-6 lg:px-8">
        <AnimatePresence>
          {sidebarOpen ? (
            <motion.aside
              key="sidebar"
              initial={{ x: -24, opacity: 0 }}
              animate={{ x: 0, opacity: 1 }}
              exit={{ x: -24, opacity: 0 }}
              transition={{ duration: 0.22, ease: "easeOut" }}
              className="fixed inset-y-0 left-0 z-50 w-64 shrink-0 overflow-y-auto border-r border-border bg-card p-4 shadow-lg md:static md:z-auto md:h-auto md:max-h-[calc(100vh-8rem)] md:rounded-xl md:border md:shadow-card"
              aria-label="侧边导航"
            >
              <div className="mb-4 flex items-center justify-between">
                <span className="text-sm font-semibold">导航</span>
                <Button
                  variant="ghost"
                  size="icon"
                  aria-label="收起侧边栏"
                  onClick={() => setSidebarOpen(false)}
                >
                  <X className="size-4" aria-hidden />
                </Button>
              </div>
              <nav className="space-y-1">
                {NAV_ITEMS.map((item) => {
                  const Icon = item.icon;
                  return (
                    <NavLink
                      key={item.to}
                      to={item.to}
                      end={item.end}
                      className={({ isActive }) =>
                        cn(
                          "flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors",
                          isActive
                            ? "bg-primary/10 text-primary"
                            : "text-muted-foreground hover:bg-accent hover:text-foreground",
                        )
                      }
                    >
                      <Icon className="size-4" aria-hidden />
                      {item.label}
                    </NavLink>
                  );
                })}
              </nav>
              <div className="mt-6 rounded-lg bg-muted/60 p-3 text-xs leading-relaxed text-muted-foreground">
                <p className="mb-1 font-medium text-foreground">系统状态</p>
                <p>L1 采集 / L2 归一化：纯传统代码（禁止 LLM）</p>
                <p>L3 富化 / L4 问答：LangGraph 多 Agent</p>
                <p>L5 服务：FastAPI · L6 前端：React + TS</p>
              </div>
            </motion.aside>
          ) : null}
        </AnimatePresence>

        <main className="min-w-0 flex-1">
          <Outlet />
        </main>
      </div>

      <footer className="border-t border-border/70 py-6">
        <div className="mx-auto flex w-full max-w-7xl flex-col items-center gap-1 px-4 text-xs text-muted-foreground sm:flex-row sm:justify-between sm:px-6 lg:px-8">
          <p>智能体驱动的 AI 安全知识情报系统 · 赛题九 · v{APP_VERSION}</p>
          <p>数据来源：NVD · CISA KEV · EPSS · OSV · GHSA · arXiv · OpenAlex</p>
        </div>
      </footer>
    </div>
  );
}

/**
 * 深色模式 Provider（Day14 任务 3）。
 *
 * 取值：``light`` / ``dark`` / ``system``（默认 ``system``，跟随操作系统；
 * 用户显式选择后写入 ``localStorage``）。
 * 实现方式为在 ``<html>`` 上增删 ``dark`` 类（与 ``tailwind.config.js`` 的
 * ``darkMode: ["class"]`` 对应），不引入额外依赖。
 */

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

/** 主题模式。 */
export type Theme = "light" | "dark" | "system";

/** 主题上下文值。 */
export interface ThemeContextValue {
  /** 当前主题模式（含 ``system``）。 */
  theme: Theme;
  /** 实际生效的外观（``system`` 已解析为具体值）。 */
  resolvedTheme: "light" | "dark";
  /** 设置主题模式并持久化。 */
  setTheme: (theme: Theme) => void;
  /** 在 light / dark 之间切换（保留 ``system`` 之外的语义）。 */
  toggleTheme: () => void;
}

/** localStorage 键名。 */
const STORAGE_KEY = "aisec-intel-theme";

const ThemeContext = createContext<ThemeContextValue | undefined>(undefined);

/**
 * 解析系统偏好。
 *
 * @returns 系统当前的外观。
 */
function systemTheme(): "light" | "dark" {
  if (typeof window === "undefined" || !window.matchMedia) {
    return "light";
  }
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

/**
 * 读取已持久化的主题设置。
 *
 * @returns 合法主题值，缺省为 ``system``。
 */
function readStoredTheme(): Theme {
  if (typeof window === "undefined") {
    return "system";
  }
  const raw = window.localStorage.getItem(STORAGE_KEY);
  return raw === "light" || raw === "dark" || raw === "system" ? raw : "system";
}

/**
 * 深色模式 Provider。
 *
 * @param props.children 子树。
 * @returns 带主题上下文的 React 元素。
 */
export function ThemeProvider({ children }: { children: ReactNode }): JSX.Element {
  const [theme, setThemeState] = useState<Theme>(() => readStoredTheme());
  const [resolvedTheme, setResolvedTheme] = useState<"light" | "dark">(() =>
    readStoredTheme() === "system" ? systemTheme() : (readStoredTheme() as "light" | "dark"),
  );

  useEffect(() => {
    const applied: "light" | "dark" = theme === "system" ? systemTheme() : theme;
    setResolvedTheme(applied);
    const root = document.documentElement;
    root.classList.toggle("dark", applied === "dark");
    root.style.colorScheme = applied;
  }, [theme]);

  useEffect(() => {
    if (theme !== "system" || !window.matchMedia) {
      return undefined;
    }
    const query = window.matchMedia("(prefers-color-scheme: dark)");
    const handler = (event: MediaQueryListEvent): void => {
      const applied: "light" | "dark" = event.matches ? "dark" : "light";
      setResolvedTheme(applied);
      document.documentElement.classList.toggle("dark", applied === "dark");
      document.documentElement.style.colorScheme = applied;
    };
    query.addEventListener("change", handler);
    return () => query.removeEventListener("change", handler);
  }, [theme]);

  const setTheme = useCallback((next: Theme) => {
    setThemeState(next);
    window.localStorage.setItem(STORAGE_KEY, next);
  }, []);

  const toggleTheme = useCallback(() => {
    setTheme(resolvedTheme === "dark" ? "light" : "dark");
  }, [resolvedTheme, setTheme]);

  const value = useMemo<ThemeContextValue>(
    () => ({ theme, resolvedTheme, setTheme, toggleTheme }),
    [theme, resolvedTheme, setTheme, toggleTheme],
  );

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

/**
 * 读取主题上下文。
 *
 * @returns 主题上下文值。
 *
 * @throws Error 在 :class:`ThemeProvider` 之外调用时抛出。
 */
export function useTheme(): ThemeContextValue {
  const context = useContext(ThemeContext);
  if (!context) {
    throw new Error("useTheme 必须在 <ThemeProvider> 内部使用");
  }
  return context;
}

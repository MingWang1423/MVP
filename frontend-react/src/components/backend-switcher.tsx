/**
 * 本地 / 云端后端切换（Day19 任务 3）。
 *
 * 交互：
 * - 按钮直接显示**当前模式**（图标 + 文字：本地 ``HardDrive`` / 云端 ``Cloud``）；
 * - 点击切到另一侧：写入 ``localStorage``（键 ``aisec-intel-api-mode``）后**刷新页面**，
 *   让 TanStack Query 缓存与进行中的请求全部按新地址重来；
 * - 云端地址未配置（``VITE_API_URL_CLOUD`` 为空或仍是 ``http://<云服务器IP>:8000`` 占位符）时
 *   不切换，只弹一次提示，避免页面直接进错误态。
 */

import { Cloud, HardDrive } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { getApiMode, getBaseUrl, isCloudConfigured, setApiMode, type ApiMode } from "@/lib/api";

/** 模式 → 中文名。 */
const MODE_LABEL: Record<ApiMode, string> = { local: "本地", cloud: "云端" };

/** 云端地址为空时的提示文案。 */
const UNCONFIGURED_DETAIL = "请在 frontend-react/.env 填写 VITE_API_URL_CLOUD 后重启 dev server / 重新构建";

/**
 * 后端切换按钮。
 *
 * @returns 显示当前后端的按钮（点击切换到另一端）。
 */
export function BackendSwitcher(): JSX.Element {
  const [mode, setMode] = useState<ApiMode>(() => getApiMode());
  const cloudReady = isCloudConfigured();
  const next: ApiMode = mode === "local" ? "cloud" : "local";
  const Icon = mode === "local" ? HardDrive : Cloud;
  const currentBase = getBaseUrl(mode) || "同源（Vite 代理 / nginx 反代）";

  /**
   * 切换后端：持久化模式并刷新页面；云端未配置时仅提示不切换。
   *
   * @returns 无返回值。
   */
  const handleSwitch = (): void => {
    if (next === "cloud" && !cloudReady) {
      toast.warning("云端后端未配置", {
        id: "backend-switch-unconfigured",
        description: UNCONFIGURED_DETAIL,
      });
      return;
    }
    setApiMode(next);
    setMode(next);
    window.location.reload();
  };

  return (
    <Button
      variant="ghost"
      size="sm"
      className="gap-1.5 px-2"
      aria-label={`切换后端（当前：${MODE_LABEL[mode]}）`}
      title={`当前后端：${MODE_LABEL[mode]} · ${currentBase}｜点击切换到${MODE_LABEL[next]}`}
      onClick={handleSwitch}
    >
      <Icon className="size-4" aria-hidden />
      <span className="hidden text-xs font-medium sm:inline">{MODE_LABEL[mode]}</span>
    </Button>
  );
}

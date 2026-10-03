/// <reference types="vite/client" />

/**
 * 环境变量类型声明（Vite 只注入 `VITE_` 前缀变量）。
 *
 * 后端地址（本地 / 云端可切换，见 `src/lib/api.ts`）：
 * - `VITE_API_URL_LOCAL`：本地后端基地址，开发态默认 `http://localhost:8000`；
 * - `VITE_API_URL_CLOUD`：云端后端基地址（云服务器对外地址），未配置则不允许切换；
 * - `VITE_API_DEFAULT`：缺省模式，`local`（默认）/ `cloud`；
 * - `VITE_API_URL`：旧变量，作为本地基地址的兼容回退（容器构建参数仍在使用）。
 */
interface ImportMetaEnv {
  readonly VITE_API_URL?: string;
  readonly VITE_API_URL_LOCAL?: string;
  readonly VITE_API_URL_CLOUD?: string;
  readonly VITE_API_DEFAULT?: string;
  readonly VITE_APP_TITLE?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}

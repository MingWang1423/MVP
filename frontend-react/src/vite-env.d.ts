/// <reference types="vite/client" />

/**
 * 环境变量类型声明（Vite 只注入 `VITE_` 前缀变量）。
 *
 * - `VITE_API_URL`：后端 API 基地址。开发环境留空即走 Vite 代理（`/api` → :8000）。
 */
interface ImportMetaEnv {
  readonly VITE_API_URL?: string;
  readonly VITE_APP_TITLE?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}

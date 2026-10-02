import { fileURLToPath, URL } from "node:url";

import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

/**
 * Vite 配置（Day14 任务 1 / 任务 8）。
 *
 * - 别名 `@` → `src`（与 tsconfig.json 的 paths 对齐，shadcn 组件生成依赖该约定）；
 * - 开发代理 `/api` → `http://localhost:8000`（FastAPI 后端），
 *   前端代码只写相对路径 `/api/v1/...`，无需处理跨域与 CORS 预检。
 */
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
  server: {
    port: 5173,
    strictPort: false,
    proxy: {
      "/api": {
        target: "http://localhost:8000",
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: false,
    chunkSizeWarningLimit: 1200,
    rollupOptions: {
      output: {
        // 拆包：ECharts（约 1MB）与 React 运行时独立于业务代码，
        // 首屏只需下载业务 chunk，图表库可长期缓存。
        manualChunks: {
          echarts: ["echarts", "echarts-for-react"],
          react: ["react", "react-dom", "react-router-dom"],
        },
      },
    },
  },
});

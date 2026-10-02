/**
 * 应用入口（Day14 任务 1）。
 *
 * 挂载顺序：``StrictMode`` → :class:`AppProviders`（Query / Theme / Toast）→ ``BrowserRouter`` → :class:`App`。
 */

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";

import App from "@/App";
import { AppProviders } from "@/providers/app-providers";
import "@/index.css";

const container = document.getElementById("root");
if (!container) {
  throw new Error("未找到 #root 挂载点，请检查 index.html");
}

createRoot(container).render(
  <StrictMode>
    <AppProviders>
      <BrowserRouter>
        <App />
      </BrowserRouter>
    </AppProviders>
  </StrictMode>,
);

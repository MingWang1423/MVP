# ============================================================
# React 前端镜像（PROJECT_PLAN.md §5.9 P8 前端 / §5.10 P9 部署；Day17 任务 3.1）
#   构建：docker compose build frontend-react
#   运行：docker compose up -d frontend-react   → http://localhost:3000
#   多阶段：
#     阶段 1 node:18-alpine  → npm ci + npm run build（tsc --noEmit && vite build 产出 dist/）
#     阶段 2 nginx:alpine    → 托管 dist/，同源反代 /api → api:8000
#   说明：镜像内不装 Python，不依赖仓库其他目录（保持前后端解耦，§2.1）。
#   可用构建参数 RUNTIME_IMAGE 覆盖运行基础镜像（默认官方 nginx:1.27-alpine），
#   用于 Docker Hub 镜像源不可达的内网环境（换成内网自建的 nginx 基础镜像即可）。
# ============================================================

# 全局构建参数：运行阶段的基础镜像（见 compose 的 build.args.RUNTIME_IMAGE）
ARG RUNTIME_IMAGE=nginx:1.27-alpine

# ---------- 阶段 1：构建 ----------
FROM node:18-alpine AS build

WORKDIR /app

# 显式 root：alpine 默认即 root，个别替代基础镜像默认非 root，统一声明保证可写
USER root

# 淘宝镜像（同 frontend-react/.npmrc；国内构建 npm ci 直连 registry.npmjs.org 会 ECONNRESET）
# 附带调大空闲超时与重试：容器内 cdn.npmmirror.com 偶发长时间无响应会报 EIDLETIMEOUT
ENV npm_config_registry=https://registry.npmmirror.com \
    npm_config_audit=false \
    npm_config_fund=false \
    npm_config_fetch_timeout=900000 \
    npm_config_fetch_retries=5 \
    npm_config_fetch_retry_mintimeout=20000 \
    npm_config_fetch_retry_maxtimeout=180000

# ① 先装依赖：package*.json 不变时命中缓存
COPY package.json package-lock.json .npmrc ./
RUN npm ci

# ② 再拷源码与构建配置
COPY tsconfig.json vite.config.ts tailwind.config.js postcss.config.js index.html ./
COPY src ./src

# ③ 后端地址走构建期变量（Vite 的 import.meta.env 只在构建时注入）：
#    默认留空 → 前端请求相对路径 /api/v1/...，由 nginx 同源反代到 api:8000。
#    若确实需要浏览器直连后端（例如 API 已对外暴露且开了 CORS）：
#      docker build --build-arg VITE_API_URL=http://localhost:8000 -t aisec-frontend-react .
ARG VITE_API_URL=""
ENV VITE_API_URL=${VITE_API_URL}
RUN npm run build

# ---------- 阶段 2：Nginx 托管 ----------
FROM ${RUNTIME_IMAGE} AS runtime

ENV TZ=UTC

USER root

# SPA fallback + /api 反代 + gzip + 静态资源缓存（见同目录 nginx.conf 注释）
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
# 某些基础镜像自带 default site（监听 80），移除以免与 3000 端口配置混淆
RUN rm -f /etc/nginx/sites-enabled/default /etc/nginx/conf.d/default.conf.bak

EXPOSE 3000

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=10 \
    CMD wget -qO- http://127.0.0.1:3000/healthz >/dev/null 2>&1 || exit 1

CMD ["nginx", "-g", "daemon off;"]

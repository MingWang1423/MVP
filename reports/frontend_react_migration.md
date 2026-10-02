# 前端迁移说明：Streamlit → React + TypeScript（Day14）

> 交付物位置：`frontend-react/`（React 18 + TypeScript + Vite）。
> 原 `frontend/`（Streamlit）**保留不动**，作为降级兜底与对照，两者并存互不影响。

## 1. 技术栈与选型

| 能力 | 选型 | 说明 |
|---|---|---|
| 构建 / 开发服务器 | Vite 5 | 秒级冷启动，`/api` 代理后端 |
| UI 框架 | React 18.3 + TypeScript 5.6 | 全量 TS，`strict: true` |
| 样式 | TailwindCSS 3.4 + shadcn/ui | 语义色走 CSS 变量，风险色走设计 token |
| 路由 | React Router v6 | `/`、`/vulnerabilities`、`/vulnerabilities/:cveId`、`/qa`、`/graph`、`/quality` |
| 服务端状态 | TanStack Query v5 | `useStats` / `useVulns` / `useVuln` / `useQA` |
| HTTP | Axios | 统一错误处理 + Sonner Toast |
| 图表 | ECharts 5 + echarts-for-react | 饼图（风险分布）/ 柱图（来源分布）/ 折线图（30 天趋势） |
| 图形 | @xyflow/react（React Flow） | 已就绪，`/graph` 页 P8 使用 |
| 动效 | Framer Motion | KPI 数字滚动 + 卡片入场 |
| 图标 / 提示 | lucide-react / Sonner | — |

## 2. 本地启动

```powershell
# ① 后端（5 服务需 healthy）
cd d:\MVP; docker compose ps
cd d:\MVP; docker compose up -d --build api   # 仅当 src/ 有改动时需重建

# ② 前端
cd d:\MVP\frontend-react
npm install                                    # 国内网络建议加镜像（见下）
npm run dev                                    # http://localhost:5173
```

**npm 镜像**：本机直连 `registry.npmjs.org` 会 `ECONNRESET`，实测可用淘宝镜像：

```powershell
cd d:\MVP\frontend-react
npm install --registry=https://registry.npmmirror.com --no-audit --no-fund
npx --yes --registry=https://registry.npmmirror.com <cli>   # npx 同理
```

开发态前端只请求相对路径 `/api/v1/...`，由 `vite.config.ts` 代理到 `http://localhost:8000`；
部署态可设 `VITE_API_URL`（见 `frontend-react/.env.example`）。

## 3. 设计 token

`frontend-react/tailwind.config.js`：

| token | 值 | 用途 |
|---|---|---|
| `critical` | `#d62728` | 严重（CVSS CRITICAL） |
| `high` | `#ff7f0e` | 高危（HIGH） |
| `medium` | `#ffbb33` | 中危（MEDIUM） |
| `low` | `#2ca02c` | 低危（LOW） |
| `primary` | `hsl(var(--primary))` = `#1f77b4` | 主色（导航、按钮、折线、链接） |
| 字体 | Inter（index.html 引 Google Fonts，失败回退系统字体栈） | 全站 |

> `#1f77b4 ≡ hsl(205 71% 41%)`，以 CSS 变量承载以便同时满足 shadcn 的 `bg-primary`
> 原子类与深色模式切换（`dark` 类策略）。

## 4. 后端配套改动（Day14 任务 6）

新增 `GET /api/v1/stats`，一次返回首页所需的全部聚合，避免首屏多次请求。

| 字段 | 口径 |
|---|---|
| `total_vulns` | `unified_vuln` 总行数 |
| `critical_count` | 事实层 `severity = CRITICAL` |
| `source_count` | `source` 表中**已启用**的采集源数量 |
| `today_new` | **近 24 小时**新增（`published_at` 优先，回退 `normalized_at`） |
| `risk_distribution` | 事实层 `severity` 分布（小写键；恒含 critical/high/medium/low，未定级归 `unknown`） |
| `source_distribution` | `sources` JSON 展开后的各源贡献条数（按条数倒序） |
| `timeline` | 近 N 天（默认 30）按 UTC 日期分桶，**缺失日期补 0** |
| `top_high_risk` | 最近 CRITICAL/HIGH（默认 10 条，左连接富化风险分） |
| `generated_at` | 统计生成时间（UTC，ISO8601 `Z`） |

**口径说明（重要）**：`today_new` 刻意不用「UTC 当日零点」——全量重跑会把
`normalized_at` 刷成当天，导致「今日新增 ≈ 总量」的失真数字（实测 1410/1454）；
改为滚动 24 小时窗口后为 25 条，对运维更有信息量。

涉及的代码：
`src/aisec_intel/storage/repositories/stats_repo.py`（新增只读聚合仓储 + 3 个纯函数）、
`src/aisec_intel/api/schemas/stats.py`、`src/aisec_intel/api/routers/stats.py`、
`api/deps.py`（`get_stats_repo` / `get_source_repo`）、`api/main.py`（挂载路由）、
`source_repo.count()`、`VulnSummary.from_unified()`（与漏洞列表共用条目装配）。

测试：`tests/unit/test_stats_aggregation.py`（纯函数）、
`tests/integration/test_stats_endpoint.py`（端点全字段口径，SQLite 内存库 + 依赖覆盖）。

## 5. 本轮完成度

- ✅ 工程化骨架、设计 token、布局骨架（顶部导航 / 全局搜索 / 深色模式 / 默认折叠侧边栏 / footer）
- ✅ 路由配置（6 条路由 + 404 兜底），首页仪表盘完整实现
- ✅ API 客户端 + TanStack Query Hooks + 统一错误 Toast
- ✅ 首页：4 KPI（数字滚动 + hover 阴影）、风险分布饼图、来源分布柱图、30 天趋势折线、高危 Top10 表格、Skeleton 加载态
- ⏳ 占位页：`/vulnerabilities`、`/vulnerabilities/:cveId`、`/qa`、`/graph`、`/quality`（P8 逐页替换）

## 6. 已知限制与后续

1. **shadcn CLI 未能联网执行**：`npx shadcn@latest init/add` 需访问 `ui.shadcn.com`，
   本机网络超时/`ECONNRESET`；因此 `components.json`、`src/index.css` 的 CSS 变量与
   `src/components/ui/*`（button/card/table/skeleton/badge/input/dropdown-menu/sonner）
   **按官方源码等价手写落地**，API 与官方组件一致；网络恢复后可直接用 CLI 追加组件。
2. **图表关闭入场动画**（`animation: false`）：首屏更快，且保证无头截图 / 视觉回归可复现
   （虚拟时间下 ECharts 入场动画会停在 0 帧）；KPI 卡片同理去掉了错峰延迟。
3. **本机 headless 截图为 Edge（`msedge --headless=new`）**：非 Playwright，页面高度按
   `--window-size` 固定，超长页面需加大高度参数。
4. 前端未纳入 `docker-compose.yml`（本轮为开发态交付）；如需容器化，建议 P9 增加
   `frontend-react` 服务（`vite build` + nginx 静态托管 + `/api` 反代）。

## 7. 验证记录（2026-10-02）

| 项 | 结果 |
|---|---|
| `docker compose ps` | 5 服务全部 healthy |
| `GET /healthz` | `{"status":"ok"}` |
| `GET /api/v1/stats` | 真实数据：总数 1454 / 高危 63 / 源 7 / 近 24h 25 |
| `python -m pytest` | **711 passed, 19 deselected**（23.2s，离线可复现） |
| `python -m ruff check src tests` | All checks passed |
| `python -m mypy`（本轮新增/改动文件） | Success: no issues found in 8 source files |
| `npx tsc --noEmit` | 通过（strict） |
| `npm run build` | 通过（见构建产物 `frontend-react/dist/`） |
| 首页截图 | `reports/frontend_dashboard.png` |
| 路由切换截图 | `reports/frontend_route_check.png`（`/vulnerabilities/CVE-2026-92948`） |

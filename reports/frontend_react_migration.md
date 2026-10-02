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
| 页面截图（可复现） | `scripts/capture-screenshot.mjs` | 自研 CDP 脚本：真实时间等「数据就绪 + 动画播完」再抓整页 |

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

**页面截图（可复现，需 dev server 运行中）**：

```powershell
cd d:\MVP\frontend-react
# 仪表盘（等待数据 + 图表/卡片动画播完，抓整页）
node scripts/capture-screenshot.mjs --url http://localhost:5173/ `
  --out ../reports/frontend_dashboard.png --settle-ms 1800 --width 1600
# 占位页（无图表，--mode page 跳过就绪轮询）
node scripts/capture-screenshot.mjs --url http://localhost:5173/vulnerabilities/CVE-2026-92948 `
  --mode page --out ../reports/frontend_route_check.png --width 1440 --height 900
```

参数：`--url` 页面地址、`--out` 输出路径、`--width/--height` 视口、`--settle-ms` 动画收尾等待、
`--timeout-ms` 就绪轮询超时、`--port` 调试端口、`--mode dashboard|page`。
脚本会打印就绪状态（如 `{"canvases":3,"skeleton":false,"opaque":true} ready=true`）。

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
2. **动画一律保留**（ECharts 入场动画 + KPI 卡片错峰淡入 + 数字滚动），**不为了截图牺牲真实体验**。
   截图改由工具侧解决：`frontend-react/scripts/capture-screenshot.mjs` 通过 CDP 在**真实时间**里
   轮询「3 个 canvas 已挂载 + Skeleton 消失（无 `[aria-busy]`）+ 4 张 KPI 卡片 `opacity=1`」，
   再额外等 `--settle-ms`（默认 1500ms）收尾后抓帧，**无需关闭任何动画**。
3. **`--screenshot-delay` 不是 Chromium/Edge 的参数**（实测被静默忽略）。直接
   `msedge --headless --screenshot` 只等到 `load` 事件，而本应用是 CSR（数据要等
   `/api/v1/stats` 返回），所以会抓到 Skeleton 加载态——本轮已实测复现，故弃用该路线；
   `--virtual-time-budget` 则会把 ECharts / Framer Motion 的 rAF 动画冻在 0 帧（图表空白）。
   **结论：截图统一走 CDP 脚本。**
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
| 首页截图 | `reports/frontend_dashboard.png`（`scripts/capture-screenshot.mjs`，就绪状态 `{"canvases":3,"skeleton":false,"opaque":true}`） |
| 路由切换截图 | `reports/frontend_route_check.png`（`/vulnerabilities/CVE-2026-92948`，`--mode page`） |

---

## 8. Day16 追加：列表 / 详情 / 问答三页 + 图谱与筛选接口

### 8.1 交付范围

| 任务 | 产出 | 状态 |
|---|---|---|
| 1 漏洞列表页 | `src/pages/vuln-list.tsx`、`src/components/vuln/{filter-bar,vuln-table}.tsx`、`src/lib/vuln-filters.ts` | ✅ 严重度/来源多选、7d/30d/90d/全部、KEV 开关、有 PoC 开关、关键词搜索、重置；表格 8 列 + 列头排序 + 分页 20/50/100 + Skeleton；**筛选/排序/页码全部写 URL** |
| 2 漏洞详情页 | `src/pages/vuln-detail.tsx`、`src/components/detail/{vuln-tabs,detail-sidebar,graph-view}.tsx`、`src/lib/cvss.ts` | ✅ 7 Tab（基础信息 / 资产 / PoC / 论文 / 攻击链 / 修复建议 / 图谱子图）+ 侧栏（风险环 / 置信度 / 时间线 / 来源）+ 导出 JSON / 复制 CVE ID / 在 NVD 查看；整页 Skeleton + 图谱 Tab 局部 Skeleton |
| 3 问答页 | `src/pages/qa.tsx`、`src/components/qa/qa-parts.tsx`、`src/components/markdown.tsx` | ✅ 气泡对话（用户右 / AI 左）、Enter 发送 / Shift+Enter 换行、自动滚底、Markdown 主答案、引用卡片、2 跳推理链、4 个快捷问题、`session_id` 存 localStorage、新对话、AI 思考动画 |
| 4 后端补 API | `GET /api/v1/graph/{cve_id}`；`GET /api/v1/vulnerabilities` 增强筛选；`VulnSummary.poc_count` | ✅ 见 §8.2；图谱端点 Neo4j 优先、降级 PG 推导（`backend` 字段明示来源） |
| 5 验证 | pytest / ruff / tsc / build / 三张截图 | ✅ 见 §8.4 |

新增依赖（镜像安装）：`@tanstack/react-table@8`、`@tanstack/react-virtual@3`、`react-markdown`、`remark-gfm`、
`@radix-ui/react-{tabs,switch,select,separator}`。`frontend-react/.npmrc` 固定淘宝镜像
（本机直连 registry.npmjs.org 会 ECONNRESET；`@tanstack/react-table` 默认装到 v9 alpha，已**显式钉 v8**）。

### 8.2 后端接口（只增不改，备案见 `reports/INTERFACE_FREEZE.md` §6 末行）

| 变更 | 文件 | 说明 |
|---|---|---|
| 新增 `GET /api/v1/graph/{cve_id}` | `api/routers/graph.py`、`api/schemas/graph.py`、`services/graph_service.py`、`storage/repositories/graph_repo.py::subgraph()` | 1 跳子图 → React Flow `{nodes, edges}`；`map_subgraph_rows()` / `map_extraction()` / `facts_only_subgraph()` 均为纯函数；`limit` 越界 422，CVE 不存在 404 |
| 列表筛选增强 | `api/routers/vulns.py`、`storage/repositories/vuln_repo.py::list_filtered()` | `severity`/`source` 多选（并集）、`since`/`until`、`kev` 三态、`has_poc`（`EXISTS(json_array_length(exploits)>0)` 下推 SQL，跨 PG/SQLite 一致）、`q`（编号/标题/描述）；`normalize_severity_params()` 大小写不敏感 + 非法值 422 |
| `poc_count` 列 | `api/schemas/vuln.py::VulnSummary`、`vuln_repo.poc_counts()` | 列表页 PoC 数列，批量查询避免 N+1 |
| 时间轴单一定义 | `storage/models/vuln.py::timeline_column()` | `published_at` 回退 `normalized_at`；列表筛选与 `/stats` 趋势统计共用 |

新增测试：`tests/unit/test_graph_subgraph.py`（12 例，纯函数）、
`tests/integration/test_vuln_filters.py`（19 例，多选/区间/KEV/PoC/关键词/排序/分页）、
`tests/integration/test_graph_endpoint.py`（6 例，降级路径 + 假 Neo4j 客户端 + 404 + limit 校验）。

### 8.3 前端实现要点

1. **数组查询参数**：Axios 默认把数组序列化成 `severity[]=HIGH`，FastAPI `Query(list[str])` 只认重复键 →
   `lib/api.ts::serializeParams()` 自定义序列化（并丢弃 `undefined`/空串），否则多选筛选会 422 或静默失效；
2. **虚拟滚动**：表格固定行高 56 px + `useVirtualizer`，表头与行共用同一份 `GRID_TEMPLATE`；
   排序为**当前页内排序**（服务端只保证时间轴倒序），页面底部已如实标注；
3. **React Flow 布局**：不引布局引擎，`layoutRadial()` 以漏洞节点为圆心放射排布（同一 CVE 每次位置一致，便于截图对比）；
   6 类节点（漏洞/组件/资产/技术/论文/补丁）按设计色着色，图例同步展示；
4. **CVSS 可视化**：`parseVectorMetrics()` 只拆解 `CVSS:3.1/AV:N/...` 各度量并给出中文释义，
   **分数一律取源数据**（前端不重算），色阶仅用于展示；
5. **Markdown 渲染**：未引 `@tailwindcss/typography`，改用 react-markdown 的 `components` 逐标签套 Tailwind 类（无自定义 CSS）。

### 8.4 验收证据

| 检查项 | 结果 |
|---|---|
| `python -m pytest` | **749 passed, 19 deselected** |
| `python -m ruff check src tests` | All checks passed |
| `npx tsc --noEmit` | 通过（strict） |
| `npm run build` | 通过，`dist/index-*.js` 905 kB（gzip 288 kB）/ `echarts-*.js` 1054 kB（gzip 350 kB） |
| 列表页截图 | `reports/frontend_list.png` |
| 详情页截图 | `reports/frontend_detail.png` |
| 问答页截图 | `reports/frontend_qa.png` |

截图命令（CDP 直连脚本，`--screenshot-delay` 不是 Chromium 标志、`--virtual-time-budget` 会冻结 rAF，均不可用）：

```powershell
cd frontend-react
node scripts/capture-screenshot.mjs --url http://localhost:5173/vulnerabilities --out ../reports/frontend_list.png --mode page --wait-selector 'main div.grid' --width 1600 --height 1100
node scripts/capture-screenshot.mjs --url http://localhost:5173/vulnerabilities/CVE-2026-92948 --out ../reports/frontend_detail.png --mode page --wait-selector '[role=tablist]' --width 1600 --height 1000
node scripts/capture-screenshot.mjs --url http://localhost:5173/qa --out ../reports/frontend_qa.png --mode page --wait-selector 'textarea[aria-label="问题输入框"]' --ask '最近 30 天高危漏洞' --answer-wait-ms 30000 --width 1600 --height 1200
```

### 8.5 已知缺口（页面已明示，不在本阶段修）

1. **修复建议（富化维度⑦）未落库**：`Remediation` 仅存在于 `EnrichmentOutput` 内存对象，
   `enriched_vuln` 无对应列 → 该 Tab 用事实层 patch / 公告引用 + 受影响版本区间呈现，页脚标注缺口；
2. **论文标题 / 作者未由 API 暴露**：`PaperVulnLink` 只含 `paper_id` / 关系 / 置信度 → 卡片给出 arXiv 链接；
3. **`/graph`、`/quality` 仍为占位页**（P8 剩余）；
4. **PoC 卡片无 star 数**：`ExploitRecord` 无 `stars` 字段，星标写在 `evidence_refs`（`stars=N`），按原文展示；
5. **`today_new` 为近 24 h 滚动窗口**（非自然日），首页 KPI 旁已标注口径。


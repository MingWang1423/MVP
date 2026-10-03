# React 前端「本地 / 云端后端切换」（Day19）

> 目标：前端可在**本地后端**与**云端后端**之间一键切换，**保留本地为默认**；切换后所有请求改走新地址。

## 1. 改动文件

| 文件 | 改动 |
|---|---|
| `frontend-react/.env` | 新增 `VITE_API_URL_LOCAL=http://localhost:8000`、`VITE_API_URL_CLOUD=http://<云服务器IP>:8000`（占位符）、`VITE_API_DEFAULT=local`（该文件被 `.gitignore` 排除，不入库） |
| `frontend-react/.env.example` | 同步三变量 + 说明「占位符 = 未配置 = 不允许切换」、旧变量 `VITE_API_URL` 仍是本地地址的兼容回退 |
| `frontend-react/src/vite-env.d.ts` | 三个新环境变量的类型声明 |
| `frontend-react/src/lib/api.ts` | 新增 `ApiMode` / `API_MODE_STORAGE_KEY` / `normalizeBaseUrl` / `isCloudConfigured` / `getApiMode` / `setApiMode` / `getBaseUrl`；Axios **请求拦截器**每次按当前模式动态覆盖 `baseURL` |
| `frontend-react/src/components/backend-switcher.tsx` | 新增组件：lucide `HardDrive` / `Cloud` 图标 + 当前模式文字（本地 / 云端），点击切换 → 写 localStorage → `location.reload()` |
| `frontend-react/src/components/layout.tsx` | 在 `ThemeToggle` 旁挂载 `<BackendSwitcher />`（同时修掉了工作区里一处残留的半截粘贴代码，该粘贴导致页面无法编译） |
| `frontend-react/scripts/verify-backend-switch.mjs` | 新增可复现验证脚本（CDP，零依赖）：录请求地址 → 点按钮 → 录新地址 → 断言 |
| `src/aisec_intel/api/main.py` | 新增 `CORS_ALLOW_ORIGINS`（`localhost:5173` / `127.0.0.1:5173` / `localhost:3000` / `127.0.0.1:3000`）+ `CORSMiddleware`（`expose_headers=["X-Trace-Id"]`） |
| `tests/integration/test_cors.py` | 新增 CORS 契约测试：放行名单、放行源预检 200 回显、非放行源预检 400 且无 `allow-origin`、实际响应暴露 `X-Trace-Id` |

## 2. 行为口径

- **默认模式**：`VITE_API_DEFAULT=local` → 默认连 `VITE_API_URL_LOCAL`（开发态 `http://localhost:8000`）。
- **云端未配置**：`VITE_API_URL_CLOUD` 为空或仍是 `http://<云服务器IP>:8000` 这类占位符时，
  `isCloudConfigured()` 为 `false` → 按钮点击**不切换**，只弹一次「云端后端未配置」提示
  （避免把请求打到非法地址导致整页错误态）。
- **切换效果**：模式写入 `localStorage['aisec-intel-api-mode']` 并刷新页面；
  Axios 请求拦截器在每次请求时按当前模式覆盖 `baseURL`，因此切换后（含 TanStack Query 重放）
  所有 `/api/v1/*` 请求都走新地址，无需重建实例。
- **本地地址回退链**：`VITE_API_URL_LOCAL` → `VITE_API_URL`（旧变量）→ `""`（同源相对路径）。
  容器部署不注入前两者 → 仍走 `nginx` 同源反代，**不改变原有部署行为**。
- **跨域**：切到绝对地址后浏览器直连后端属跨域，故后端显式放行 5173（Vite dev server）
  与 3000（容器 nginx）的 `localhost` / `127.0.0.1` 两种写法。

## 3. 验证（实测输出）

### 3.1 构建

```powershell
cd d:\MVP\frontend-react
npm run build          # tsc --noEmit && vite build，exit=0
```

### 3.2 本地默认 + 切换后走新地址（云端用 `http://127.0.0.1:8000` 临时占位联调）

```powershell
# 临时 .env.local（已被 .gitignore 排除，验证后已删除）
Set-Content frontend-react\.env.local 'VITE_API_URL_CLOUD=http://127.0.0.1:8000'
python -m uvicorn aisec_intel.api.main:app --port 8000     # API
cd frontend-react; npm run dev                              # dev server 5173
node scripts/verify-backend-switch.mjs `
  --url http://localhost:5173/ --local-origin http://localhost:8000 --cloud-origin http://127.0.0.1:8000
```

实测输出：

```
[1] 切换前模式=local（localStorage=null）
    请求（1 条）：http://localhost:8000/api/v1/stats?timeline_days=30&high_risk_limit=10
[2] 点击切换按钮 → localStorage['aisec-intel-api-mode']=cloud
    请求（1 条）：http://127.0.0.1:8000/api/v1/stats?timeline_days=30&high_risk_limit=10
PASS: 默认连本地，切换后请求改走云端地址          # exit=0
```

### 3.3 云端未配置分支

```powershell
Remove-Item frontend-react\.env.local        # 回到 .env 里的占位符
node scripts/verify-backend-switch.mjs --url http://localhost:5173/ --local-origin http://localhost:8000
```

实测输出：

```
[1] 切换前模式=local（localStorage=null）
[2] 云端未配置时点击 → localStorage=null，提示已出现=true
PASS: 默认连本地，云端未配置时拒绝切换并给出提示   # exit=0
```

### 3.4 后端（CORS）

```powershell
cd d:\MVP
python -m ruff check src/aisec_intel/api/main.py tests/integration/test_cors.py   # exit=0
python -m pytest tests/integration/test_cors.py tests/integration/test_ops_endpoints.py -q   # 10 passed
```

## 4. 使用说明（换真实云端地址）

1. 编辑 `frontend-react/.env`，把 `VITE_API_URL_CLOUD` 换成真实地址（如 `http://1.2.3.4:8000` 或
   `https://intel.example.com`）；
2. **重启** `npm run dev`（Vite 只在启动/构建时读取环境变量；容器部署需重新 `npm run build`）；
3. 若云端后端不是本仓库这套 CORS 白名单，需在 `CORS_ALLOW_ORIGINS` 里追加前端访问源；
4. 页面右上角按钮显示当前后端（本地 / 云端），点击即切换并刷新；F12 Network 可见请求地址变化。

# 项目规范
- 采集层、归一化层：纯传统代码，禁止 LLM
- 富化、问答层：LangGraph 多 Agent
- 所有数据模型用 Pydantic
- Python 必须有 type hints 和 docstring
- 采集器继承 BaseConnector
- 归一化函数必须是纯函数
- 禁止修改 .clineignore 排除的目录

## 环境约束
- 所有 Python 命令必须在仓库内 .venv 执行（`d:\MVP\.venv`）
- 禁止使用 `d:\venvs\` 下的任何虚拟环境
- 跑测试统一用 `python -m pytest`，禁止直接敲 `pytest`
- 装依赖统一用清华镜像：`python -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple ...`
## 计划书引用规则
- PROJECT_PLAN.md 只按章节引用，禁止整文件读取
- 每阶段只读对应 §5.X（文件清单）和 §6.X（验收标准）
- 需要架构时读 §1，需要接口时读 §10
## 环境约束
- 所有 Python 命令必须在仓库内 .venv 执行（d:\MVP\.venv）
- 禁止使用 d:\venvs\ 下的任何虚拟环境
- 跑测试统一用 `python -m pytest`，禁止直接敲 `pytest`
- 装依赖统一用 `python -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple ...`
## 提交规范
- 每天任务结束时必须 git commit
- commit message 格式：Day N: <模块>（<关键产出>）
- 禁止跨天堆积未提交改动
## 包导入规范
- 项目采用 src 布局，aisec_intel 在 src/ 下
- 已通过 `pip install -e .` 可编辑安装，任何目录都能 import
- 新增依赖后如 import 失败，先检查是否在仓库内 .venv 且已激活
- 不要用 sys.path.insert 硬编码路径
## 计划书读取硬约束
- 禁止整文件读取 PROJECT_PLAN.md
- 每个任务只读对应章节：
  - 采集任务：§5.4 + §10
  - 富化任务：§5.6 + §10
  - 问答任务：§5.7 + §10
  - 工程任务：§2 + §11
- 需要架构时只读 §1
- 需要接口时只读 §10
## 规则文件维护
- `.clinerules/plan-reference.md` 允许在 Day 任务中自动刷新行号；其他 `.clinerules/` 文件禁改
## 测试范围硬约束
必须写测试：
- 核心契约（Pydantic 模型校验）
- 纯函数算法（CVSS 计算、去重、合并）
- Agent 编排逻辑（mock LLM）
- 采集器解析逻辑（mock 响应）

不写测试：
- 简单 getter/setter/property
- 纯配置类（Settings 字段）
- 一次性脚本（scripts/ 下的一次性工具）
- UI 渲染（Streamlit 页面）
- 日志格式、异常消息文案
- 内部私有方法（除非算法复杂）

## Docker 镜像源故障应对（Day17 任务 6）
### 症状
- `docker pull` 官方 `node` / `nginx` / `python` 镜像时报 **TLS 证书异常 / EOF / 403**（本机 Docker Hub
  镜像源 daocloud 曾出现），表现为 `docker compose build` 在拉基础镜像阶段失败。
- 注意区分：**代码问题**（构建日志里出现 `npm error` / `ModuleNotFoundError`）与**源问题**
  （日志里只有 `failed to resolve source metadata` / `x509: certificate`）。只有后者才走下面的处置路径。

### 处置路径（按顺序尝试，均需在仓库内记录到 reports/ 或本文件）
1. **换基础镜像仓库**：`node:20-bookworm-slim` → `mcr.microsoft.com` / 内网私有仓库同款镜像；
   先 `docker pull <镜像>` 验证可拉取，再改 `Dockerfile` / compose 构建参数。
2. **`apt-get install` 补齐运行时**：用 `mcr.microsoft.com` 的 `debian` 基础镜像 +
   `apt-get install -y nodejs npm nginx`（或对应运行时），`apt-get` 走的是发行版源，通常不受
    Docker Hub 影响。装完先 `docker run --rm <容器> node -v` 验证。
3. **`docker commit` 固化为本地基础镜像**：
   ```powershell
   docker run -it --name tmp-base mcr.microsoft.com/debian:12 bash
   # 容器内：apt-get update && apt-get install -y nodejs npm nginx
   docker commit tmp-base node-local:bookworm      # 生成本地镜像
   docker rm tmp-base
   ```
4. **构建参数指向本地镜像**（不改 Dockerfile 里的默认值，保证他人仍可用官方镜像）：
   ```powershell
   $env:REACT_RUNTIME_IMAGE='nginx-local:bookworm'; docker compose build frontend-react
   ```
   `frontend-react/Dockerfile` 已预留 `ARG RUNTIME_IMAGE=nginx:1.27-alpine`。
5. **离线兜底**：现场断网时用提前导出的镜像包恢复：
   ```powershell
   docker save -o aisec-images.tar aisec-intel-api:local aisec-intel-frontend:local `
       aisec-intel-frontend-react:local postgres:16 neo4j:5 chromadb/chroma:0.5.5
   docker load -i aisec-images.tar      # 现场机器执行
   docker compose up -d --no-build      # 不再重新构建，直接起容器
   ```
   比赛前一天必须验证一次 `docker load` → `up -d` 全流程（写入 `reports/offline_drill_2.md`）。

### 提交与记录要求
- 上述任何“绕行”都必须**同时保留官方默认值**（用构建参数 / 环境变量覆盖），不得把本机镜像名硬编码进
  `Dockerfile`；
- 处置完成后把实际命令与镜像名追加到 `reports/offline_drill_*.md` 或本文档的对应条目，
  禁止只口头说明（复现时无处可查）。
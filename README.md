# 智能体驱动的 AI 安全知识情报系统

> 高校 ICT 产教融合创新大赛 · 赛题九（奇安信）
> 多源安全情报采集 → 归一化 → **LangGraph 多 Agent 富化** → **GraphRAG 跨文档问答**

[![Python](https://img.shields.io/badge/python-3.11-blue)](https://www.python.org/)
[![Pydantic](https://img.shields.io/badge/pydantic-v2-e92063)](https://docs.pydantic.dev/)
[![LangGraph](https://img.shields.io/badge/orchestration-langgraph-1c3c3c)](https://langchain-ai.github.io/langgraph/)

---

## 1. 项目简介

围绕「AI 安全」主题构建一条可复现的情报流水线：

| 层 | 名称 | 技术约束 | 职责 |
|---|---|---|---|
| L1 | 采集层 | **纯传统代码，禁止 LLM** | 多源采集（NVD / OSV / GHSA / KEV / EPSS / arXiv / Exploit-DB / ATT&CK / 厂商公告 / 安全博客） |
| L2 | 归一化层 | **纯函数，禁止 LLM** | CVE / CVSS / CPE / 时间 / 文本统一，去重与幂等 |
| L3 | 富化层 | **LangGraph 多 Agent（7 Agent + 回流条件边）** | 五维度富化：受影响资产、关联论文、PoC/EXP、风险分、攻击链 |
| L4 | 问答层 | **LangGraph 多 Agent** | SQL / Cypher / Vector 三路检索 → 多跳推理 → **强制引用回溯** |
| L5 | 服务层 | FastAPI | REST + SSE 流式问答 |
| L6 | 前端 | Streamlit | 情报看板 / CVE 详情 / 知识图谱 / 智能问答 / 采集运维 |

完整架构、排期、验收标准与风险应对见 **[`PROJECT_PLAN.md`](./PROJECT_PLAN.md)**（项目唯一基线）。

---

## 2. 快速开始

### 2.1 环境准备（Python 3.11）

```powershell
# 方式 A：仓库内本地虚拟环境（推荐给开发者；.venv/ 已被 .gitignore 排除）
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1

# 方式 B：将虚拟环境放在仓库外（Cline 协作场景，因 .venv/ 在 .clineignore 中被排除）
#   本项目 Day1 已建立：d:\venvs\aisec-intel-311
```

### 2.2 安装依赖

```powershell
# Day1 最小子集（跑测试所需）
pip install "pydantic>=2.9" "pydantic-settings>=2.5" "pytest>=8.3" pytest-asyncio pytest-cov ruff

# 完整依赖（含采集 / 存储 / Agent / 前端；体积较大，建议在 P2/P5 阶段按需安装）
pip install -e .
```

### 2.3 配置环境变量

```powershell
copy .env.example .env
# 至少填写：LLM_API_KEY（DeepSeek）；建议填写 NVD_API_KEY（无 Key 时 NVD 限流 5 req/30s）
```

密钥安全约定：所有密钥字段为 `SecretStr`，日志中一律走 `Settings.masked()`，**禁止输出明文**。

### 2.4 运行测试

```powershell
pytest
```

测试无需任何外部服务（数据库 / 网络 / LLM）即可通过；需要外部依赖的用例会以 `importorskip` 或
`@pytest.mark.integration` 标记跳过。

### 2.5 启动服务（P7 / P8 完成后可用）

```powershell
docker compose up -d                                  # PostgreSQL + Neo4j + ChromaDB
uvicorn aisec_intel.api.main:app --reload --port 8000  # 后端 API
streamlit run frontend/app.py --server.port 8501        # 前端
```

---

## 3. 目录结构

```text
src/aisec_intel/
├─ models/       # ★接口层：Day1 冻结契约（RawItem / UnifiedVuln / EnrichedVuln）
├─ connectors/   # L1 采集（继承 BaseConnector，禁止 LLM）
├─ normalize/    # L2 归一化（纯函数，禁止 LLM）
├─ storage/      # PostgreSQL / Neo4j / ChromaDB 适配
├─ enrich/       # L3 富化（LangGraph 7 Agent）
├─ qa/           # L4 问答（LangGraph: Supervisor → Router → SQL/Cypher/Vector → Reasoner → Citation）
├─ llm/          # LLM Provider 抽象（唯一模型出口）
├─ api/          # L5 FastAPI
├─ services/     # 任务级业务编排
├─ utils/        # 限流 / HTTP / 哈希 / 文本工具
├─ config.py     # pydantic-settings 全局配置
└─ logging_config.py  # 结构化日志 + trace_id
frontend/        # L6 Streamlit
tests/           # test_models.py（契约）/ test_config.py（基础设施）
reports/         # 评测报告、接口冻结记录、答辩材料
```

**文档落点约定**：`docs/`、`data/`、`logs/`、`*.csv`、`*.pdf` 均被 `.clineignore` 排除，
因此所有需要协作编辑与提交的文档只落在**仓库根目录**与 **`reports/`**。

---

## 4. 当前进度（Day1 已完成）

- [x] 目录骨架 + Python 3.11 环境
- [x] `pyproject.toml` / `.env.example` / `.gitignore`
- [x] **三个冻结接口**：`RawItem`、`UnifiedVuln`、`EnrichedVuln`（`extra="forbid"` + UTC 时间语义）
- [x] `config.py`（含降级开关与密钥脱敏）、`logging_config.py`（trace_id 贯穿）
- [x] `llm/provider.py`（`chat` / `structured` 两方法，DeepSeek 完整支持 + Ollama 兜底）
- [x] 单元测试（契约 + 配置 + Provider + 日志）

后续阶段（P1–P9）见 `PROJECT_PLAN.md` §4 / §5。

---

## 5. 数据来源与许可证说明（合规声明）

| 数据源 | 用途 | 许可 / 合规处理 |
|---|---|---|
| NVD / CVE List v5 | 漏洞主数据 | 美国政府公开数据（Public Domain） |
| OSV.dev / GitHub Advisory | 生态包漏洞与修复版本 | 公开数据，仅存元数据 |
| CISA KEV / FIRST EPSS | 被利用情况与利用概率 | 公开数据 |
| Exploit-DB | PoC 线索 | **只存元数据与原始链接，不转载利用代码**（GPL 内容） |
| arXiv / OpenAlex | AI 安全论文关联 | **只存标题、摘要与元数据，不存全文 PDF** |
| 厂商公告 / 安全博客 | 事件背景 | 只存标题、链接与摘要 |

本项目所有结论均可通过 `trace_id` 回溯到上述来源原文链接。

---

## 6. 开发协作

- 规范：`.clinerules/coding-standards.md`（分层约束、Pydantic、type hints、BaseConnector）
- 计划书引用规则：`.clinerules/plan-reference.md`（**按章节引用，禁止整文件读取**）
- 接口冻结记录与变更流程：`reports/INTERFACE_FREEZE.md`、`PROJECT_PLAN.md` §10.3

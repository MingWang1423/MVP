# 断网 / 降级演练记录（一）· Day13（2026-10-02）

> 对应 `PROJECT_PLAN.md` §5.10 P9.1、§3.3（Ollama 离线兜底）、§8（MVP 收敛）与 §11.1（`DEGRADED_MODE`）。
> 本次演练目标：**中间件不可用时，L4 问答与 L5/L6 演示路径仍可跑通**。

## 1. 演练方式

| 步骤 | 操作 | 观察点 |
|---|---|---|
| ① | `docker stop aisec-neo4j aisec-chroma` | 图数据库 / 向量服务真实下线（`docker compose ps` 仅剩 `postgres (healthy)`） |
| ② | 以降级环境变量启动 API（端口 8010） | `DEGRADED_MODE=true`、`NEO4J_ENABLED=false`、`VECTOR_BACKEND=chroma_memory`、`EMBEDDING_BACKEND=hashing`、`LLM_API_KEY=""`、`DATABASE_URL=<PG DSN>`（保留事实数据以便验证「降级而非空库」） |
| ③ | 调用 `GET /healthz`、`GET /qa/health`、`GET /vulnerabilities`、`POST /qa/ask` | 链路是否可用、是否显式标记降级 |

等价的一行命令（可复现）：

```powershell
docker stop aisec-neo4j aisec-chroma
$env:DEGRADED_MODE='true'; $env:NEO4J_ENABLED='false'
$env:VECTOR_BACKEND='chroma_memory'; $env:EMBEDDING_BACKEND='hashing'
$env:LLM_API_KEY=''; $env:DATABASE_URL='postgresql+asyncpg://aisec:aisec@localhost:5432/aisec'
python -m uvicorn aisec_intel.api.main:app --port 8010
```

## 2. 实测结果（2026-10-02）

| 端点 | 结果 | 说明 |
|---|---|---|
| `GET /healthz` | `{"status":"ok"}` | 进程级探活不依赖任何中间件 |
| `GET /api/v1/qa/health` | `{"status":"degraded","llm_enabled":false,"degraded_mode":true,"vector_backend":"chroma_memory","neo4j_enabled":false,"plan":["query_understander","supervisor","reasoner","synthesizer"],"rate_limit_per_minute":60}` | 降级状态显式外露，前端侧边栏 🟡 提示 |
| `GET /api/v1/vulnerabilities?limit=2` | `total=116` | 事实层走 PostgreSQL，功能不受影响 |
| `POST /api/v1/qa/ask`（`CVE-2021-44228 影响哪些资产`） | `degraded=true` ｜ 引用 **3** 条 ｜ 推理链 **2** 步 ｜ 答案 845 字 | 图谱路退化为 PG JSON 检索；无 LLM → 模板化答案 + 真实引用（**引用仍可回溯**） |

**降级行为归纳**

1. **向量**：`chroma_memory`（进程内）+ `hashing` 嵌入（无模型权重、无网络），语义检索精度下降但链路不断；
2. **图谱**：`NEO4J_ENABLED=false` → 多跳遍历自动走 PostgreSQL 集合运算（`qa/multi_hop.py` 的 `prefer_graph=False` 分支），2 跳以内可用；
3. **LLM**：`LLM_API_KEY` 为空 → 查询理解走规则、Reasoner 产出确定性推理链、Synthesizer 用模板答案，`degraded=true` 显式标记；
4. **引用**：`citation_of()` 仍在**候选结果集合内查表**生成，故「引用可回溯率 100%」在降级下同样成立；
5. **富化**：降级模式跳过 `deepseek-reasoner`，攻击链走 CWE→ATT&CK 兜底映射（`LLM_MODEL_FAST` 仍在时用轻量模型）。

## 3. 结论与遗留

- ✅ API 与前端在 **Neo4j + Chroma 双下线** 情况下可用（本次 API 侧全程验证；前端仅依赖 HTTP，无额外中间件依赖）；
- ✅ 降级状态对调用方**可观测**（`/qa/health` 与 `QAResponse.degraded`），不会静默降智；
- ⚠️ 未覆盖：Ollama 本地模型全链路（`LLM_PROVIDER=ollama`）——安排在 P9.3 第二次断网演练（Day18）执行，需提前 `ollama pull qwen2.5:7b`；
- ⚠️ 降级下的向量召回精度未量化，评测集跑分（`scripts/run_qa_eval.py`）留待 P9.2 在两种模式下分别出报告。

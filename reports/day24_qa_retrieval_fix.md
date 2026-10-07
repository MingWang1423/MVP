# Day24 问答检索层修复报告（Fulltext CVE 约束 + 精确 CVE 短路 + 关联度加权置信度）

> 范围：L4 问答层（`:mod:`aisec_intel.qa``）与检索服务（`:mod:`aisec_intel.services.retrieval_service``）。
> 冻结契约（§10）零变更：`UnifiedVuln` / `RawItem` / `EnrichedVuln` 与 REST 出参结构不变，
> `QAResponse.confidence` 仍是 `[0,1]` 浮点（**只改取值口径**，不改字段）。

## 1. 问题现象

| # | 现象 | 根因 |
|---|---|---|
| 1 | 问「CVE-2024-34359 应升级到哪个版本」返回无关 CVE（CVE-2026-71379 等） | `retrieval_service.fulltext_search` 未接收 `cve_ids`；PG `to_tsquery` 为 **OR 语义**（`cve \| 2024 \| 34359`），任一术语命中即返回，`ts_rank` 前排被无关记录占据 |
| 2 | 4 个引用里 3 个无关，仍显示 100% | `qa/graph.py` 旧口径 `confidence = 0.3 if (degraded or not citations) else 1.0`，只看「有没有引用」，不判断引用相关性 |

## 2. 修复前实测（真实知识库 PG，4113 条 `unified_vuln`）

```
fulltext WITHOUT cve_ids: 8 → ['CVE-2026-105754','CVE-2026-105760','CVE-2026-105755',
                              'CVE-2026-105753','CVE-2025-24357','CVE-2024-43372',
                              'CVE-2024-39306','CVE-2022-24433']      # 全部与 CVE-2024-34359 无关
plan intent-level : ['vector','fulltext','graph']
```

旧构建（远程 demo 实例）的 `/api/v1/qa/ask` 实测：

```
confidence = 1.0   degraded = False
citations  = vuln_descriptions:CVE-2024-34359 / unified_vuln:CVE-2026-71379 /
             unified_vuln:CVE-2026-90443 / unified_vuln:CVE-2023-46604    # 4 条中 3 条无关
```

## 3. 修复后实测（同一知识库、同一问题）

```
fulltext WITH cve_ids: 1 → ['CVE-2024-34359']            # OR 语义噪声被 CVE 白名单拦住
plan executed(1 CVE) : ['vector','graph']                # 精确 CVE 短路 fulltext
```

| 问句 | citations（仅 CVE） | confidence | 说明 |
|---|---|---|---|
| `CVE-2024-34359 应升级到哪个版本` | `graph:CVE-2024-34359`（1 条） | **0.6** < 1.0 | 引用全相关（1.0）× 缺路折扣（vector 0 命中 → ×0.6）；答案明确「现有证据未给出修复版本」 |
| `CVE-2024-3400 影响哪些资产` | `multi_hop:CVE->AttackTechnique->CVE:CVE-2024-3400`（1 条） | 1.0 | 计划两路（graph + multi_hop）均有命中、引用全相关，故不折扣 |

## 4. 代码改动清单

| 文件 | 改动 |
|---|---|
| `src/aisec_intel/services/retrieval_service.py` | 新增 `PG_FULLTEXT_SQL_CVE`（`WHERE vuln_id = ANY(:cve_ids)`）、纯函数 `normalize_cve_filter` / `fulltext_sql_for`；`fulltext_search` / `_pg_fulltext` / `_python_fulltext` 接收 `cve_ids`（SQLite 路径等价用 `in_()` 过滤）；`dispatch` 与 `hybrid_search` 自愈兜底透传 `cve_ids`；`with_cve_filter` 复用 `normalize_cve_filter` |
| `src/aisec_intel/qa/agents/supervisor.py` | 新增纯函数 `precise_cve_plan`（唯一 CVE → 去掉 `fulltext`，仅剩 fulltext 时原样保留）；`SupervisorOutcome.failed_routes` + `partial` 属性；节点增量写入 `partial_retrieval` |
| `src/aisec_intel/qa/state.py` | `QAState` 新增 `partial_retrieval: NotRequired[bool]`（`new_qa_state` 显式初始化 False） |
| `src/aisec_intel/qa/graph.py` | 新增纯函数 `calculate_confidence` + 3 个常量；`ainvoke` 用它替换 `0.3/1.0` 二元口径 |
| `src/aisec_intel/qa/agents/reasoner.py` | 新增纯函数 `filter_cve_relevant`（进模型前剔除 CVE 冲突证据）；`SYSTEM_PROMPT` 第 4 条 + `build_prompt` 引用约束行 |
| `src/aisec_intel/qa/agents/synthesizer.py` | 同源过滤（`synthesize` 入口）+ `SYSTEM_PROMPT` 第 3 条 + `build_prompt` 引用约束行 |
| `tests/unit/` | `test_retrieval_service`（CVE 约束 / 纯函数 / dispatch 透传）、`test_supervisor`（`precise_cve_plan` / `partial`）、`test_qagraph`（置信度公式 + 全链路）、`test_reasoner` / `test_synthesizer`（引用约束与冲突过滤） |

## 5. 新 confidence 公式

```
confidence = (base + relevance_ratio × 0.5) × (0.6 if degraded) × (0.6 if incomplete_retrieval)
```

| 变量 | 取值 |
|---|---|
| `base` | 有引用 = `0.5`；无引用 = `0` |
| `relevance_ratio` | `citations` 中 `cve_id ∈ query_cve_ids` 的占比；查询未指定 CVE 时 = `1.0`；`cve_id` 为空（论文类证据）且查询指定了 CVE 时计为**不相关** |
| `degraded` | 无 LLM / 模板化答案 / 无引用 → ×0.6 |
| `incomplete_retrieval` | `SupervisorOutcome.partial`（计划中任一路 0 命中或抛异常）→ ×0.6 |

对照表（旧 → 新）：

| 场景 | 旧口径 | 新口径 |
|---|---|---|
| 4 引用中 1 条相关 | 1.0 | **0.625** = 0.5 + 0.25×0.5 |
| 4 引用中 3 条相关 | 1.0 | 0.75 |
| 全相关（无降级、检索完备） | 1.0 | 1.0 |
| 全相关 + 降级 | 0.3 | 0.6 |
| 全相关 + 缺路（如知识库缺修复版本） | 1.0 | **0.6** |
| 全相关 + 降级 + 缺路 | 0.3 | 0.36 |
| 无引用 | 0.3 | 0.0 |

> 「缺路折扣」为满足验收「知识库缺修复版本时 confidence 必须 < 1.0」而设：
> 引用全相关≠证据完备，计划中有通路 0 命中说明召回面不完整，与「降级」同档打折。

## 6. 验证命令与结果

```powershell
# 1) 重建并重启 api + scheduler（6/6 healthy）
docker compose up -d --build api scheduler

# 2) 两条验收问句（容器内 CLI + 容器内 HTTP，避开宿主 8000 的 SSH 隧道）
docker compose exec -T api python -m scripts.qa_ask "CVE-2024-34359 应升级到哪个版本"
#   → [引用] 1 条：graph:CVE-2024-34359 | cve=CVE-2024-34359（只含目标 CVE）
#   → 答案：「现有证据未给出修复版本，无法确定应升级到哪个版本」
docker compose exec -T api python -m scripts.qa_ask "CVE-2024-3400 影响哪些资产"
#   → [引用] 1 条：multi_hop:CVE->AttackTechnique->CVE:CVE-2024-3400（只含目标 CVE）
docker compose exec -T api python -c "import httpx; d=httpx.post('http://127.0.0.1:8000/api/v1/qa/ask', json={'query':'CVE-2024-34359 应升级到哪个版本'}, timeout=180).json(); print(d['confidence'], [c['cve_id'] for c in d['citations']])"
#   → 0.6 ['CVE-2024-34359']

# 3) 回归
python -m pytest        # 990 passed, 19 deselected（0 失败）
python -m ruff check src tests scripts   # All checks passed
```

## 7. 环境注意（复现时必读，不改任何默认值）

1. **宿主 `localhost:8000` 被 SSH 隧道占用**：本机存在
   `ssh.exe -L 8000:localhost:8000 root@114.55.110.118`（PID 22280），
   因此宿主 `localhost:8000` 实际打到的**远程 demo 实例仍是修复前构建**（即问题现象的来源）。
   本仓库的修复要在该远程环境 `git pull` 后执行
   `docker compose up -d --build api scheduler` 才生效；本机验证请在容器内发起请求。
2. **Windows 排除端口段覆盖 5432**：`netsh interface ipv4 show excludedportrange protocol=tcp`
   显示 `5358–5457` 已保留，PG 容器无法发布 5432（`ports are not available: ... 5432`）。
   本次用一次性环境变量临时改宿主端口（**保留 compose / .env 默认值不变**）：

   ```powershell
   $env:PG_PORT='15432'; docker compose up -d postgres      # PG 发布到 15432
   # 宿主直连 PG 时：
   $env:PG_DSN='postgresql+asyncpg://aisec:aisec@localhost:15432/aisec'
   ```

   若重启后排除段变化，`docker compose up -d` 会尝试按 `.env` 的 5432 重建 PG；
   端口被占用时用上面的 `PG_PORT` 覆盖即可（数据在 `pg_data` 卷中，不受影响）。

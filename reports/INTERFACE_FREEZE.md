# 接口冻结记录（Day1）

> 冻结日期：2026-09-30 ｜ 版本：v1.0 ｜ 冻结依据：`PROJECT_PLAN.md` §10
> 三个模型是**全系统唯一的跨层契约**，任何变更必须走 §10.3 流程并在本文件追加修订记录。

## 1. 冻结清单

| 契约 | 文件（实际落地） | 生产者 → 消费者 | 说明 |
|---|---|---|---|
| `RawItem` | `src/aisec_intel/models/raw_item.py` | L1 采集 → L2 归一化 | 原始情报件，`frozen=True` |
| `UnifiedVuln` | `src/aisec_intel/models/unified_vuln.py` | L2 归一化 → L3/L4/存储 | 多源合并后的统一漏洞实体（**无推断**） |
| `EnrichedVuln` | `src/aisec_intel/models/enriched_vuln.py` | L3 富化 → L4 问答/L5 API/L6 前端 | 五维度富化结论 + 复核状态 |

附带模型（`EnrichedVuln` 的组成部分，同样冻结）：
`CVSSVector` / `CpeMatch` / `Reference`（`unified_vuln.py`）、
`AgentStep` / `AffectedAsset` / `ExploitRecord` / `AttackChain` / `AttackChainStep`（`enriched_vuln.py`）、
`Paper` / `PaperVulnLink`（`paper.py`）、基类与时间类型（`base.py`）。

## 2. 字段速查表

### 2.1 `RawItem`（12 字段，1 个必填组 + 可选组）

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `schema_version` | str | 否（默认 `1.0`） | 契约版本，变更必须 bump |
| `trace_id` | str（非空） | **是** | 全链路追踪 ID（uuid4） |
| `source` | str（非空） | **是** | 源标识：nvd/osv/ghsa/kev/epss/arxiv/... |
| `source_id` | str（非空） | **是** | 源内唯一 ID |
| `url` | str（非空） | **是** | 原文链接（引用回溯依据） |
| `title` | str \| None | 否 | RSS / 厂商公告标题 |
| `raw_text` | str | **是** | 原文正文，保真保存 |
| `lang` | str \| None | 否 | zh / en |
| `published_at` | UTC datetime \| None | 否 | 源发布时间 |
| `fetched_at` | UTC datetime | **是** | 采集时间 |
| `sha256` | str | **是** | `raw_text` 内容指纹（幂等 / 去重） |
| `meta` | dict[str, str] | 否（默认 `{}`） | 源特有附加字段 |

### 2.2 `UnifiedVuln`（21 字段，v1.1）

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `schema_version` | str | 否（`1.1`） | 契约版本（v1.0 → v1.1，见 §6） |
| `vuln_id` | str（非空） | **是** | 规范主键，如 `CVE-2024-3400` |
| `aliases` | list[str] | 否（`[]`） | GHSA / OSV / CNVD 别名 |
| `trace_ids` | list[str] | 否（`[]`） | 关联 `RawItem.trace_id` 列表 |
| `title` | str \| None | 否 | 标题 |
| `description` | str | **是** | 清洗后的描述 |
| `lang` | str \| None | 否 | 描述语言 |
| `cvss` | list[CVSSVector] | 否（`[]`） | 按版本升序 |
| `severity` | Severity \| None | 否（`None`） | **v1.1 新增**：最高 CVSS 严重度（确定性推导，无 CVSS 时为 `None`） |
| `cwe_ids` | list[str] | 否（`[]`） | 如 `CWE-78` |
| `cpe_matches` | list[CpeMatch] | 否（`[]`） | 受影响版本区间（结构化） |
| `affected_versions` | list[str] | 否（`[]`） | **v1.1 新增**：受影响版本区间描述（由 `cpe_matches` 确定性渲染） |
| `ecosystem_packages` | list[str] | 否（`[]`） | 如 `PyPI:django` |
| `references` | list[Reference] | 否（`[]`） | 外部链接（含 `tags`：patch / exploit） |
| `kev` | bool | 否（`False`） | 是否进入 CISA KEV |
| `epss_score` | float \| None（0–1） | 否 | FIRST EPSS 概率 |
| `epss_percentile` | float \| None（0–1） | 否 | FIRST EPSS 百分位 |
| `published_at` | UTC datetime \| None | 否 | 公开发布时间 |
| `modified_at` | UTC datetime \| None | 否 | 最近修改时间 |
| `sources` | list[str] | 否（`[]`） | 贡献源并集 |
| `normalized_at` | UTC datetime | **是** | 归一化时间 |

### 2.3 `EnrichedVuln`（继承 `UnifiedVuln` + 13 个自有字段）

| 自有字段 | 类型 | 必填 | 富化维度 |
|---|---|---|---|
| `affected_assets` | list[AffectedAsset] | 否（`[]`） | ① 受影响资产 |
| `related_papers` | list[PaperVulnLink] | 否（`[]`） | ② 关联论文 |
| `exploits` | list[ExploitRecord] | 否（`[]`） | ③ PoC / EXP |
| `risk_score` | float（0–100） | **是** | ④ 风险分（确定性公式） |
| `risk_level` | low/medium/high/critical | **是** | ④ 风险级别 |
| `risk_breakdown` | dict[str, float] | 否（`{}`） | ④ 权重拆解（cvss/epss/kev/poc） |
| `attack_chain` | AttackChain \| None | 否（`None`） | ⑤ 攻击链 |
| `confidence` | float（0–1） | **是** | 整体置信度（Reviewer 裁决） |
| `review_status` | auto_pass/revised/needs_human | 否（`auto_pass`） | 复核状态 |
| `review_notes` | list[str] | 否（`[]`） | 修订 / 驳回理由 |
| `agent_trace` | list[AgentStep] | 否（`[]`） | 7 个 Agent 执行轨迹 |
| `model_used` | str | **是** | fast / smart 模型标识 |
| `enriched_at` | UTC datetime | **是** | 富化完成时间 |

## 3. 冻结不变式（§10.2）

1. 字段名与语义不变。
2. 只增不改：新增字段必须带默认值，且 `schema_version` 递增。
3. 时间统一 UTC，序列化为 ISO8601 带 `Z`（由 `base.UTCDateTime` 强制，已单测覆盖）。
4. 富化只追加：`EnrichedVuln` 不得覆写 `UnifiedVuln` 字段（已单测 `test_inherits_parent_fields_without_override`）。
5. `trace_id` 必须透传：`RawItem.trace_id` → `UnifiedVuln.trace_ids[]` → `EnrichedVuln.*.evidence_refs`（已单测）。
6. `extra="forbid"` 不可放开（已单测 `test_extra_forbid_enabled_everywhere`）。

## 4. 变更流程（§10.3）

```
① 提出（站会/issue，说明原因与影响面） → ② 双方评估（≤15 min）
→ ③ 双方同意 → ④ 改 models/*.py + bump schema_version + 兼容 shim
→ ⑤ 回归：pytest tests/test_models.py -q + 跑最小演示路径（§8.1）
→ ⑥ 在本文件「修订记录」追加一行
```

**明令禁止**：直接改字段名或类型；删除已被下游消费的字段；未经站会告知改 `models/`；在 Agent 内 `setattr` 动态塞字段。

## 5. Day1 实际落地与计划书的命名差异（待 P1 收口）

| 计划书（§2 / §10.1） | 实际文件 | 原因 | 收口计划 |
|---|---|---|---|
| `models/raw.py` | `models/raw_item.py` | Day1 任务书指定文件名，语义更明确 | P1 评估是否统一为计划书命名（走 §10.3） |
| `models/vuln.py` | `models/unified_vuln.py` | 同上 | 同上 |
| `models/enriched.py` | `models/enriched_vuln.py` | 同上 | 同上 |
| `logging.py`（§2） | `logging_config.py` | 避免与标准库 `logging` 同名歧义 | 保留实际命名，P1 同步修正 §2 目录树描述 |
| `tests/unit/test_models.py` | `tests/test_models.py` | Day1 任务书指定路径 | P1 迁移至 `tests/unit/`，并修正 §10.3 回归命令 |
| `models/paper.py` 属 P1 | Day1 已创建 | `EnrichedVuln.related_papers` 依赖 `PaperVulnLink` | P1 仅扩展字段，不改结构 |

## 6. 修订记录

| 日期 | 变更 | 原因 | 影响面 | 签字 |
|---|---|---|---|---|
| 2026-09-30 | 首次冻结 v1.0（三模型 + 附带组件） | Day1 接口冻结（P0） | 全链路 | A / B 待联签 |
| 2026-10-01 | ① 计划书回写文件名（§2、§10.1）并追加 §12 修订记录；② 新增 Agent IO 契约 `agent_io.py`（`EnrichmentInput/Output`、`QAQuery/QAResponse`、`Citation`、`ReasoningStep`）；③ 新增存储层 ORM 映射 `unified_vuln` / `enriched_vuln` + 迁移 `0001_init` | Day2 / P1：命名定稿 + Agent IO 与存储层落地 | 三模型**字段未变**（`schema_version` 仍为 `1.0`，无兼容 shim）；新增契约同样受 §10.2 不变式约束（`extra="forbid"`、UTC、`trace_id` 透传） | A / B 待联签 |
| 2026-09-30 | **`UnifiedVuln` v1.0 → v1.1（只增不改）**：新增 `severity: Severity \| None = None`（最高 CVSS 严重度）与 `affected_versions: list[str] = []`（受影响版本区间描述）；`unified_vuln` 表追加同名列（迁移 `0004_summary_fields`，两列均可空，既有行无需回填）；§2.2 字段表与 §7 验收命令同步更新 | **Day7 前置接口适配审查**：7 个富化 Agent 中 AssetMapper / Remediation 需要「受影响版本」、Verifier 需要「严重度」，原 19 字段无法满足 | ① L2：`normalize/cvss.severity_from_vectors` + `normalize/pipeline.affected_versions_from_cpes`（纯函数派生，无推断），`build_unified_vuln` 填充、`dedupe.merge_group` 随并集重算；② 存储：`UnifiedVulnRow.from_domain/to_domain` + 迁移 0004；③ Agent IO、`EnrichedVuln` 自有字段、`RawItem` 均**未改**（`EnrichedVuln` 因继承字段集，其 `schema_version` 随父契约取 `1.1`）；④ 测试：`tests/unit/test_models.py` 版本断言更新 + 新增 `tests/unit/test_normalize_summary_fields.py`（20 例） | A / B 待联签 |
| 2026-09-30 | **行为变更（非契约字段变更）**：`VulnRepository.upsert` 由「后写整体覆盖」改为「按字段类型合并」——空值不覆盖、集合取并集、`kev` 取 OR、`epss` 取最大、`cvss` 并集后取最高、`severity` 只升不降、`description` 取最长、时间取极值；`cvss`/`severity` 规则同步用于 `normalize/dedupe.merge_group`；**新增 §8 落库合并策略**专章记录 | **多源覆盖缺陷**：逐源分开重跑（先 NVD 后 KEV/EPSS）会用后写源的空值清空先写源的数据（如 `cvss=10.0` → `None`、`kev=True` → `False`），破坏「多源事实汇聚」语义 | ① 实现：`normalize/dedupe.merge_for_update`（复用 `merge_group` 规则，主键保持既有行）+ `normalize/cvss.severity_rank_max`；② `VulnRepository.upsert` 调用点替换（`upsert_enriched` 不变）；③ 无表结构变更、无 `schema_version` 变更（字段集未变，仅落库语义）；④ 测试：新增 `tests/integration/test_upsert_merge.py`（6 例：3 源分序重跑 / 顺序无关 / 幂等）与 `TestMergeForUpdate`（6 例）、`TestSeverityRankMax`（3 例）、`test_storage.py` 回归 1 例 | A / B 待联签 |

## 8. 落库合并策略（v1.1 行为变更，2026-09-30）

### 8.1 变更内容

`VulnRepository.upsert` 命中既有行时，**由「后写整体覆盖」改为「按字段类型合并」**。
实现复用 L2 纯函数 [`normalize/dedupe.merge_for_update`](../src/aisec_intel/normalize/dedupe.py)
（与 `merge_group` 同一套规则，策略单点定义）。

**缺陷（修复前）**：逐源分开重跑会丢数据 —— 先跑 NVD 写入 `cvss=10.0`，再跑 KEV（无 CVSS）→ 库中 `cvss` 变 `None`；再跑 EPSS → `kev` / `cvss` 全丢。

### 8.2 字段级规则（确定性，无推断）

| 字段 | 合并规则 |
|---|---|
| `description` | 取**最长**（信息量最大；与 L2 既有口径一致） |
| `title` | 取首个非空（按发布时间正序） |
| `cvss` | 并集（`(version, vector)` 去重、版本升序）→ 等价「取最高分」 |
| `severity` | **取最高等级**（贡献方声明 ∪ 由并集 `cvss` 重算；只升不降） |
| `published_at` / `modified_at` / `normalized_at` | 最早 / 最晚 / 最晚 |
| `kev` | 布尔 **OR** |
| `epss_score` / `epss_percentile` | 取**最大** |
| `cwe_ids` / `cpe_matches` / `references` / `ecosystem_packages` / `aliases` | **并集**（`references` 按规范化 URL 去重、`tags` 合并） |
| `affected_versions` | 由并集 `cpe_matches` 重算 |
| `sources` / `trace_ids` | **并集**（§10.2 不变式 5：链路不丢） |
| `schema_version` | 取**最高** |
| `vuln_id` | **保持库中既有行主键**（不静默换主键）；本次写入若用不同主键，该主键降级写入 `aliases` |

**语义性质（已单测）**：① 非空值优先 —— 空值/`None` 不覆盖已有值；② 语义字段与「重跑顺序」无关；
③ 重复重跑幂等（不产生第二行、字段不再变化）；④ 集合类字段的元素**顺序**跟随贡献记录的
`published_at` 升序（集合语义与顺序无关）。

**不在本次范围**：`upsert_enriched`（L3 富化结果）仍为整体覆盖 —— 重新富化即应替换旧结论。

### 8.3 回归证据

```powershell
python -m pytest tests/integration/test_upsert_merge.py -q      # 3 源分序重跑（仓储级 + 采集级）
python -m pytest tests/unit/test_normalize_dedupe.py -q         # 合并规则纯函数
python -m pytest tests/unit/test_storage.py -q                  # 仓储层
```

---

## 9. 验收证据

```text
pytest tests/unit/test_models.py -q                       # 契约测试（字段、UTC、extra=forbid、trace_id 透传）
pytest tests/unit/test_normalize_summary_fields.py -q      # v1.1 新增字段：派生 / 合并 / ORM 往返
pytest tests/unit/test_agent_io.py -q                      # Agent IO 契约与一致性校验
python -c "from aisec_intel.models import RawItem, UnifiedVuln, EnrichedVuln; print('ok')"
```

**v1.1 回归命令（§10.3 ⑤）**：

```powershell
python -m pytest tests/unit/test_models.py tests/unit/test_normalize_summary_fields.py -q
python -m pytest tests/unit/test_storage.py -q            # ORM 往返（含新列）
python -m scripts.init_db                                 # 迁移 0004_summary_fields → head
python -m scripts.run_collect --source nvd,epss,kev --cve CVE-2024-3400   # 最小演示路径 ①
```

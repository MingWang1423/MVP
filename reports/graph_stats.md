# P6 图谱规模统计（graph_stats.md）

> 生成命令：`python -m scripts.load_graph --all`（Day9 / P6）
> 数据流：PostgreSQL `enriched_vuln` → `aisec_intel.graph.extractor`（纯函数，无 LLM）→ Neo4j
> 模式：实灌（幂等 upsert）

## 1. 本次抽取统计

| 漏洞 | 节点数 | 边数 | 节点明细 | 边明细 |
|---|---:|---:|---|---|
| CVE-2026-96451 | 6 | 5 | AttackTechnique:4, Patch:1, Vulnerability:1 | EXPLOITS:4, FIXED_BY:1 |
| CVE-2026-105123 | 6 | 5 | AttackTechnique:4, Patch:1, Vulnerability:1 | EXPLOITS:4, FIXED_BY:1 |
| CVE-2026-105126 | 8 | 7 | AttackTechnique:3, Patch:4, Vulnerability:1 | EXPLOITS:3, FIXED_BY:4 |
| CVE-2026-68770 | 13 | 12 | Asset:1, AttackTechnique:4, Component:1, Patch:6, Vulnerability:1 | AFFECTS:1, EXPLOITS:4, FIXED_BY:6, INSTALLED_ON:1 |
| CVE-2026-80047 | 9 | 8 | Asset:1, AttackTechnique:4, Component:1, Patch:2, Vulnerability:1 | AFFECTS:1, EXPLOITS:4, FIXED_BY:2, INSTALLED_ON:1 |
| CVE-2023-29374 | 9 | 9 | Asset:1, AttackTechnique:3, Component:2, Patch:2, Vulnerability:1 | AFFECTS:2, EXPLOITS:3, FIXED_BY:2, INSTALLED_ON:2 |
| CVE-2026-22778 | 16 | 16 | Asset:1, AttackTechnique:4, Component:2, Patch:8, Vulnerability:1 | AFFECTS:2, EXPLOITS:4, FIXED_BY:8, INSTALLED_ON:2 |
| CVE-2024-37032 | 8 | 7 | Asset:2, AttackTechnique:4, Component:1, Vulnerability:1 | AFFECTS:1, EXPLOITS:4, INSTALLED_ON:2 |
| CVE-2024-27537 | 2 | 1 | AttackTechnique:1, Vulnerability:1 | EXPLOITS:1 |
| CVE-2021-44228 | 21 | 20 | Asset:10, AttackTechnique:4, Component:1, Patch:5, Vulnerability:1 | AFFECTS:1, EXPLOITS:4, FIXED_BY:5, INSTALLED_ON:10 |
| CVE-2024-3400 | 8 | 7 | Asset:1, AttackTechnique:3, Component:1, Patch:2, Vulnerability:1 | AFFECTS:1, EXPLOITS:3, FIXED_BY:2, INSTALLED_ON:1 |
| **合计** | 106 | 97 | — | — |

## 2. Neo4j 现有规模

| 节点标签 | 数量 | 关系类型 | 数量 |
|---|---:|---|---:|
| Asset | 17 | AFFECTS | 9 |
| AttackTechnique | 20 | EXPLOITS | 38 |
| Component | 9 | FIXED_BY | 31 |
| Paper | 0 | INSTALLED_ON | 19 |
| Patch | 31 | RELATED_TO | 0 |
| Vulnerability | 11 |  |  |

## 3. 复核用查询（Neo4j Browser）

```cypher
MATCH (v:Vulnerability {cve_id:'CVE-2024-3400'}) RETURN v
MATCH (v:Vulnerability {cve_id:'CVE-2024-3400'})-[r]->(n) RETURN v, r, n
MATCH (v:Vulnerability)-[:AFFECTS]->(c:Component)<-[:AFFECTS]-(peer:Vulnerability) RETURN c.key, collect(peer.cve_id) AS related_cves
```

> 约束与索引由 `aisec_intel/graph/schema.py` 统一声明，`GraphRepository.ensure_schema()` 幂等执行。

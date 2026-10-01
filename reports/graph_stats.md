# P6 图谱规模统计（graph_stats.md）

> 生成命令：`python -m scripts.load_graph --all`（Day9 / P6）
> 数据流：PostgreSQL `enriched_vuln` → `aisec_intel.graph.extractor`（纯函数，无 LLM）→ Neo4j
> 模式：实灌（幂等 upsert）

## 1. 本次抽取统计

| 漏洞 | 节点数 | 边数 | 节点明细 | 边明细 |
|---|---:|---:|---|---|
| CVE-2021-44228 | 163 | 1582 | Asset:10, AttackTechnique:4, Component:143, Patch:5, Vulnerability:1 | AFFECTS:143, EXPLOITS:4, FIXED_BY:5, INSTALLED_ON:1430 |
| CVE-2024-3400 | 8 | 7 | Asset:1, AttackTechnique:3, Component:1, Patch:2, Vulnerability:1 | AFFECTS:1, EXPLOITS:3, FIXED_BY:2, INSTALLED_ON:1 |
| CVE-2024-27537 | 2 | 1 | AttackTechnique:1, Vulnerability:1 | EXPLOITS:1 |
| **合计** | 173 | 1590 | — | — |

## 2. Neo4j 现有规模

| 节点标签 | 数量 | 关系类型 | 数量 |
|---|---:|---|---:|
| Asset | 11 | AFFECTS | 144 |
| AttackTechnique | 6 | EXPLOITS | 8 |
| Component | 144 | FIXED_BY | 7 |
| Paper | 0 | INSTALLED_ON | 1431 |
| Patch | 7 | RELATED_TO | 0 |
| Vulnerability | 3 |  |  |

## 3. 复核用查询（Neo4j Browser）

```cypher
MATCH (v:Vulnerability {cve_id:'CVE-2024-3400'}) RETURN v
MATCH (v:Vulnerability {cve_id:'CVE-2024-3400'})-[r]->(n) RETURN v, r, n
MATCH (v:Vulnerability)-[:AFFECTS]->(c:Component)<-[:AFFECTS]-(peer:Vulnerability) RETURN c.key, collect(peer.cve_id) AS related_cves
```

> 约束与索引由 `aisec_intel/graph/schema.py` 统一声明，`GraphRepository.ensure_schema()` 幂等执行。

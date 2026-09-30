# P6 图谱规模统计（graph_stats.md）

> 生成命令：`python -m scripts.load_graph --all --no-schema`（Day9 / P6）
> 数据流：PostgreSQL `enriched_vuln` → `aisec_intel.graph.extractor`（纯函数，无 LLM）→ Neo4j
> 模式：实灌（幂等 upsert）

## 1. 本次抽取统计

| 漏洞 | 节点数 | 边数 | 节点明细 | 边明细 |
|---|---:|---:|---|---|
| CVE-2024-27537 | 2 | 1 | AttackTechnique:1, Vulnerability:1 | EXPLOITS:1 |
| CVE-2024-3400 | 8 | 7 | Asset:1, AttackTechnique:3, Component:1, Patch:2, Vulnerability:1 | AFFECTS:1, EXPLOITS:3, FIXED_BY:2, INSTALLED_ON:1 |
| **合计** | 10 | 8 | — | — |

## 2. Neo4j 现有规模

| 节点标签 | 数量 | 关系类型 | 数量 |
|---|---:|---|---:|
| Asset | 1 | AFFECTS | 1 |
| AttackTechnique | 4 | EXPLOITS | 4 |
| Component | 1 | FIXED_BY | 2 |
| Paper | 0 | INSTALLED_ON | 1 |
| Patch | 2 | RELATED_TO | 0 |
| Vulnerability | 2 |  |  |

## 3. 复核用查询（Neo4j Browser）

```cypher
MATCH (v:Vulnerability {cve_id:'CVE-2024-3400'}) RETURN v
MATCH (v:Vulnerability {cve_id:'CVE-2024-3400'})-[r]->(n) RETURN v, r, n
MATCH (v:Vulnerability)-[:AFFECTS]->(c:Component)<-[:AFFECTS]-(peer:Vulnerability) RETURN c.key, collect(peer.cve_id) AS related_cves
```

> 约束与索引由 `aisec_intel/graph/schema.py` 统一声明，`GraphRepository.ensure_schema()` 幂等执行。

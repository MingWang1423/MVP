"""知识图谱子包（PROJECT_PLAN.md §5.7 P6）。

- :mod:`aisec_intel.graph.schema`：节点标签 / 关系类型 / 约束与索引（唯一 schema 声明处）；
- :mod:`aisec_intel.graph.extractor`：``EnrichedVuln`` → 节点 + 边 的**纯函数**抽取器（禁用 LLM）。

写入与查询由 :mod:`aisec_intel.storage.repositories.graph_repo` 承担（neo4j 官方驱动）。
"""

"""ORM 映射集合（PROJECT_PLAN.md §2 storage/models）。

导入本包即完成所有表到 ``Base.metadata`` 的注册，Alembic autogenerate 与
:func:`aisec_intel.storage.database.init_models` 均依赖此副作用。
"""

from __future__ import annotations

from aisec_intel.storage.models.cache import LLMCacheRow
from aisec_intel.storage.models.enriched import EnrichedVulnRow
from aisec_intel.storage.models.raw import RawItemRow
from aisec_intel.storage.models.source import SourceRow, SourceSnapshot
from aisec_intel.storage.models.task import TaskRunRow, TaskRunSnapshot
from aisec_intel.storage.models.vuln import UnifiedVulnRow

__all__ = [
    "EnrichedVulnRow",
    "LLMCacheRow",
    "RawItemRow",
    "SourceRow",
    "SourceSnapshot",
    "TaskRunRow",
    "TaskRunSnapshot",
    "UnifiedVulnRow",
]

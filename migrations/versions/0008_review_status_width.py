"""enriched_vuln.review_status 放宽到 varchar(32)（新增永久失败状态）

Revision ID: 0008
Revises: 0007
Create Date: 2026-10-06 02:00:00.000000

Day23 任务 2（PROJECT_PLAN.md §10.3 变更流程）：补齐「自愈缺口 · 失败重试队列」的落库能力。

变更内容：
    ``enriched_vuln.review_status`` 由 ``varchar(16)`` 放宽到 ``varchar(32)``，
    以容纳新增状态值 ``permanently_failed``（18 字符，原宽度会被 PG 拒绝）。

配套契约变更（只增不改）：
    ``EnrichedVuln.review_status`` 的 ``Literal`` 增加 ``"permanently_failed"``；
    ``EnrichedVuln.schema_version`` 默认值 v1.2 → v1.3（父契约 ``UnifiedVuln`` 仍为 1.1）。

Note:
    仅放宽列宽、不新增列，历史数据无需回填；SQLite 走 ``batch_alter_table`` 重建表。
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0008"
down_revision: str | Sequence[str] | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema：放宽 ``review_status`` 列宽到 32。"""
    with op.batch_alter_table("enriched_vuln") as batch_op:
        batch_op.alter_column(
            "review_status",
            existing_type=sa.String(length=16),
            type_=sa.String(length=32),
            existing_nullable=True,
        )


def downgrade() -> None:
    """Downgrade schema：回收列宽（回退前需先把 ``permanently_failed`` 行改回 needs_human）。"""
    op.execute("UPDATE enriched_vuln SET review_status = 'needs_human' WHERE review_status = 'permanently_failed'")
    with op.batch_alter_table("enriched_vuln") as batch_op:
        batch_op.alter_column(
            "review_status",
            existing_type=sa.String(length=32),
            type_=sa.String(length=16),
            existing_nullable=True,
        )

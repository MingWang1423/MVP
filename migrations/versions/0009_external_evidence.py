"""新增 external_evidence 表（受控外部检索的隔离区）

Revision ID: 0009
Revises: 0008
Create Date: 2026-10-07 04:00:00.000000

Day25 阶段 2 任务 2.1（PROJECT_PLAN.md §5.8「受控外部检索」）：

变更内容：
    新增 ``external_evidence`` 表，存放本地证据不足时从**权威源白名单**
    （NVD / GHSA / OSV / CISA KEV）补齐的事实。

设计约束：
    1. **外部证据不直接写正式表**：``unified_vuln`` / ``enriched_vuln`` 的写入链路不变；
    2. **不可信标记**：``snippet`` 均为 :mod:`aisec_intel.security.external_sanitizer`
       清洗后的正文（≤2000 字符），``trust_score`` / ``verified`` 记录复核结论；
    3. **幂等**：``content_hash`` 为内容指纹（重复检索只刷新时间与复核结果）；
    4. 全部列可空 / 有默认值，历史数据无需回填（本表为新增表，无回填动作）。
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0009"
down_revision: str | Sequence[str] | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema：创建 ``external_evidence`` 表与索引。"""
    op.create_table(
        "external_evidence",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("query", sa.String(length=512), nullable=False, server_default=""),
        sa.Column("cve_id", sa.String(length=32), nullable=True),
        sa.Column("source_type", sa.String(length=16), nullable=False),
        sa.Column("source_name", sa.String(length=128), nullable=False, server_default=""),
        sa.Column("url", sa.String(length=512), nullable=False, server_default=""),
        sa.Column("title", sa.Text(), nullable=False, server_default=""),
        sa.Column("snippet", sa.Text(), nullable=False, server_default=""),
        sa.Column("retrieved_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("trust_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("verified", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("content_hash", sa.String(length=64), nullable=False, server_default=""),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_external_evidence_query", "external_evidence", ["query"])
    op.create_index("ix_external_evidence_cve_id", "external_evidence", ["cve_id"])
    op.create_index("ix_external_evidence_source_type", "external_evidence", ["source_type"])
    op.create_index("ix_external_evidence_retrieved_at", "external_evidence", ["retrieved_at"])
    op.create_index("ix_external_evidence_verified", "external_evidence", ["verified"])
    op.create_index("ix_external_evidence_content_hash", "external_evidence", ["content_hash"])


def downgrade() -> None:
    """Downgrade schema：删除 ``external_evidence`` 表（外部证据可重新检索，无需备份）。"""
    op.drop_index("ix_external_evidence_content_hash", table_name="external_evidence")
    op.drop_index("ix_external_evidence_verified", table_name="external_evidence")
    op.drop_index("ix_external_evidence_retrieved_at", table_name="external_evidence")
    op.drop_index("ix_external_evidence_source_type", table_name="external_evidence")
    op.drop_index("ix_external_evidence_cve_id", table_name="external_evidence")
    op.drop_index("ix_external_evidence_query", table_name="external_evidence")
    op.drop_table("external_evidence")

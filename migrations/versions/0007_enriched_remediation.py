"""enriched_vuln.remediation_json

Revision ID: 0007
Revises: 0005
Create Date: 2026-10-02 09:00:00.000000

Day17 任务 1（PROJECT_PLAN.md §10.3 变更流程）：补齐「富化维度⑦ 修复建议」落库缺口。

变更内容：
    ``enriched_vuln`` 追加 JSON 列 ``remediation_json``（可空），存放
    ``Remediation.model_dump(mode="json")`` 快照（summary / fixed_versions /
    mitigations / patch_urls / confidence）。

配套契约变更（只增不改）：
    ``EnrichedVuln.schema_version`` 默认值 v1.1 → v1.2（父契约 ``UnifiedVuln`` 仍为 1.1）。

Note:
    编号沿用 Day17 任务书（``0007``）；``0006`` 在 Day16 未使用（当阶段无 schema 变更），
    因此本迁移的 ``down_revision`` 直接指向 ``0005``（alembic 不要求编号连续）。
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0007'
down_revision: Union[str, Sequence[str], None] = '0005'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('enriched_vuln', sa.Column('remediation_json', sa.JSON(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('enriched_vuln', 'remediation_json')

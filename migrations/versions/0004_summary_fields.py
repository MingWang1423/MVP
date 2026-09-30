"""summary_fields

Revision ID: 0004
Revises: 0003
Create Date: 2026-09-30 06:10:00.000000

Day7 前置适配审查：``UnifiedVuln`` 契约 v1.0 → v1.1，新增两个**带默认值**的字段
（只增不改，§10.2 不变式 2）：

- ``severity``：最高 CVSS 严重度（由 ``cvss`` 确定性推导），供 Verifier / 风险评分消费；
- ``affected_versions``：受影响版本区间描述（由 ``cpe_matches`` 确定性渲染），
  供 AssetMapper / Remediation 消费。

两列均允许 NULL，既有行无需回填（可重新归一化刷新）。
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0004'
down_revision: Union[str, Sequence[str], None] = '0003'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('unified_vuln', sa.Column('severity', sa.String(length=16), nullable=True))
    op.add_column('unified_vuln', sa.Column('affected_versions', sa.JSON(), nullable=True))
    op.create_index(op.f('ix_unified_vuln_severity'), 'unified_vuln', ['severity'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_unified_vuln_severity'), table_name='unified_vuln')
    op.drop_column('unified_vuln', 'affected_versions')
    op.drop_column('unified_vuln', 'severity')

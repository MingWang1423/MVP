"""llm_cache

Revision ID: 0005
Revises: 0004
Create Date: 2026-09-30 07:20:00.000000

P5：新增 ``llm_cache`` 表（LLM 结构化输出缓存，§3.4 额度保护 / §5.6）。

键 = ``sha256(prompt + model + temperature)``；命中即返回，避免重复扣费。
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0005'
down_revision: Union[str, Sequence[str], None] = '0004'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'llm_cache',
        sa.Column('cache_key', sa.String(length=64), nullable=False),
        sa.Column('provider', sa.String(length=32), nullable=False),
        sa.Column('model', sa.String(length=64), nullable=False),
        sa.Column('temperature', sa.Float(), nullable=False),
        sa.Column('schema_name', sa.String(length=64), nullable=False),
        sa.Column('response_json', sa.Text(), nullable=False),
        sa.Column('prompt_tokens', sa.Integer(), nullable=False),
        sa.Column('completion_tokens', sa.Integer(), nullable=False),
        sa.Column('hits', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('cache_key', name=op.f('pk_llm_cache')),
    )
    op.create_index(op.f('ix_llm_cache_model'), 'llm_cache', ['model'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_llm_cache_model'), table_name='llm_cache')
    op.drop_table('llm_cache')

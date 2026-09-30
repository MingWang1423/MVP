"""SQLAlchemy 2.0 声明式基类与约束命名约定。

本模块只放基类，不放具体表定义；表定义位于 ``storage/models/`` 下，与领域契约
（``aisec_intel.models``）一一对应。Alembic 通过 ``Base.metadata`` 做 autogenerate，
因此命名约定必须显式声明（否则不同数据库生成的约束名不一致，迁移会漂移）。
"""

from __future__ import annotations

from sqlalchemy import MetaData
from sqlalchemy.orm import DeclarativeBase

NAMING_CONVENTION: dict[str, str] = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}
"""索引/约束统一命名模板（跨 PostgreSQL / SQLite 保持一致）。"""


class Base(DeclarativeBase):
    """全项目 ORM 映射基类。"""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)

"""采集器注册表（PROJECT_PLAN.md §5.3 P2）。

采集器类通过 ``@register`` 装饰器自注册；上层（``scripts/run_collect.py``、
``services/collect_service.py``、前端「采集运维」页）只按**源标识字符串**取用，
不直接 import 具体类，便于 P3 批量新增源。
"""

from __future__ import annotations

from typing import TypeVar

from aisec_intel.connectors.base import BaseConnector

_REGISTRY: dict[str, type[BaseConnector]] = {}
"""源标识 → 采集器类。"""

TConnector = TypeVar("TConnector", bound=type[BaseConnector])


class UnknownSourceError(LookupError):
    """请求了未注册的源标识。"""


def register(connector_cls: TConnector) -> TConnector:
    """注册采集器类（装饰器）。

    Args:
        connector_cls: 继承 ``BaseConnector`` 的类。

    Returns:
        原类本身（便于 ``@register`` 用法）。

    Raises:
        ValueError: 类未声明非空 ``source_name``。
        ValueError: 同一 ``source_name`` 被重复注册（避免静默覆盖）。
    """
    source = connector_cls.source_name
    if not source:
        raise ValueError(f"{connector_cls.__name__} 必须声明非空的 source_name")
    existing = _REGISTRY.get(source)
    if existing is not None and existing is not connector_cls:
        raise ValueError(f"源 {source!r} 已被 {existing.__name__} 注册，禁止重复注册")
    _REGISTRY[source] = connector_cls
    return connector_cls


def get_connector_class(source: str) -> type[BaseConnector]:
    """按源标识取采集器类。

    Args:
        source: 源标识，如 ``"kev"``。

    Returns:
        采集器类。

    Raises:
        UnknownSourceError: 源未注册。
    """
    key = source.strip().lower()
    if key not in _REGISTRY:
        raise UnknownSourceError(f"未注册的源 {source!r}；可用源：{available_sources()}")
    return _REGISTRY[key]


def create_connector(source: str, **kwargs: object) -> BaseConnector:
    """按源标识实例化采集器。

    Args:
        source: 源标识。
        **kwargs: 透传给采集器构造函数（如 ``http=`` / ``limiter=`` / ``settings=``）。

    Returns:
        采集器实例。
    """
    return get_connector_class(source)(**kwargs)


def available_sources() -> list[str]:
    """返回已注册的源标识（字典序）。

    Returns:
        源标识列表。
    """
    return sorted(_REGISTRY)


def clear_registry() -> None:
    """清空注册表（仅供测试使用）。"""
    _REGISTRY.clear()

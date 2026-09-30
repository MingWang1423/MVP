"""L1 采集层（PROJECT_PLAN.md §5.3）：所有采集器继承 ``BaseConnector``，**禁止 LLM**。

用法::

    from aisec_intel.connectors import create_connector

    async with create_connector("kev") as connector:
        items = await connector.fetch_incremental(since_dt)

导入本包会触发各采集器模块的 ``@register`` 自注册，因此无需手工登记。
"""

from __future__ import annotations

from aisec_intel.connectors.arxiv import ArxivConnector
from aisec_intel.connectors.base import BaseConnector
from aisec_intel.connectors.epss import EpssConnector
from aisec_intel.connectors.ghsa import GhsaAuthError, GhsaConnector, GhsaError, GhsaQueryError
from aisec_intel.connectors.http_client import (
    DEFAULT_MAX_RETRIES,
    DEFAULT_TIMEOUT_S,
    HttpClient,
    HttpClientError,
    HttpStatusError,
    HttpTransportError,
)
from aisec_intel.connectors.kev import KevConnector
from aisec_intel.connectors.nvd import NvdConnector
from aisec_intel.connectors.openalex import OpenAlexConnector
from aisec_intel.connectors.osv import OsvConnector
from aisec_intel.connectors.rate_limiter import DEFAULT_RATE_LIMIT, RateLimiter, RateSpec
from aisec_intel.connectors.registry import (
    UnknownSourceError,
    available_sources,
    create_connector,
    get_connector_class,
    register,
)
from aisec_intel.connectors.rss_blog import RssBlogConnector
from aisec_intel.connectors.vendor_github import VendorGithubConnector

__all__ = [
    "DEFAULT_MAX_RETRIES",
    "DEFAULT_RATE_LIMIT",
    "DEFAULT_TIMEOUT_S",
    "ArxivConnector",
    "BaseConnector",
    "EpssConnector",
    "GhsaAuthError",
    "GhsaConnector",
    "GhsaError",
    "GhsaQueryError",
    "HttpClient",
    "HttpClientError",
    "HttpStatusError",
    "HttpTransportError",
    "KevConnector",
    "NvdConnector",
    "OpenAlexConnector",
    "OsvConnector",
    "RateLimiter",
    "RateSpec",
    "RssBlogConnector",
    "UnknownSourceError",
    "VendorGithubConnector",
    "available_sources",
    "create_connector",
    "get_connector_class",
    "register",
]


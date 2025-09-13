"""
Middleware components for Augments MCP Web Server
"""

from .smart_limiter import SmartRateLimiter
from .edge_cache import EdgeCacheMiddleware
from .cloudflare import CloudflareProtection
from .request_coalescer import RequestCoalescer
from .abuse_detector import AbuseDetector

__all__ = [
    "SmartRateLimiter",
    "EdgeCacheMiddleware",
    "CloudflareProtection",
    "RequestCoalescer",
    "AbuseDetector",
]
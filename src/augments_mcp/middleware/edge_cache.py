"""
Edge Cache Middleware
Aggressive caching at the edge to minimize backend load
"""

import json
import time
import hashlib
from typing import Optional, Dict, Any
from datetime import datetime, timedelta

import redis.asyncio as redis
import structlog
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

logger = structlog.get_logger(__name__)


class EdgeCacheMiddleware(BaseHTTPMiddleware):
    """Cache responses at edge to reduce backend load"""
    
    def __init__(
        self,
        app: ASGIApp,
        redis_client: redis.Redis,
        default_ttl: int = 300,
        max_cache_size: int = 10485760  # 10MB
    ):
        super().__init__(app)
        self.redis = redis_client
        self.default_ttl = default_ttl
        self.max_cache_size = max_cache_size
        
        # Cache configuration per endpoint pattern
        self.cache_config = {
            "/api/v1/frameworks": {"ttl": 3600, "vary": ["category"]},  # 1 hour
            "/api/v1/frameworks/*/info": {"ttl": 3600, "vary": []},  # 1 hour
            "/api/v1/frameworks/*/docs": {"ttl": 1800, "vary": ["section"]},  # 30 min
            "/api/v1/frameworks/*/examples": {"ttl": 1800, "vary": ["pattern"]},  # 30 min
            "/api/v1/search": {"ttl": 600, "vary": ["query", "framework"]},  # 10 min
            "/api/v1/cache/stats": {"ttl": 60, "vary": []},  # 1 min
            "/health": {"ttl": 10, "vary": []},  # 10 seconds
        }
    
    def _get_cache_config(self, path: str) -> Dict[str, Any]:
        """Get cache configuration for a given path"""
        # Direct match
        if path in self.cache_config:
            return self.cache_config[path]
        
        # Pattern match (with wildcards)
        for pattern, config in self.cache_config.items():
            if "*" in pattern:
                import re
                regex = pattern.replace("*", "[^/]+")
                if re.match(f"^{regex}$", path):
                    return config
        
        # Default config
        return {"ttl": self.default_ttl, "vary": []}
    
    async def _generate_cache_key(self, request: Request) -> str:
        """Generate cache key from request"""
        # Base components
        components = [
            request.method,
            request.url.path,
        ]
        
        # Add vary headers based on endpoint config
        config = self._get_cache_config(request.url.path)
        vary_params = config.get("vary", [])
        
        # Add query parameters that matter
        if request.url.query:
            query_params = dict(request.query_params)
            for param in vary_params:
                if param in query_params:
                    components.append(f"{param}:{query_params[param]}")
        
        # Add important headers for cache variation
        # CloudFlare geo-location for regional caching
        cf_country = request.headers.get("CF-IPCountry")
        if cf_country and cf_country != "XX":  # XX = unknown
            components.append(f"country:{cf_country}")
        
        # Create hash
        cache_str = "|".join(components)
        cache_hash = hashlib.md5(cache_str.encode()).hexdigest()
        
        return f"edge:{cache_hash}"
    
    async def _should_cache(self, request: Request, response: Response) -> bool:
        """Determine if response should be cached"""
        # Only cache GET requests
        if request.method != "GET":
            return False
        
        # Only cache successful responses
        if response.status_code != 200:
            return False
        
        # Check if endpoint is cacheable
        config = self._get_cache_config(request.url.path)
        if config.get("ttl", 0) <= 0:
            return False
        
        # Don't cache if client requests no-cache
        cache_control = request.headers.get("Cache-Control", "")
        if "no-cache" in cache_control or "no-store" in cache_control:
            return False
        
        # Check response size
        content_length = response.headers.get("Content-Length")
        if content_length and int(content_length) > self.max_cache_size:
            return False
        
        return True
    
    async def _get_cached_response(self, cache_key: str) -> Optional[Dict]:
        """Get cached response if available"""
        try:
            cached_data = await self.redis.get(cache_key)
            if cached_data:
                return json.loads(cached_data)
        except Exception as e:
            logger.error("Cache retrieval error", error=str(e))
        
        return None
    
    async def _cache_response(
        self,
        cache_key: str,
        response_data: Dict,
        ttl: int
    ):
        """Cache response data"""
        try:
            # Add cache metadata
            response_data["cached_at"] = time.time()
            response_data["ttl"] = ttl
            
            # Store in Redis
            await self.redis.setex(
                cache_key,
                ttl,
                json.dumps(response_data)
            )
            
            # Update cache statistics
            await self.redis.hincrby("cache:stats", "writes", 1)
            
        except Exception as e:
            logger.error("Cache storage error", error=str(e))
    
    async def dispatch(self, request: Request, call_next):
        """Process request with edge caching"""
        start_time = time.time()
        
        # Skip cache for non-GET requests
        if request.method != "GET":
            response = await call_next(request)
            return response
        
        # Generate cache key
        cache_key = await self._generate_cache_key(request)
        
        # Check if we should force cache (from CloudFlare protection)
        force_cache = getattr(request.state, "force_cache", False)
        
        # Try to get cached response
        cached_data = await self._get_cached_response(cache_key)
        
        if cached_data:
            # Serve from cache
            cache_age = int(time.time() - cached_data.get("cached_at", 0))
            max_age = cached_data.get("ttl", 300)
            
            # Update cache statistics
            await self.redis.hincrby("cache:stats", "hits", 1)
            
            # Track cache hit for rate limiting
            if hasattr(request.state, "rate_limit"):
                client_id = request.state.rate_limit.get("fingerprint")
                if client_id:
                    await self.redis.hincrby(f"usage:{client_id}", "cache_hits", 1)
            
            return JSONResponse(
                content=cached_data.get("content", {}),
                status_code=cached_data.get("status_code", 200),
                headers={
                    "X-Cache": "HIT",
                    "X-Cache-Age": str(cache_age),
                    "Cache-Control": f"public, max-age={max_age - cache_age}",
                    "X-Response-Time": str(int((time.time() - start_time) * 1000)),
                    # CloudFlare caching hints
                    "CF-Cache-Status": "HIT",
                    "CDN-Cache-Control": f"max-age={max_age}"
                }
            )
        
        # Cache miss - generate response
        response = await call_next(request)
        
        # Check if we should cache this response
        config = self._get_cache_config(request.url.path)
        ttl = config.get("ttl", self.default_ttl)
        
        if await self._should_cache(request, response):
            # Read response body
            body = b""
            async for chunk in response.body_iterator:
                body += chunk
            
            # Parse response
            try:
                content = json.loads(body)
                
                # Cache the response
                await self._cache_response(
                    cache_key,
                    {
                        "content": content,
                        "status_code": response.status_code,
                        "headers": dict(response.headers)
                    },
                    ttl
                )
                
                # Update statistics
                await self.redis.hincrby("cache:stats", "misses", 1)
                
            except json.JSONDecodeError:
                # Non-JSON response, don't cache
                pass
            
            # Return response with cache headers
            return Response(
                content=body,
                status_code=response.status_code,
                headers={
                    **dict(response.headers),
                    "X-Cache": "MISS",
                    "Cache-Control": f"public, max-age={ttl}",
                    "X-Response-Time": str(int((time.time() - start_time) * 1000)),
                    # CloudFlare caching hints
                    "CF-Cache-Status": "MISS",
                    "CDN-Cache-Control": f"max-age={ttl * 2}"  # CDN caches longer
                },
                media_type=response.headers.get("content-type")
            )
        
        # Non-cacheable response
        response.headers["X-Cache"] = "BYPASS"
        response.headers["Cache-Control"] = "no-cache"
        response.headers["X-Response-Time"] = str(int((time.time() - start_time) * 1000))
        
        return response
    
    async def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        stats = await self.redis.hgetall("cache:stats")
        
        # Convert bytes to int
        hits = int(stats.get(b"hits", 0))
        misses = int(stats.get(b"misses", 0))
        writes = int(stats.get(b"writes", 0))
        
        total_requests = hits + misses
        hit_rate = (hits / total_requests * 100) if total_requests > 0 else 0
        
        # Get cache size
        cache_keys = await self.redis.keys("edge:*")
        cache_size = len(cache_keys)
        
        # Estimate memory usage
        if cache_keys:
            sample_sizes = []
            for key in cache_keys[:10]:  # Sample first 10
                value = await self.redis.get(key)
                if value:
                    sample_sizes.append(len(value))
            
            avg_size = sum(sample_sizes) / len(sample_sizes) if sample_sizes else 0
            estimated_memory = int(avg_size * cache_size)
        else:
            estimated_memory = 0
        
        return {
            "hits": hits,
            "misses": misses,
            "writes": writes,
            "hit_rate": f"{hit_rate:.2f}%",
            "total_requests": total_requests,
            "cached_items": cache_size,
            "estimated_memory_bytes": estimated_memory,
            "estimated_memory_mb": f"{estimated_memory / 1024 / 1024:.2f}"
        }
    
    async def clear_cache(self, pattern: Optional[str] = None):
        """Clear cache entries"""
        if pattern:
            keys = await self.redis.keys(f"edge:*{pattern}*")
        else:
            keys = await self.redis.keys("edge:*")
        
        if keys:
            await self.redis.delete(*keys)
            logger.info(f"Cleared {len(keys)} cache entries")
        
        # Reset statistics
        await self.redis.delete("cache:stats")
        
        return len(keys)
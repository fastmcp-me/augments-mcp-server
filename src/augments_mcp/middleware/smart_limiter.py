"""
Smart Rate Limiting Middleware
Progressive rate limiting based on client behavior without requiring API keys
"""

import hashlib
import time
from typing import Optional, Dict
from datetime import datetime, timedelta

import redis.asyncio as redis
import structlog
from fastapi import Request, HTTPException, status
from slowapi import Limiter
from slowapi.util import get_remote_address

logger = structlog.get_logger(__name__)


class SmartRateLimiter:
    """Intelligent rate limiting that adapts to usage patterns"""
    
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client
        self.limiter = Limiter(
            key_func=self.get_client_identifier,
            storage_uri=None  # We'll handle storage manually
        )
        
        # Define tier limits
        self.tier_limits = {
            "good": {"per_minute": 60, "per_hour": 1000, "burst": 10},
            "normal": {"per_minute": 30, "per_hour": 500, "burst": 5},
            "restricted": {"per_minute": 10, "per_hour": 100, "burst": 2},
            "blocked": {"per_minute": 0, "per_hour": 0, "burst": 0}
        }
    
    async def get_client_fingerprint(self, request: Request) -> str:
        """Create unique fingerprint without API keys"""
        components = [
            get_remote_address(request) or "unknown",
            request.headers.get("User-Agent", ""),
            request.headers.get("Accept-Language", ""),
            request.headers.get("Accept-Encoding", ""),
            # CloudFlare headers if available
            request.headers.get("CF-IPCountry", ""),
            request.headers.get("CF-Ray", ""),
        ]
        
        fingerprint_str = "|".join(components)
        return hashlib.sha256(fingerprint_str.encode()).hexdigest()[:16]
    
    def get_client_identifier(self, request: Request) -> str:
        """Get client identifier for rate limiting"""
        # Try CloudFlare IP first (most accurate)
        cf_ip = request.headers.get("CF-Connecting-IP")
        if cf_ip:
            return f"cf:{cf_ip}"
        
        # Fall back to regular IP
        return f"ip:{get_remote_address(request) or 'unknown'}"
    
    async def get_client_tier(self, client_id: str) -> str:
        """Determine client tier based on usage history"""
        # Check if blocked
        if await self.redis.exists(f"blocked:{client_id}"):
            return "blocked"
        
        # Check if throttled
        if await self.redis.exists(f"throttled:{client_id}"):
            return "restricted"
        
        # Get usage score
        usage_data = await self.redis.hgetall(f"usage:{client_id}")
        if not usage_data:
            # New client starts as normal
            return "normal"
        
        score = int(usage_data.get(b"score", 0))
        errors = int(usage_data.get(b"errors", 0))
        requests = int(usage_data.get(b"requests", 0))
        
        # Calculate tier based on behavior
        if errors > 50 or score > 1000:
            return "restricted"
        elif score < 0 or (requests > 10 and errors == 0):
            return "good"  # Reward good behavior
        else:
            return "normal"
    
    async def track_request(
        self, 
        client_id: str, 
        request: Request,
        response_status: int,
        response_time: float,
        cache_hit: bool = False
    ):
        """Track request for behavior analysis"""
        pipe = self.redis.pipeline()
        
        # Increment request counter
        pipe.hincrby(f"usage:{client_id}", "requests", 1)
        
        # Track response times
        if response_time > 5.0:  # Slow request
            pipe.hincrby(f"usage:{client_id}", "score", 10)
        elif response_time < 0.1:  # Fast (likely cached)
            pipe.hincrby(f"usage:{client_id}", "score", -1)
        
        # Track errors
        if 400 <= response_status < 500:
            pipe.hincrby(f"usage:{client_id}", "errors", 1)
            pipe.hincrby(f"usage:{client_id}", "score", 5)
        elif response_status >= 500:
            # Don't penalize for server errors
            pass
        elif cache_hit:
            # Reward cache usage
            pipe.hincrby(f"usage:{client_id}", "score", -2)
        
        # Track request patterns
        pipe.lpush(f"paths:{client_id}", request.url.path)
        pipe.ltrim(f"paths:{client_id}", 0, 50)  # Keep last 50 paths
        
        # Set expiry
        pipe.expire(f"usage:{client_id}", 3600)  # Reset hourly
        pipe.expire(f"paths:{client_id}", 3600)
        
        await pipe.execute()
    
    async def check_burst_protection(self, client_id: str) -> bool:
        """Check if client is within burst limits"""
        tier = await self.get_client_tier(client_id)
        burst_limit = self.tier_limits[tier]["burst"]
        
        if burst_limit == 0:
            return False
        
        # Count requests in last 5 seconds
        now = time.time()
        burst_key = f"burst:{client_id}"
        
        # Clean old entries and count recent
        pipe = self.redis.pipeline()
        pipe.zremrangebyscore(burst_key, 0, now - 5)
        pipe.zadd(burst_key, {str(now): now})
        pipe.zcard(burst_key)
        pipe.expire(burst_key, 10)
        results = await pipe.execute()
        
        burst_count = results[2]
        return burst_count <= burst_limit
    
    async def check_rate_limit(self, request: Request) -> tuple[bool, str, Dict]:
        """Check if request should be rate limited"""
        client_id = self.get_client_identifier(request)
        fingerprint = await self.get_client_fingerprint(request)
        
        # Get client tier
        tier = await self.get_client_tier(client_id)
        limits = self.tier_limits[tier]
        
        if tier == "blocked":
            return False, "Client is blocked due to abuse", {}
        
        # Check burst protection
        if not await self.check_burst_protection(client_id):
            # Temporarily throttle
            await self.redis.setex(f"throttled:{client_id}", 60, "burst_exceeded")
            return False, "Burst limit exceeded", {"retry_after": 60}
        
        # Check minute rate
        minute_key = f"rate:min:{client_id}"
        minute_count = await self.redis.incr(minute_key)
        if minute_count == 1:
            await self.redis.expire(minute_key, 60)
        
        if minute_count > limits["per_minute"]:
            return False, f"Rate limit exceeded: {limits['per_minute']}/min", {
                "limit": limits["per_minute"],
                "remaining": 0,
                "reset": 60
            }
        
        # Check hourly rate
        hour_key = f"rate:hour:{client_id}"
        hour_count = await self.redis.incr(hour_key)
        if hour_count == 1:
            await self.redis.expire(hour_key, 3600)
        
        if hour_count > limits["per_hour"]:
            return False, f"Hourly limit exceeded: {limits['per_hour']}/hour", {
                "limit": limits["per_hour"],
                "remaining": 0,
                "reset": 3600
            }
        
        # Return success with metadata
        return True, "OK", {
            "tier": tier,
            "limit": limits["per_minute"],
            "remaining": limits["per_minute"] - minute_count,
            "reset": 60,
            "fingerprint": fingerprint
        }
    
    async def analyze_patterns(self, client_id: str) -> Optional[str]:
        """Analyze request patterns for suspicious behavior"""
        paths = await self.redis.lrange(f"paths:{client_id}", 0, 20)
        
        if not paths:
            return None
        
        # Convert bytes to strings
        paths = [p.decode() if isinstance(p, bytes) else p for p in paths]
        
        # Pattern 1: Sequential scanning
        if self._is_sequential_scan(paths):
            return "sequential_scanning"
        
        # Pattern 2: Rapid enumeration
        if len(set(paths)) > 15:  # Many different endpoints quickly
            return "rapid_enumeration"
        
        # Pattern 3: Repeated failures
        usage_data = await self.redis.hgetall(f"usage:{client_id}")
        if usage_data:
            errors = int(usage_data.get(b"errors", 0))
            requests = int(usage_data.get(b"requests", 0))
            if requests > 10 and errors / requests > 0.5:
                return "high_error_rate"
        
        return None
    
    def _is_sequential_scan(self, paths: list) -> bool:
        """Detect sequential scanning patterns"""
        # Check for incrementing IDs or sequential paths
        numbers = []
        for path in paths:
            # Extract numbers from paths
            import re
            nums = re.findall(r'\d+', path)
            if nums:
                numbers.extend([int(n) for n in nums])
        
        if len(numbers) > 5:
            # Check if numbers are sequential
            sorted_nums = sorted(set(numbers))
            if len(sorted_nums) > 3:
                diffs = [sorted_nums[i+1] - sorted_nums[i] for i in range(len(sorted_nums)-1)]
                if all(d == 1 for d in diffs[:3]):  # At least 3 sequential
                    return True
        
        return False
    
    async def __call__(self, request: Request) -> Dict:
        """Middleware entry point"""
        allowed, message, metadata = await self.check_rate_limit(request)
        
        if not allowed:
            # Log rate limit exceeded
            client_id = self.get_client_identifier(request)
            logger.warning(
                "Rate limit exceeded",
                client_id=client_id,
                path=request.url.path,
                message=message
            )
            
            # Check for patterns and potentially block
            pattern = await self.analyze_patterns(client_id)
            if pattern:
                logger.warning(
                    "Suspicious pattern detected",
                    client_id=client_id,
                    pattern=pattern
                )
                if pattern in ["sequential_scanning", "rapid_enumeration"]:
                    await self.redis.setex(f"blocked:{client_id}", 3600, pattern)
            
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=message,
                headers={
                    "X-RateLimit-Limit": str(metadata.get("limit", 0)),
                    "X-RateLimit-Remaining": str(metadata.get("remaining", 0)),
                    "X-RateLimit-Reset": str(metadata.get("reset", 60)),
                    "Retry-After": str(metadata.get("retry_after", 60))
                }
            )
        
        # Add metadata to request state
        request.state.rate_limit = metadata
        return metadata
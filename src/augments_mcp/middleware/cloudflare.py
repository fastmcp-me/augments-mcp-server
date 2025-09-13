"""
CloudFlare Protection Middleware
Leverage CloudFlare's free protection and bot detection
"""

import os
import time
from typing import Optional, Dict
from ipaddress import ip_address, ip_network

import structlog
from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

logger = structlog.get_logger(__name__)


class CloudflareProtection(BaseHTTPMiddleware):
    """Leverage CloudFlare's protection and bot detection"""
    
    # CloudFlare IP ranges (update periodically from https://www.cloudflare.com/ips/)
    CLOUDFLARE_IPS = [
        "173.245.48.0/20",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "141.101.64.0/18",
        "108.162.192.0/18",
        "190.93.240.0/20",
        "188.114.96.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "162.158.0.0/15",
        "104.16.0.0/13",
        "104.24.0.0/14",
        "172.64.0.0/13",
        "131.0.72.0/22"
    ]
    
    def __init__(
        self,
        app: ASGIApp,
        enforce_cloudflare: bool = None,
        block_direct_access: bool = None,
        trust_bot_score: bool = True,
        min_bot_score: int = 30
    ):
        super().__init__(app)
        
        # Configuration from environment or parameters
        self.enforce_cloudflare = enforce_cloudflare if enforce_cloudflare is not None else \
            os.getenv("ENFORCE_CLOUDFLARE", "false").lower() == "true"
        
        self.block_direct_access = block_direct_access if block_direct_access is not None else \
            os.getenv("BLOCK_DIRECT_ACCESS", "false").lower() == "true"
        
        self.trust_bot_score = trust_bot_score
        self.min_bot_score = min_bot_score
        
        # Parse CloudFlare IP ranges
        self.cf_networks = [ip_network(cidr) for cidr in self.CLOUDFLARE_IPS]
    
    def _is_cloudflare_ip(self, ip: str) -> bool:
        """Check if IP belongs to CloudFlare"""
        try:
            addr = ip_address(ip)
            return any(addr in network for network in self.cf_networks)
        except ValueError:
            return False
    
    def _get_real_ip(self, request: Request) -> str:
        """Get the real client IP"""
        # CloudFlare provides the real IP
        cf_connecting_ip = request.headers.get("CF-Connecting-IP")
        if cf_connecting_ip:
            return cf_connecting_ip
        
        # Fallback to X-Forwarded-For
        x_forwarded_for = request.headers.get("X-Forwarded-For")
        if x_forwarded_for:
            # Take the first IP (original client)
            return x_forwarded_for.split(",")[0].strip()
        
        # Fallback to X-Real-IP
        x_real_ip = request.headers.get("X-Real-IP")
        if x_real_ip:
            return x_real_ip
        
        # Last resort - direct connection IP
        if request.client:
            return request.client.host
        
        return "unknown"
    
    def _extract_cf_metadata(self, request: Request) -> Dict:
        """Extract CloudFlare metadata from headers"""
        return {
            "ray_id": request.headers.get("CF-RAY"),
            "country": request.headers.get("CF-IPCountry"),
            "colo": request.headers.get("CF-Colo"),  # CloudFlare datacenter
            "bot_score": request.headers.get("CF-Bot-Score"),
            "threat_score": request.headers.get("CF-Threat-Score"),
            "verified_bot": request.headers.get("CF-Verified-Bot-Flag") == "1",
            "is_tor": request.headers.get("CF-IPCountry") == "T1",  # Tor exit node
            "cache_status": request.headers.get("CF-Cache-Status"),
            "worker": request.headers.get("CF-Worker"),
            "connecting_ip": request.headers.get("CF-Connecting-IP")
        }
    
    async def _check_bot_score(self, cf_metadata: Dict) -> tuple[bool, str]:
        """Check CloudFlare bot score"""
        bot_score = cf_metadata.get("bot_score")
        
        if not bot_score:
            # No bot score available
            return True, "no_score"
        
        try:
            score = int(bot_score)
        except (ValueError, TypeError):
            return True, "invalid_score"
        
        # CloudFlare bot scores:
        # 1-29: Likely automated
        # 30-99: Likely human
        # 100: Verified bot (like Googlebot)
        
        if cf_metadata.get("verified_bot"):
            # Allow verified bots (search engines, etc.)
            return True, "verified_bot"
        
        if score < self.min_bot_score:
            # Likely automated - restrict access
            return False, f"bot_score_{score}"
        
        return True, f"human_{score}"
    
    async def _check_threat_score(self, cf_metadata: Dict) -> tuple[bool, int]:
        """Check CloudFlare threat score"""
        threat_score = cf_metadata.get("threat_score")
        
        if not threat_score:
            return True, 0
        
        try:
            score = int(threat_score)
        except (ValueError, TypeError):
            return True, 0
        
        # CloudFlare threat scores:
        # 0-10: Low risk
        # 11-25: Medium risk
        # 26-50: High risk
        # 51-100: Very high risk
        
        if score > 50:
            # Very high risk - block
            return False, score
        
        return True, score
    
    async def dispatch(self, request: Request, call_next):
        """Process request with CloudFlare protection"""
        # Extract CloudFlare metadata
        cf_metadata = self._extract_cf_metadata(request)
        
        # Get real client IP
        real_ip = self._get_real_ip(request)
        
        # Store in request state for other middleware
        request.state.cf_metadata = cf_metadata
        request.state.real_ip = real_ip
        
        # Check if request came through CloudFlare
        cf_ray = cf_metadata.get("ray_id")
        is_via_cloudflare = bool(cf_ray)
        
        # Log request info
        logger.debug(
            "CloudFlare request",
            real_ip=real_ip,
            country=cf_metadata.get("country"),
            ray_id=cf_ray,
            bot_score=cf_metadata.get("bot_score"),
            via_cf=is_via_cloudflare
        )
        
        # Enforce CloudFlare if configured
        if self.enforce_cloudflare and not is_via_cloudflare:
            # Check if it's from CloudFlare IP (health checks, etc.)
            if request.client and self._is_cloudflare_ip(request.client.host):
                # Allow CloudFlare infrastructure requests
                pass
            elif self.block_direct_access:
                logger.warning(
                    "Direct access blocked",
                    ip=real_ip,
                    path=request.url.path
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Direct access not allowed. Please use the official domain."
                )
        
        # Check bot score if available
        if self.trust_bot_score and cf_metadata.get("bot_score"):
            allowed, bot_type = await self._check_bot_score(cf_metadata)
            
            if not allowed:
                # Likely a bot - serve from cache only
                request.state.force_cache = True
                request.state.bot_restricted = True
                
                logger.info(
                    "Bot detected - restricting access",
                    ip=real_ip,
                    bot_type=bot_type,
                    bot_score=cf_metadata.get("bot_score")
                )
        
        # Check threat score
        safe, threat_score = await self._check_threat_score(cf_metadata)
        if not safe:
            logger.warning(
                "High threat score - blocking",
                ip=real_ip,
                threat_score=threat_score
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied due to security risk"
            )
        
        # Check if from Tor
        if cf_metadata.get("is_tor"):
            # Tor users get restricted access
            request.state.force_cache = True
            request.state.tor_user = True
            logger.info("Tor user detected", ip=real_ip)
        
        # Process request
        response = await call_next(request)
        
        # Add CloudFlare headers to response
        if is_via_cloudflare:
            response.headers["CF-Cache-Control"] = "public, max-age=3600"
            response.headers["CF-Edge-Cache"] = "cache, platform=augments"
            
            # Add security headers
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["X-XSS-Protection"] = "1; mode=block"
            response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
            
            # Add country-specific headers for analytics
            country = cf_metadata.get("country")
            if country and country != "XX":
                response.headers["X-Country"] = country
        
        return response
    
    async def get_protection_stats(self, redis_client) -> Dict:
        """Get protection statistics"""
        stats_key = "cf:protection:stats"
        stats = await redis_client.hgetall(stats_key)
        
        return {
            "requests_via_cf": int(stats.get(b"via_cf", 0)),
            "direct_requests": int(stats.get(b"direct", 0)),
            "bots_detected": int(stats.get(b"bots", 0)),
            "threats_blocked": int(stats.get(b"threats", 0)),
            "tor_users": int(stats.get(b"tor", 0)),
            "countries": await redis_client.scard("cf:countries")
        }
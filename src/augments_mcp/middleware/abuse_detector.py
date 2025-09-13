"""
Abuse Detection System
Identify and block abusive usage patterns
"""

import time
import re
from typing import Dict, List, Optional, Tuple
from collections import defaultdict
from datetime import datetime, timedelta

import redis.asyncio as redis
import structlog
from fastapi import Request

logger = structlog.get_logger(__name__)


class AbuseDetector:
    """Detect and prevent abusive usage patterns"""
    
    # Suspicious patterns
    SCANNING_PATTERNS = [
        r"/api/v1/frameworks/\w+/docs.*[0-9]{3,}",  # Sequential IDs
        r".*test.*test.*test",  # Repeated test patterns
        r".*\.\./.*",  # Path traversal attempts
        r".*<script.*>.*",  # XSS attempts
        r".*union.*select.*",  # SQL injection attempts
    ]
    
    # User agent patterns that might indicate bots
    SUSPICIOUS_USER_AGENTS = [
        r".*python.*requests.*",  # Python requests library
        r".*curl.*",  # curl command
        r".*wget.*",  # wget command
        r".*scrapy.*",  # Scrapy crawler
        r".*bot.*",  # Generic bot pattern
        r".*crawler.*",  # Generic crawler
        r".*spider.*",  # Spider pattern
    ]
    
    # Legitimate bot user agents (don't block these)
    ALLOWED_BOTS = [
        r".*googlebot.*",
        r".*bingbot.*",
        r".*slackbot.*",
        r".*discordbot.*",
        r".*twitterbot.*",
    ]
    
    def __init__(
        self,
        redis_client: redis.Redis,
        sensitivity: str = "medium"
    ):
        """
        Initialize abuse detector
        
        Args:
            redis_client: Redis client for tracking
            sensitivity: Detection sensitivity (low, medium, high)
        """
        self.redis = redis_client
        self.sensitivity = sensitivity
        
        # Thresholds based on sensitivity
        self.thresholds = {
            "low": {
                "max_404_per_minute": 20,
                "max_unique_paths_per_minute": 50,
                "max_errors_per_minute": 30,
                "sequential_threshold": 10,
                "rapid_fire_ms": 50
            },
            "medium": {
                "max_404_per_minute": 10,
                "max_unique_paths_per_minute": 30,
                "max_errors_per_minute": 15,
                "sequential_threshold": 5,
                "rapid_fire_ms": 100
            },
            "high": {
                "max_404_per_minute": 5,
                "max_unique_paths_per_minute": 20,
                "max_errors_per_minute": 10,
                "sequential_threshold": 3,
                "rapid_fire_ms": 200
            }
        }
        
        self.current_thresholds = self.thresholds[sensitivity]
        
        # Pattern matchers
        self.scanning_regex = [re.compile(p, re.IGNORECASE) for p in self.SCANNING_PATTERNS]
        self.suspicious_ua_regex = [re.compile(p, re.IGNORECASE) for p in self.SUSPICIOUS_USER_AGENTS]
        self.allowed_bot_regex = [re.compile(p, re.IGNORECASE) for p in self.ALLOWED_BOTS]
    
    async def check_request(
        self,
        request: Request,
        client_id: str
    ) -> Tuple[bool, Optional[str]]:
        """
        Check request for abusive patterns
        
        Args:
            request: FastAPI request object
            client_id: Client identifier
        
        Returns:
            Tuple of (is_allowed, reason_if_blocked)
        """
        # Check if already blocked
        if await self.redis.exists(f"abuse:blocked:{client_id}"):
            reason = await self.redis.get(f"abuse:blocked:{client_id}")
            return False, f"Blocked: {reason}"
        
        # Check user agent
        user_agent = request.headers.get("User-Agent", "")
        ua_check = self._check_user_agent(user_agent)
        if not ua_check[0]:
            await self._record_suspicious_activity(client_id, "suspicious_ua", user_agent)
            # Don't immediately block, but track
        
        # Check path patterns
        path = request.url.path
        if self._is_suspicious_path(path):
            await self._record_suspicious_activity(client_id, "suspicious_path", path)
            return False, "Suspicious request pattern detected"
        
        # Check rapid-fire requests
        is_rapid = await self._check_rapid_fire(client_id)
        if is_rapid:
            await self._temporary_throttle(client_id, 60, "rapid_fire")
            return False, "Too many rapid requests"
        
        # Check 404 rate
        four_oh_four_rate = await self._check_404_rate(client_id)
        if four_oh_four_rate:
            await self._temporary_throttle(client_id, 300, "high_404_rate")
            return False, "Too many not found errors"
        
        # Check path diversity (scanning detection)
        is_scanning = await self._check_scanning_behavior(client_id, path)
        if is_scanning:
            await self._block_client(client_id, 3600, "scanning_detected")
            return False, "Scanning behavior detected"
        
        # Check error rate
        high_errors = await self._check_error_rate(client_id)
        if high_errors:
            await self._temporary_throttle(client_id, 180, "high_error_rate")
            return False, "Too many errors"
        
        # Track the request
        await self._track_request(client_id, path)
        
        return True, None
    
    def _check_user_agent(self, user_agent: str) -> Tuple[bool, str]:
        """Check if user agent is suspicious"""
        if not user_agent:
            return True, "no_user_agent"
        
        # Check if it's an allowed bot
        for pattern in self.allowed_bot_regex:
            if pattern.match(user_agent):
                return True, "allowed_bot"
        
        # Check if it's suspicious
        for pattern in self.suspicious_ua_regex:
            if pattern.match(user_agent):
                return False, "suspicious_ua"
        
        return True, "normal"
    
    def _is_suspicious_path(self, path: str) -> bool:
        """Check if path matches suspicious patterns"""
        for pattern in self.scanning_regex:
            if pattern.match(path):
                return True
        
        # Check for obvious attack patterns
        suspicious_keywords = [
            "../../", "../",  # Path traversal
            "<script", "javascript:",  # XSS
            "union select", "drop table",  # SQL injection
            "eval(", "exec(",  # Code execution
            ".env", ".git", ".config",  # Sensitive files
            "wp-admin", "phpmyadmin",  # Common targets
        ]
        
        path_lower = path.lower()
        return any(keyword in path_lower for keyword in suspicious_keywords)
    
    async def _check_rapid_fire(self, client_id: str) -> bool:
        """Check for rapid-fire requests"""
        now_ms = int(time.time() * 1000)
        last_request_key = f"abuse:last_request:{client_id}"
        
        last_request = await self.redis.get(last_request_key)
        if last_request:
            time_diff = now_ms - int(last_request)
            if time_diff < self.current_thresholds["rapid_fire_ms"]:
                return True
        
        # Update last request time
        await self.redis.setex(last_request_key, 60, str(now_ms))
        return False
    
    async def _check_404_rate(self, client_id: str) -> bool:
        """Check rate of 404 errors"""
        key = f"abuse:404:{client_id}"
        count = await self.redis.incr(key)
        
        if count == 1:
            await self.redis.expire(key, 60)
        
        return count > self.current_thresholds["max_404_per_minute"]
    
    async def _check_scanning_behavior(self, client_id: str, path: str) -> bool:
        """Detect scanning/enumeration behavior"""
        paths_key = f"abuse:paths:{client_id}"
        
        # Add current path
        await self.redis.sadd(paths_key, path)
        await self.redis.expire(paths_key, 60)
        
        # Count unique paths in last minute
        unique_paths = await self.redis.scard(paths_key)
        
        if unique_paths > self.current_thresholds["max_unique_paths_per_minute"]:
            # Check if paths are sequential
            paths = await self.redis.smembers(paths_key)
            if self._detect_sequential_pattern(paths):
                return True
        
        return False
    
    def _detect_sequential_pattern(self, paths: set) -> bool:
        """Detect sequential scanning in paths"""
        # Extract numbers from paths
        numbers = []
        for path in paths:
            path_str = path.decode() if isinstance(path, bytes) else path
            nums = re.findall(r'\d+', path_str)
            numbers.extend([int(n) for n in nums if n.isdigit()])
        
        if len(numbers) < self.current_thresholds["sequential_threshold"]:
            return False
        
        # Check for sequential patterns
        sorted_nums = sorted(set(numbers))
        sequential_count = 0
        
        for i in range(len(sorted_nums) - 1):
            if sorted_nums[i + 1] - sorted_nums[i] == 1:
                sequential_count += 1
                if sequential_count >= self.current_thresholds["sequential_threshold"]:
                    return True
            else:
                sequential_count = 0
        
        return False
    
    async def _check_error_rate(self, client_id: str) -> bool:
        """Check overall error rate"""
        key = f"abuse:errors:{client_id}"
        count = await self.redis.incr(key)
        
        if count == 1:
            await self.redis.expire(key, 60)
        
        return count > self.current_thresholds["max_errors_per_minute"]
    
    async def _track_request(self, client_id: str, path: str):
        """Track request for analysis"""
        # Add to request history
        history_key = f"abuse:history:{client_id}"
        await self.redis.lpush(history_key, f"{time.time()}:{path}")
        await self.redis.ltrim(history_key, 0, 100)  # Keep last 100 requests
        await self.redis.expire(history_key, 3600)
    
    async def _record_suspicious_activity(
        self,
        client_id: str,
        activity_type: str,
        details: str
    ):
        """Record suspicious activity"""
        key = f"abuse:suspicious:{client_id}"
        await self.redis.hincrby(key, activity_type, 1)
        await self.redis.expire(key, 3600)
        
        # Log the activity
        logger.warning(
            "Suspicious activity detected",
            client_id=client_id,
            activity_type=activity_type,
            details=details
        )
    
    async def _temporary_throttle(
        self,
        client_id: str,
        duration: int,
        reason: str
    ):
        """Temporarily throttle a client"""
        key = f"abuse:throttled:{client_id}"
        await self.redis.setex(key, duration, reason)
        
        logger.info(
            "Client throttled",
            client_id=client_id,
            duration=duration,
            reason=reason
        )
    
    async def _block_client(
        self,
        client_id: str,
        duration: int,
        reason: str
    ):
        """Block a client"""
        key = f"abuse:blocked:{client_id}"
        await self.redis.setex(key, duration, reason)
        
        # Add to blocklist
        await self.redis.sadd("abuse:blocklist", client_id)
        
        logger.warning(
            "Client blocked",
            client_id=client_id,
            duration=duration,
            reason=reason
        )
    
    async def track_response(
        self,
        client_id: str,
        status_code: int,
        response_time: float
    ):
        """Track response for pattern analysis"""
        if status_code == 404:
            await self.redis.incr(f"abuse:404:{client_id}")
        elif 400 <= status_code < 500:
            await self.redis.incr(f"abuse:errors:{client_id}")
    
    async def get_client_risk_score(self, client_id: str) -> Dict:
        """Get risk score for a client"""
        suspicious = await self.redis.hgetall(f"abuse:suspicious:{client_id}")
        
        # Calculate risk score
        risk_score = 0
        factors = []
        
        if suspicious:
            for activity, count in suspicious.items():
                activity_str = activity.decode() if isinstance(activity, bytes) else activity
                count_int = int(count)
                
                if activity_str == "suspicious_ua":
                    risk_score += count_int * 5
                    factors.append(f"Suspicious user agent ({count_int}x)")
                elif activity_str == "suspicious_path":
                    risk_score += count_int * 10
                    factors.append(f"Suspicious paths ({count_int}x)")
                elif activity_str == "rapid_fire":
                    risk_score += count_int * 3
                    factors.append(f"Rapid requests ({count_int}x)")
        
        # Check if blocked or throttled
        if await self.redis.exists(f"abuse:blocked:{client_id}"):
            risk_score += 100
            factors.append("Currently blocked")
        elif await self.redis.exists(f"abuse:throttled:{client_id}"):
            risk_score += 50
            factors.append("Currently throttled")
        
        return {
            "client_id": client_id,
            "risk_score": risk_score,
            "risk_level": self._get_risk_level(risk_score),
            "factors": factors
        }
    
    def _get_risk_level(self, score: int) -> str:
        """Convert risk score to level"""
        if score >= 100:
            return "critical"
        elif score >= 50:
            return "high"
        elif score >= 20:
            return "medium"
        elif score >= 10:
            return "low"
        else:
            return "minimal"
    
    async def get_abuse_stats(self) -> Dict:
        """Get abuse detection statistics"""
        blocklist = await self.redis.smembers("abuse:blocklist")
        
        return {
            "blocked_clients": len(blocklist),
            "sensitivity": self.sensitivity,
            "thresholds": self.current_thresholds
        }
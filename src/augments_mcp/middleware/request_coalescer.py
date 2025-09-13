"""
Request Coalescing System
Combine duplicate requests to prevent redundant work
"""

import asyncio
import time
import hashlib
from typing import Dict, Any, Optional, Callable
from functools import wraps

import structlog

logger = structlog.get_logger(__name__)


class RequestCoalescer:
    """Coalesce duplicate requests into single operations"""
    
    def __init__(self, ttl: int = 5):
        """
        Initialize request coalescer
        
        Args:
            ttl: Time to live for pending requests in seconds
        """
        self.pending_requests: Dict[str, asyncio.Future] = {}
        self.request_metadata: Dict[str, Dict] = {}
        self.ttl = ttl
        
        # Statistics
        self.stats = {
            "coalesced": 0,
            "unique": 0,
            "errors": 0,
            "timeouts": 0
        }
    
    def _generate_key(self, prefix: str, *args, **kwargs) -> str:
        """Generate unique key for request"""
        # Create string representation of arguments
        key_parts = [prefix]
        
        # Add positional arguments
        for arg in args:
            if isinstance(arg, (str, int, float, bool)):
                key_parts.append(str(arg))
            elif isinstance(arg, (list, tuple)):
                key_parts.append("|".join(str(x) for x in arg))
            elif isinstance(arg, dict):
                # Sort dict keys for consistent hashing
                sorted_items = sorted(arg.items())
                key_parts.append("|".join(f"{k}:{v}" for k, v in sorted_items))
            else:
                # Hash complex objects
                key_parts.append(hashlib.md5(str(arg).encode()).hexdigest()[:8])
        
        # Add keyword arguments (sorted for consistency)
        for key, value in sorted(kwargs.items()):
            key_parts.append(f"{key}={value}")
        
        return ":".join(key_parts)
    
    async def coalesce(
        self,
        key: str,
        func: Callable,
        *args,
        **kwargs
    ) -> Any:
        """
        Coalesce duplicate requests
        
        Args:
            key: Unique key for this request
            func: Async function to execute
            *args: Function arguments
            **kwargs: Function keyword arguments
        
        Returns:
            Function result (shared across coalesced requests)
        """
        # Check if request is already pending
        if key in self.pending_requests:
            # Wait for existing request
            self.stats["coalesced"] += 1
            
            logger.debug(
                "Coalescing request",
                key=key,
                waiters=len(self.request_metadata.get(key, {}).get("waiters", []))
            )
            
            # Add to waiters count
            if key in self.request_metadata:
                self.request_metadata[key]["waiters"] += 1
            
            try:
                # Wait for the result with timeout
                result = await asyncio.wait_for(
                    self.pending_requests[key],
                    timeout=self.ttl * 2  # Double TTL for safety
                )
                return result
            except asyncio.TimeoutError:
                self.stats["timeouts"] += 1
                logger.warning("Coalesced request timeout", key=key)
                # Fall through to execute independently
        
        # Create new future for this request
        future = asyncio.create_future()
        self.pending_requests[key] = future
        self.request_metadata[key] = {
            "started_at": time.time(),
            "waiters": 1
        }
        
        # Track unique requests
        self.stats["unique"] += 1
        
        try:
            # Execute the function
            start_time = time.time()
            result = await func(*args, **kwargs)
            
            # Set result for all waiters
            if not future.done():
                future.set_result(result)
            
            # Log if multiple waiters benefited
            metadata = self.request_metadata.get(key, {})
            if metadata.get("waiters", 1) > 1:
                logger.info(
                    "Coalesced request completed",
                    key=key,
                    waiters=metadata["waiters"],
                    duration=time.time() - start_time
                )
            
            return result
            
        except Exception as e:
            # Set exception for all waiters
            self.stats["errors"] += 1
            
            if not future.done():
                future.set_exception(e)
            
            logger.error(
                "Coalesced request failed",
                key=key,
                error=str(e)
            )
            raise
            
        finally:
            # Clean up after TTL
            asyncio.create_task(self._cleanup_request(key))
    
    async def _cleanup_request(self, key: str):
        """Clean up request after TTL"""
        await asyncio.sleep(self.ttl)
        
        # Remove from pending requests
        self.pending_requests.pop(key, None)
        self.request_metadata.pop(key, None)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get coalescing statistics"""
        total = self.stats["unique"] + self.stats["coalesced"]
        
        return {
            "total_requests": total,
            "unique_requests": self.stats["unique"],
            "coalesced_requests": self.stats["coalesced"],
            "coalesce_ratio": f"{(self.stats['coalesced'] / total * 100):.2f}%" if total > 0 else "0%",
            "errors": self.stats["errors"],
            "timeouts": self.stats["timeouts"],
            "pending": len(self.pending_requests)
        }
    
    def reset_stats(self):
        """Reset statistics"""
        self.stats = {
            "coalesced": 0,
            "unique": 0,
            "errors": 0,
            "timeouts": 0
        }


def coalesce_endpoint(
    key_prefix: str = None,
    ttl: int = 5,
    key_params: list = None
):
    """
    Decorator for coalescing endpoint requests
    
    Args:
        key_prefix: Prefix for coalescing key
        ttl: Time to live for pending requests
        key_params: List of parameter names to include in key
    
    Example:
        @app.get("/api/v1/frameworks/{framework}/docs")
        @coalesce_endpoint(key_prefix="docs", key_params=["framework", "section"])
        async def get_docs(framework: str, section: str = None):
            # Heavy operation that benefits from coalescing
            return await fetch_docs(framework, section)
    """
    def decorator(func):
        # Create coalescer for this endpoint
        coalescer = RequestCoalescer(ttl=ttl)
        
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Generate coalescing key
            if key_prefix:
                prefix = key_prefix
            else:
                prefix = func.__name__
            
            # Extract key parameters
            key_parts = [prefix]
            
            if key_params:
                for param in key_params:
                    if param in kwargs:
                        key_parts.append(f"{param}:{kwargs[param]}")
            else:
                # Use all parameters
                key_parts.extend(str(arg) for arg in args)
                key_parts.extend(f"{k}:{v}" for k, v in sorted(kwargs.items()))
            
            key = "|".join(key_parts)
            
            # Coalesce the request
            return await coalescer.coalesce(key, func, *args, **kwargs)
        
        # Attach coalescer for stats access
        wrapper.coalescer = coalescer
        
        return wrapper
    
    return decorator


# Global coalescer for shared operations
global_coalescer = RequestCoalescer(ttl=10)


async def coalesce_global(
    operation: str,
    func: Callable,
    *args,
    **kwargs
) -> Any:
    """
    Coalesce operation globally across all endpoints
    
    Args:
        operation: Operation identifier
        func: Function to execute
        *args: Function arguments
        **kwargs: Function keyword arguments
    
    Returns:
        Function result
    
    Example:
        # Multiple endpoints requesting same framework docs
        result = await coalesce_global(
            f"fetch_docs:{framework}",
            fetch_framework_docs,
            framework
        )
    """
    key = global_coalescer._generate_key(operation, *args, **kwargs)
    return await global_coalescer.coalesce(key, func, *args, **kwargs)
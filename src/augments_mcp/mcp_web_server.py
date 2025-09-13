"""
MCP-Compliant Web Server for Augments
Implements the Model Context Protocol over HTTP with Server-Sent Events
"""

import os
import json
import asyncio
import uuid
from typing import Optional, Dict, Any, List
from contextlib import asynccontextmanager
from datetime import datetime

import structlog
from fastapi import FastAPI, Request, HTTPException, Response
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import redis.asyncio as redis

from .registry.manager import FrameworkRegistryManager
from .registry.cache import DocumentationCache
from .providers.github import GitHubProvider
from .providers.website import WebsiteProvider
from .tools import framework_discovery, documentation, context_enhancement, updates

# Configure logging
logger = structlog.get_logger(__name__)

# Global instances
redis_client: Optional[redis.Redis] = None
registry_manager: Optional[FrameworkRegistryManager] = None
doc_cache: Optional[DocumentationCache] = None
github_provider: Optional[GitHubProvider] = None
website_provider: Optional[WebsiteProvider] = None

# MCP Protocol Models
class JsonRpcRequest(BaseModel):
    jsonrpc: str = "2.0"
    id: Optional[Any] = None
    method: str
    params: Optional[Dict[str, Any]] = None

class JsonRpcResponse(BaseModel):
    jsonrpc: str = "2.0"
    id: Optional[Any] = None
    result: Optional[Any] = None
    error: Optional[Dict[str, Any]] = None

# Server capabilities
SERVER_INFO = {
    "name": "augments-mcp-server",
    "version": "2.0.0"
}

CAPABILITIES = {
    "tools": {},
    "completion": {}
}

# Tool definitions matching the local MCP server
TOOLS = [
    {
        "name": "list_available_frameworks",
        "description": "List all available frameworks, optionally filtered by category",
        "inputSchema": {
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "description": "Filter by category (web, backend, mobile, ai-ml, design, tools)"
                }
            }
        }
    },
    {
        "name": "search_frameworks",
        "description": "Search for frameworks by name, keyword, or feature",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search term to match against framework names and features"
                }
            },
            "required": ["query"]
        }
    },
    {
        "name": "get_framework_info",
        "description": "Get detailed information about a specific framework",
        "inputSchema": {
            "type": "object",
            "properties": {
                "framework": {
                    "type": "string",
                    "description": "Framework name"
                }
            },
            "required": ["framework"]
        }
    },
    {
        "name": "get_framework_docs",
        "description": "Retrieve comprehensive documentation for a specific framework",
        "inputSchema": {
            "type": "object",
            "properties": {
                "framework": {
                    "type": "string",
                    "description": "Framework name (e.g., 'react', 'tailwind', 'laravel')"
                },
                "section": {
                    "type": "string",
                    "description": "Specific documentation section"
                },
                "use_cache": {
                    "type": "boolean",
                    "description": "Whether to use cached content (default: true)",
                    "default": True
                }
            },
            "required": ["framework"]
        }
    },
    {
        "name": "get_framework_examples",
        "description": "Get code examples for specific patterns within a framework",
        "inputSchema": {
            "type": "object",
            "properties": {
                "framework": {
                    "type": "string",
                    "description": "Framework name"
                },
                "pattern": {
                    "type": "string",
                    "description": "Specific pattern (e.g., 'components', 'routing', 'authentication')"
                }
            },
            "required": ["framework"]
        }
    },
    {
        "name": "search_documentation",
        "description": "Search within a framework's cached documentation",
        "inputSchema": {
            "type": "object",
            "properties": {
                "framework": {
                    "type": "string",
                    "description": "Framework name to search within"
                },
                "query": {
                    "type": "string",
                    "description": "Search query"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of results (default: 10)",
                    "default": 10
                }
            },
            "required": ["framework", "query"]
        }
    },
    {
        "name": "get_framework_context",
        "description": "Get relevant context for multiple frameworks based on the development task",
        "inputSchema": {
            "type": "object",
            "properties": {
                "frameworks": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of framework names being used"
                },
                "task_description": {
                    "type": "string",
                    "description": "Description of what you're trying to build"
                }
            },
            "required": ["frameworks", "task_description"]
        }
    },
    {
        "name": "analyze_code_compatibility",
        "description": "Analyze code for framework compatibility and suggest improvements",
        "inputSchema": {
            "type": "object",
            "properties": {
                "code": {
                    "type": "string",
                    "description": "Code snippet to analyze"
                },
                "frameworks": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of frameworks the code should work with"
                }
            },
            "required": ["code", "frameworks"]
        }
    },
    {
        "name": "check_framework_updates",
        "description": "Check if framework documentation has been updated since last cache",
        "inputSchema": {
            "type": "object",
            "properties": {
                "framework": {
                    "type": "string",
                    "description": "Framework name to check"
                }
            },
            "required": ["framework"]
        }
    },
    {
        "name": "refresh_framework_cache",
        "description": "Refresh cached documentation for frameworks",
        "inputSchema": {
            "type": "object",
            "properties": {
                "framework": {
                    "type": "string",
                    "description": "Specific framework to refresh, or None for all"
                },
                "force": {
                    "type": "boolean",
                    "description": "Force refresh even if cache is still valid",
                    "default": False
                }
            }
        }
    },
    {
        "name": "get_cache_stats",
        "description": "Get detailed cache statistics and performance metrics",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "get_registry_stats",
        "description": "Get statistics about the framework registry",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    }
]

def get_redis_url() -> str:
    """Get Redis URL from environment or default"""
    return os.getenv("REDIS_URL", "redis://localhost:6379/0")

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifecycle"""
    global redis_client, registry_manager, doc_cache, github_provider, website_provider
    
    logger.info("Starting MCP Web Server")
    
    try:
        # Initialize Redis
        redis_url = get_redis_url()
        if redis_url != "redis://localhost:6379/0":  # Only connect if not localhost
            try:
                redis_client = await redis.from_url(
                    redis_url,
                    encoding="utf-8",
                    decode_responses=True,
                    socket_timeout=5,
                    socket_connect_timeout=5
                )
                await redis_client.ping()
                logger.info("Connected to Redis")
            except Exception as e:
                logger.warning(f"Could not connect to Redis: {e}, continuing without Redis")
                redis_client = None
        
        # Initialize registry and providers
        registry_manager = FrameworkRegistryManager()
        await registry_manager.initialize()
        
        doc_cache = DocumentationCache(redis_client=redis_client)
        
        github_token = os.getenv("GITHUB_TOKEN")
        github_provider = GitHubProvider(github_token)
        
        website_provider = WebsiteProvider()
        
        logger.info("MCP Web Server initialized successfully")
        
    except Exception as e:
        logger.error(f"Failed to initialize server: {e}")
        raise
    
    yield
    
    # Cleanup
    logger.info("Shutting down MCP Web Server")
    if redis_client:
        await redis_client.close()

# Create FastAPI app
app = FastAPI(
    title="Augments MCP Server",
    version="2.0.0",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

async def handle_initialize(params: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Handle MCP initialization"""
    return {
        "protocolVersion": "0.1.0",
        "serverInfo": SERVER_INFO,
        "capabilities": CAPABILITIES
    }

async def handle_initialized(params: Optional[Dict[str, Any]]) -> None:
    """Handle initialization confirmation"""
    logger.info("Client initialized")
    return None

async def handle_tools_list(params: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """List available tools"""
    return {"tools": TOOLS}

async def handle_tools_call(params: Optional[Dict[str, Any]]) -> Any:
    """Execute a tool"""
    if not params or "name" not in params:
        raise ValueError("Tool name is required")
    
    tool_name = params["name"]
    tool_params = params.get("arguments", {})
    
    # Map tool names to implementation functions
    if tool_name == "list_available_frameworks":
        result = await framework_discovery.list_available_frameworks(
            registry=registry_manager,
            category=tool_params.get("category")
        )
    elif tool_name == "search_frameworks":
        result = await framework_discovery.search_frameworks(
            registry=registry_manager,
            query=tool_params["query"]
        )
    elif tool_name == "get_framework_info":
        result = await framework_discovery.get_framework_info(
            registry=registry_manager,
            framework=tool_params["framework"]
        )
    elif tool_name == "get_framework_docs":
        result = await documentation.get_framework_docs(
            registry=registry_manager,
            cache=doc_cache,
            github_provider=github_provider,
            website_provider=website_provider,
            framework=tool_params["framework"],
            section=tool_params.get("section"),
            use_cache=tool_params.get("use_cache", True)
        )
    elif tool_name == "get_framework_examples":
        result = await documentation.get_framework_examples(
            registry=registry_manager,
            cache=doc_cache,
            github_provider=github_provider,
            website_provider=website_provider,
            framework=tool_params["framework"],
            pattern=tool_params.get("pattern")
        )
    elif tool_name == "search_documentation":
        result = await documentation.search_documentation(
            cache=doc_cache,
            framework=tool_params["framework"],
            query=tool_params["query"],
            limit=tool_params.get("limit", 10)
        )
    elif tool_name == "get_framework_context":
        result = await context_enhancement.get_framework_context(
            registry=registry_manager,
            cache=doc_cache,
            github_provider=github_provider,
            website_provider=website_provider,
            frameworks=tool_params["frameworks"],
            task_description=tool_params["task_description"]
        )
    elif tool_name == "analyze_code_compatibility":
        result = await context_enhancement.analyze_code_compatibility(
            registry=registry_manager,
            code=tool_params["code"],
            frameworks=tool_params["frameworks"]
        )
    elif tool_name == "check_framework_updates":
        result = await updates.check_framework_updates(
            registry=registry_manager,
            cache=doc_cache,
            framework=tool_params["framework"]
        )
    elif tool_name == "refresh_framework_cache":
        result = await updates.refresh_framework_cache(
            registry=registry_manager,
            cache=doc_cache,
            github_provider=github_provider,
            website_provider=website_provider,
            framework=tool_params.get("framework"),
            force=tool_params.get("force", False)
        )
    elif tool_name == "get_cache_stats":
        result = await updates.get_cache_statistics(cache=doc_cache)
    elif tool_name == "get_registry_stats":
        result = await framework_discovery.get_registry_stats(registry=registry_manager)
    else:
        raise ValueError(f"Unknown tool: {tool_name}")
    
    return result

async def handle_completion_complete(params: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Handle completion request"""
    # For now, return empty completions
    return {"completion": {"values": []}}

# Method handlers
METHOD_HANDLERS = {
    "initialize": handle_initialize,
    "initialized": handle_initialized,
    "tools/list": handle_tools_list,
    "tools/call": handle_tools_call,
    "completion/complete": handle_completion_complete
}

async def process_message(message: JsonRpcRequest) -> JsonRpcResponse:
    """Process a JSON-RPC message"""
    try:
        handler = METHOD_HANDLERS.get(message.method)
        if not handler:
            return JsonRpcResponse(
                id=message.id,
                error={
                    "code": -32601,
                    "message": f"Method not found: {message.method}"
                }
            )
        
        result = await handler(message.params)
        return JsonRpcResponse(id=message.id, result=result)
        
    except Exception as e:
        logger.error(f"Error processing message: {e}", exc_info=True)
        return JsonRpcResponse(
            id=message.id,
            error={
                "code": -32603,
                "message": str(e)
            }
        )

async def sse_generator(request_body: str):
    """Generate Server-Sent Events"""
    try:
        # Parse the incoming JSON-RPC request
        data = json.loads(request_body)
        request = JsonRpcRequest(**data)
        
        # Process the message
        response = await process_message(request)
        
        # Send response as SSE
        response_data = response.model_dump(exclude_none=True)
        yield f"data: {json.dumps(response_data)}\n\n"
        
    except json.JSONDecodeError as e:
        error_response = JsonRpcResponse(
            error={
                "code": -32700,
                "message": f"Parse error: {e}"
            }
        )
        yield f"data: {json.dumps(error_response.model_dump())}\n\n"
    except Exception as e:
        error_response = JsonRpcResponse(
            error={
                "code": -32603,
                "message": f"Internal error: {e}"
            }
        )
        yield f"data: {json.dumps(error_response.model_dump())}\n\n"

@app.post("/sse")
async def sse_endpoint(request: Request):
    """
    MCP Server-Sent Events endpoint
    Handles JSON-RPC messages over SSE
    """
    body = await request.body()
    return StreamingResponse(
        sse_generator(body.decode()),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )

@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "status": "ok",
        "service": "augments-mcp-server",
        "version": "2.0.0",
        "protocol": "mcp",
        "transport": "streamable-http"
    }

@app.get("/health")
async def health():
    """Health check endpoint"""
    return {"status": "healthy"}

def main():
    """Main entry point for the MCP web server"""
    import uvicorn
    
    port = int(os.getenv("PORT", "8000"))
    host = os.getenv("HOST", "0.0.0.0")
    
    uvicorn.run(
        "augments_mcp.mcp_web_server:app",
        host=host,
        port=port,
        reload=False,
        log_level="info"
    )

if __name__ == "__main__":
    main()
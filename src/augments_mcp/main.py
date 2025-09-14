#!/usr/bin/env python3
"""
Main entry point for augments-mcp-server.

This module provides a clean entry point that avoids the RuntimeWarning
about module imports when using python -m execution.
"""

# Apply warning filters IMMEDIATELY - before any other imports
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning, module="websockets.*")
warnings.filterwarnings("ignore", category=DeprecationWarning, module="uvicorn.*")
# Also catch the specific warnings by message
warnings.filterwarnings("ignore", message=".*websockets.legacy is deprecated.*")
warnings.filterwarnings("ignore", message=".*WebSocketServerProtocol is deprecated.*")

import sys


def main():
    """Main entry point for the server."""
    # Import after warnings are configured
    from .server import main as server_main
    
    # Run the server with any command line arguments
    server_main()


if __name__ == "__main__":
    main()
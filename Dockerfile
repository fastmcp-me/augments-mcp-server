# Production-ready container optimized for Railway
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    git \
    curl \
    ca-certificates \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get autoremove -y \
    && apt-get clean

# Create non-root user
RUN groupadd -r -g 1000 augments && \
    useradd -r -g augments -u 1000 -m -s /bin/bash augments

# Set working directory
WORKDIR /app

# Copy dependency files first (for Docker layer caching)
COPY pyproject.toml ./

# Install dependencies with pip (more reliable on Railway)
RUN pip install --no-cache-dir --upgrade pip setuptools wheel \
    && pip install --no-cache-dir .

# Copy application code
COPY --chown=augments:augments src/ ./src/
COPY --chown=augments:augments frameworks/ ./frameworks/

# Create cache and logs directories with proper permissions
RUN mkdir -p /app/cache /app/logs && \
    chown -R augments:augments /app

# Switch to non-root user
USER augments

# Set Python path
ENV PYTHONPATH="/app/src:$PYTHONPATH"

# Production environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    ENV=production \
    AUGMENTS_CACHE_DIR=/app/cache \
    REDIS_POOL_SIZE=20 \
    WORKERS=6 \
    LOG_LEVEL=INFO

# Health check with better timeout handling
HEALTHCHECK --interval=30s --timeout=15s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:${PORT:-8080}/health || exit 1

# Expose port
EXPOSE ${PORT:-8080}

# Use exec form for proper signal handling
CMD ["python", "-m", "augments_mcp.web_server"]
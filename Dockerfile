# Multi-stage build for optimized production container
FROM python:3.11-slim as builder

# Install build dependencies (minimize layer size)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    git \
    curl \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get autoremove -y \
    && apt-get clean

# Install uv for faster dependency resolution
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.cargo/bin:${PATH}"

# Set working directory
WORKDIR /app

# Copy dependency files first (for Docker layer caching)
COPY pyproject.toml uv.lock* ./

# Install dependencies with uv (faster than pip)
RUN uv sync --frozen --no-dev --no-cache

# Copy source code
COPY src/ ./src/
COPY frameworks/ ./frameworks/

# Production stage - minimal runtime image
FROM python:3.11-slim

# Install only essential runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get autoremove -y \
    && apt-get clean

# Create non-root user early
RUN groupadd -r -g 1000 augments && \
    useradd -r -g augments -u 1000 -m -s /bin/bash augments

# Set working directory
WORKDIR /app

# Copy Python environment from builder
COPY --from=builder --chown=augments:augments /app/.venv /app/.venv

# Copy application code
COPY --chown=augments:augments src/ ./src/
COPY --chown=augments:augments frameworks/ ./frameworks/
COPY --chown=augments:augments pyproject.toml ./

# Create cache and logs directories with proper permissions
RUN mkdir -p /app/cache /app/logs && \
    chown -R augments:augments /app

# Switch to non-root user
USER augments

# Add venv to PATH
ENV PATH="/app/.venv/bin:$PATH"
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
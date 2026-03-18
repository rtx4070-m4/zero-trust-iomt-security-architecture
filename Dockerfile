# =============================================================================
# Zero Trust IoMT - Multi-Stage Production Dockerfile
# =============================================================================
# Stage 1: Builder — installs dependencies and compiles any native extensions
# Stage 2: Runtime — minimal image with only what's needed to run the app
#
# Compliance: NIST SP 800-190 (Container Security), CIS Docker Benchmark
# =============================================================================

# ── Stage 1: Builder ──────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

LABEL maintainer="IoMT Security Team <security@iomt-zerotrust.example>"
LABEL description="Zero Trust Architecture for Internet of Medical Things"
LABEL version="2.1.0"
LABEL org.opencontainers.image.source="https://github.com/example/zero-trust-iomt"
LABEL org.opencontainers.image.licenses="MIT"

# Build-time arguments (can be overridden at build time)
ARG BUILD_DATE
ARG VCS_REF
LABEL org.opencontainers.image.created="${BUILD_DATE}"
LABEL org.opencontainers.image.revision="${VCS_REF}"

# Set environment for build stage
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# Copy only requirements first (layer caching optimization)
COPY requirements.txt .

# Install build dependencies and Python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libffi-dev \
        libssl-dev \
        curl \
    && pip install --upgrade pip \
    && pip install --prefix=/install -r requirements.txt \
    && apt-get purge -y gcc libffi-dev \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*


# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

# CIS Benchmark: Do not run as root
# Create dedicated non-root user for the application
RUN groupadd --gid 10001 iomt && \
    useradd --uid 10001 --gid iomt --shell /bin/false --no-create-home iomt

# Set secure environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    # Application config (override via docker-compose or --env-file)
    APP_ENV=production \
    APP_HOST=0.0.0.0 \
    APP_PORT=8000 \
    LOG_LEVEL=INFO \
    LOG_DIR=/app/logs \
    POLICY_STRICT_MODE=true \
    AUTH_TOKEN_TTL=3600 \
    # Security: disable Python's hash randomization for reproducibility in tests
    PYTHONHASHSEED=random

# Install only runtime OS dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3 \
        ca-certificates \
        curl \
        # For health checks and lightweight network diagnostics
        netcat-openbsd \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy installed Python packages from builder
COPY --from=builder /install /usr/local

# Set working directory
WORKDIR /app

# Copy application source code
# Order: least-frequently-changed first for better layer caching
COPY --chown=iomt:iomt policies/         ./policies/
COPY --chown=iomt:iomt iam/              ./iam/
COPY --chown=iomt:iomt monitoring/       ./monitoring/
COPY --chown=iomt:iomt simulation/       ./simulation/
COPY --chown=iomt:iomt api/              ./api/
COPY --chown=iomt:iomt firewall/         ./firewall/

# Create required directories with proper ownership
RUN mkdir -p /app/logs /app/certs /app/data && \
    chown -R iomt:iomt /app/logs /app/certs /app/data

# ── Security Hardening ────────────────────────────────────────────────────────
# Remove setuid/setgid bits from system binaries
RUN find / -xdev -perm /6000 -type f -exec chmod a-s {} \; 2>/dev/null || true

# Make source code read-only (except logs/data)
RUN chmod -R 550 /app/policies /app/iam /app/monitoring /app/simulation /app/api /app/firewall

# Switch to non-root user
USER iomt

# Expose API gateway port (internal; external mapping via docker-compose)
EXPOSE 8000

# Health check: ping the /api/v1/health endpoint every 30s
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

# Default command: run the FastAPI gateway via uvicorn
# Use --workers 1 in container (scale via Kubernetes/Swarm replicas instead)
CMD ["python", "-m", "uvicorn", "api.gateway:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "1", \
     "--log-level", "info", \
     "--access-log", \
     "--no-server-header", \
     "--proxy-headers"]


# =============================================================================
# Build Instructions:
#
#   # Standard build
#   docker build -t zero-trust-iomt:latest .
#
#   # Build with metadata
#   docker build \
#     --build-arg BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ") \
#     --build-arg VCS_REF=$(git rev-parse --short HEAD) \
#     -t zero-trust-iomt:2.1.0 .
#
#   # Run standalone
#   docker run -p 8000:8000 --read-only \
#     -v iomt_logs:/app/logs \
#     zero-trust-iomt:latest
#
#   # Scan for vulnerabilities (requires trivy)
#   trivy image zero-trust-iomt:latest
# =============================================================================

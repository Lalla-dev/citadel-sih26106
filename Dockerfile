# ==============================================================================
# Citadel Security Platform - Production Container Image
# Multi-layer adversarial-resilient email threat intelligence platform
# ==============================================================================
FROM python:3.11-slim

# Prevent Python from writing .pyc files and force unbuffered stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

# Set application working directory
WORKDIR /app

# Install minimal OS runtime dependencies (curl for container healthcheck)
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python runtime dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Create dedicated non-root user and group for container security hardening
RUN groupadd -g 1000 citadel \
    && useradd -u 1000 -g citadel -s /bin/bash -m citadel

# Copy application code and static assets
COPY backend/ ./backend/
COPY frontend/ ./frontend/
COPY samples/ ./samples/

# Ensure non-root user owns the application directory
RUN chown -R citadel:citadel /app

# Switch to non-root user
USER citadel

# Expose FastAPI / Uvicorn application port
EXPOSE 8000

# Container healthcheck querying FastAPI /api/health
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

# Launch Uvicorn bound to all interfaces on port 8000
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]

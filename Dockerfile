# DiscourseMap v2.1 Docker Image
FROM python:3.14-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    traceroute \
    iputils-ping \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY discoursemap/ ./discoursemap/
COPY demo.py .
COPY README.md .
COPY MODULAR_ARCHITECTURE.md .

# Create non-root user
RUN useradd -m -u 1000 scanner && \
    chown -R scanner:scanner /app

USER scanner

# Set environment variables
ENV PYTHONPATH=/app
ENV DISCOURSEMAP_VERSION=2.1.0

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import discoursemap; print('OK')" || exit 1

# Default command
CMD ["python", "demo.py"]

# Labels
LABEL maintainer="ibrahimsql <ibrahimsql@proton.me>"
LABEL version="2.1.0"
LABEL description="DiscourseMap - Modular Discourse Security Scanner"
LABEL org.opencontainers.image.source="https://github.com/ibrahmsql/discoursemap"
FROM python:3.12-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
        arp-scan \
        arpwatch \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt pytest

# Copy application
COPY macwatcher.py .
COPY config.ini .
COPY known-macs.conf.example .
COPY tests/ tests/

CMD ["pytest", "tests/", "-v"]

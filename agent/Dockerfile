FROM python:3.12-slim

WORKDIR /app

# Install system-level dependencies first
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    iputils-ping \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

# 1. Copy only requirements to cache this layer
COPY requirements.txt .

# 2. Use a pip cache mount so downloaded wheels persist across builds
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --no-cache-dir -r requirements.txt

# 3. Copy application source code last (frequently changing layer)
COPY . .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]

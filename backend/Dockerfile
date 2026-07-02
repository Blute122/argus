# Backend API + ingestion + detection engine
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Install deps first for better layer caching.
COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

COPY backend/ backend/

# Persistent data (SQLite fallback, generated JWT secret) lives here.
RUN mkdir -p /app/data
VOLUME ["/app/data"]

EXPOSE 8000
# Syslog listener (optional) also uses 5514/udp+tcp when SYSLOG_ENABLED=true.
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]

# Auth Service — production image.
FROM python:3.11-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Dependencies first so the layer caches across code changes.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY features ./features
COPY app ./app
COPY sdk ./sdk
COPY run.py ./

RUN useradd --create-home --uid 10001 authsvc && \
    chown -R authsvc:authsvc /app
USER authsvc

ENV AUTHSVC_PORT=8100
EXPOSE 8100

# Readiness (not liveness): the orchestrator should also probe /health/live.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import os,urllib.request,sys; \
url=f\"http://127.0.0.1:{os.getenv('AUTHSVC_PORT','8100')}/health/live\"; \
sys.exit(0 if urllib.request.urlopen(url, timeout=4).status == 200 else 1)"

# Single worker by default: the Mongo pool is per-process, and scaling is
# better handled by running more replicas than more workers.
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${AUTHSVC_PORT:-8100} --workers ${AUTHSVC_WORKERS:-1}"]

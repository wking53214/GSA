# syntax=docker/dockerfile:1
# ---- builder ----
FROM python:3.12-slim AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ---- runtime ----
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    GSA_ENV=prod \
    GSA_AUDIT_BACKEND=sqlite \
    GSA_AUDIT_DB_PATH=/data/gsa_audit.db
COPY --from=builder /install /usr/local
WORKDIR /app
COPY *.py ./
# non-root + writable data volume for the audit DB
RUN useradd -u 10001 -m gsa && mkdir -p /data && chown -R gsa:gsa /data /app
USER gsa
VOLUME ["/data"]
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8000/health').status==200 else 1)"
CMD ["uvicorn", "gsa_gateway:app", "--host", "0.0.0.0", "--port", "8000"]

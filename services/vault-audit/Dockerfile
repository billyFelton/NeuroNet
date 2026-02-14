FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends curl git && rm -rf /var/lib/apt/lists/*
ARG NEUROKIT_VERSION=v0.2.0
RUN pip install --no-cache-dir "neurokit @ git+https://github.com/billyFelton/NeuroKit.git@${NEUROKIT_VERSION}" "psycopg2-binary>=2.9.0"
RUN mkdir -p /var/log/neuronet/audit
COPY service.py .
ENV NEURO_SERVICE_NAME=vault-audit
ENV AUDIT_LOG_DIR=/var/log/neuronet/audit
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD curl -f http://localhost:8080/health || exit 1
CMD ["python", "service.py"]

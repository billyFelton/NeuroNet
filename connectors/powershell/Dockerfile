FROM python:3.11-slim

LABEL maintainer="neuro-network"
LABEL description="Connector-PowerShell: Remote PowerShell execution via WinRM"

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl git libkrb5-dev gcc && \
    rm -rf /var/lib/apt/lists/*

ARG NEUROKIT_VERSION=v0.2.0
RUN pip install --no-cache-dir \
    "neurokit @ git+https://github.com/billyFelton/NeuroKit.git@${NEUROKIT_VERSION}" \
    "pypsrp>=0.8.0" \
    "psycopg2-binary>=2.9.0"

COPY service.py .

ENV NEURO_SERVICE_NAME=connector-powershell
ENV NEURO_SERVICE_VERSION=0.1.0

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

CMD ["python", "service.py"]

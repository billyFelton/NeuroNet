FROM python:3.11-slim

LABEL maintainer="neuro-network"
LABEL description="Agent-Worker-Claude: Anthropic Claude AI worker"

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl git && \
    rm -rf /var/lib/apt/lists/*

ARG NEUROKIT_VERSION=v0.2.0
RUN pip install --no-cache-dir \
    "neurokit @ git+https://github.com/billyFelton/NeuroKit.git@${NEUROKIT_VERSION}" \
    "httpx>=0.27.0"

COPY service.py .

ENV NEURO_SERVICE_NAME=agent-worker-claude
ENV NEURO_SERVICE_VERSION=0.1.0

CMD ["python", "service.py"]

FROM python:3.11-slim

LABEL maintainer="neuro-network"
LABEL description="Resolver: RBAC enforcement and message routing gateway"

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl git && \
    rm -rf /var/lib/apt/lists/*

ARG NEUROKIT_VERSION=v0.2.0
RUN pip install --no-cache-dir \
    "neurokit @ git+https://github.com/billyFelton/NeuroKit.git@${NEUROKIT_VERSION}"

COPY service.py .

ENV NEURO_SERVICE_NAME=resolver
ENV NEURO_SERVICE_VERSION=0.1.0

CMD ["python", "service.py"]

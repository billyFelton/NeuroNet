FROM python:3.11-slim

LABEL maintainer="neuro-network"
LABEL description="Vault-IAM: Identity, RBAC, and EntraID sync"

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl git && \
    rm -rf /var/lib/apt/lists/*

# Install NeuroKit from GitHub (pinned version)
ARG NEUROKIT_VERSION=v0.2.0
RUN pip install --no-cache-dir \
    "neurokit @ git+https://github.com/billyFelton/NeuroKit.git@${NEUROKIT_VERSION}"

# Install Vault-IAM dependencies
RUN pip install --no-cache-dir \
    "fastapi>=0.109.0" \
    "uvicorn[standard]>=0.27.0" \
    "psycopg[binary]>=3.1.0" \
    "psycopg_pool>=3.1.0" \
    "httpx>=0.27.0" \
    "pyjwt>=2.8.0" \
    "passlib[bcrypt]>=1.7.4"

# Copy application code
COPY vault_iam/ vault_iam/

ENV NEURO_SERVICE_NAME=vault-iam
ENV NEURO_SERVICE_VERSION=0.1.0

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=5s --retries=5 \
    CMD curl -f http://localhost:8080/health || exit 1

CMD ["uvicorn", "vault_iam.app:app", "--host", "0.0.0.0", "--port", "8080"]

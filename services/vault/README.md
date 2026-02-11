# Vault Service

Multi-container service providing secrets management, identity/RBAC, and SOC2 audit logging for the Neuro-Network.

## Containers

| Container | Image | Purpose |
|---|---|---|
| `hcvault` | `hashicorp/vault:1.15` | Encrypted secret storage, AppRole auth |
| `vault-db` | `postgres:16-alpine` | IAM + audit log persistence |
| `vault-iam` | Custom (NeuroKit) | EntraID sync, identity resolution, RBAC |
| `vault-audit` | Custom (NeuroKit) | Audit event consumer and query API (coming soon) |

## Quick Start

```bash
# Create the shared network (once, across all Neuro-Network services)
docker network create neuro-network

# Configure
cp .env.example .env
# Edit .env with real passwords

# Start
docker compose up -d

# Verify
curl http://localhost:8080/health
```

## First-Time HashiCorp Vault Setup

```bash
# Initialize (save the unseal keys and root token!)
docker exec -it neuro-hcvault vault operator init

# Unseal (repeat 3x with different unseal keys)
docker exec -it neuro-hcvault vault operator unseal

# Authenticate
docker exec -it neuro-hcvault vault login <root-token>

# Enable KV v2 secrets engine
docker exec -it neuro-hcvault vault secrets enable -path=neuro-secrets kv-v2

# Enable AppRole auth
docker exec -it neuro-hcvault vault auth enable approle

# Store secrets (example: Anthropic API key)
docker exec -it neuro-hcvault vault kv put neuro-secrets/anthropic \
    api_key="sk-ant-..." \
    default_model="claude-sonnet-4-5-20250929"

# Store Wazuh credentials
docker exec -it neuro-hcvault vault kv put neuro-secrets/wazuh \
    api_url="https://wazuh.internal:55000" \
    api_user="wazuh-api" \
    api_password="..."

# Apply policies and create AppRoles
docker exec -it neuro-hcvault vault policy write connector-wazuh /vault/policies/connector-wazuh.hcl
docker exec -it neuro-hcvault vault write auth/approle/role/connector-wazuh \
    token_policies="connector-wazuh" token_ttl=1h token_max_ttl=4h
```

## Vault-IAM API

### Authentication
All endpoints (except `/health`) require a Bearer token.
Services authenticate via `POST /api/v1/auth/service`.

### Key Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Health check |
| POST | `/api/v1/auth/service` | Service authentication → JWT |
| GET | `/api/v1/identity/resolve?provider=slack&external_id=U123` | Resolve external ID to identity |
| GET | `/api/v1/identity/{user_id}` | Get user profile |
| GET | `/api/v1/identity/{user_id}/roles` | Get user roles |
| POST | `/api/v1/rbac/check` | Check permission |
| POST | `/api/v1/admin/identity-mappings` | Create identity mapping |
| POST | `/api/v1/admin/roles/assign` | Assign role to user |
| POST | `/api/v1/admin/group-role-mappings` | Map EntraID group → role |
| POST | `/api/v1/admin/service-accounts` | Create service account |

## Dependencies

- **NeuroKit**: `git+https://github.com/billyFelton/NeuroKit.git@v0.2.0`

# Connector-EntraID Setup Guide

## Overview

The EntraID connector provides on-demand Microsoft Graph API queries to the Neuro-Network. When a user asks about sign-in logs, MFA status, or risky users, the AI layer sends a message through RabbitMQ to this connector, which queries Graph and returns the results.

This is separate from the Vault-IAM EntraID sync, which handles background user/group sync into the IAM database. The connector handles real-time queries.

## Prerequisites

### Microsoft Entra App Registration

1. Go to **Azure Portal → Microsoft Entra ID → App registrations**
2. Click **New registration**
3. Name: `NeuroNet-EntraID-Connector`
4. Supported account types: **Single tenant**
5. Register

### API Permissions (Application type)

Add the following **Application** permissions (not Delegated):

| Permission | Type | Purpose |
|---|---|---|
| `User.Read.All` | Application | User profile lookups |
| `AuditLog.Read.All` | Application | Sign-in log queries |
| `Directory.Read.All` | Application | Directory data |
| `IdentityRiskyUser.Read.All` | Application | Risky user detection |
| `UserAuthenticationMethod.Read.All` | Application | MFA method queries |
| `Reports.Read.All` | Application | Usage reports |

After adding permissions, click **Grant admin consent** for the tenant.

### Client Secret

1. Go to **Certificates & secrets → New client secret**
2. Description: `NeuroNet connector`
3. Expiry: Choose appropriate (recommend 12 months, rotate before expiry)
4. Copy the secret value immediately

## Store Secrets in HashiCorp Vault

```bash
vault kv put neuro-secrets/microsoft-graph \
    tenant_id="your-tenant-id" \
    client_id="your-app-client-id" \
    client_secret="your-client-secret"
```

### AppRole Policy

```hcl
# policies/connector-entraid.hcl
path "neuro-secrets/data/microsoft-graph" {
  capabilities = ["read"]
}
path "neuro-secrets/data/microsoft-graph/*" {
  capabilities = ["read"]
}
```

```bash
vault policy write connector-entraid policies/connector-entraid.hcl
vault write auth/approle/role/connector-entraid \
    token_policies="connector-entraid" \
    token_ttl=1h \
    token_max_ttl=4h
```

## Query Types

| Routing Key | Payload | Returns |
|---|---|---|
| `entraid.query.user` | `{user_id}` or `{email}` | User profile |
| `entraid.query.signin-logs` | `{user_id?, hours?, status?, risk_level?}` | Sign-in logs + summary |
| `entraid.query.mfa-status` | `{user_id}` | MFA methods and registration status |
| `entraid.query.risky-users` | `{risk_level?, risk_state?, top?}` | Risky user list |
| `entraid.query.groups` | `{group_id, action?}` | Group details or members |
| `entraid.query.devices` | `{user_id}` | Registered devices |

## RBAC Resources

These resources are defined in the IAM database and control who can query what:

| Resource | Required Role |
|---|---|
| `entra-users` | security-admin, security-analyst, it-support (view only) |
| `entra-signin-logs` | security-admin, security-analyst |
| `entra-mfa-status` | security-admin, security-analyst, it-support (view only) |
| `entra-groups` | security-admin |

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `NEURO_SERVICE_NAME` | No | `connector-entraid` | Service name |
| `HCVAULT_ROLE_ID` | Yes | — | AppRole role ID |
| `HCVAULT_SECRET_ID` | Yes | — | AppRole secret ID |
| `RABBITMQ_HOST` | No | `rabbitmq` | RabbitMQ hostname |
| `RABBITMQ_PASSWORD` | Yes | — | RabbitMQ password |
| `VAULT_IAM_SERVICE_TOKEN` | Yes | — | Token for Vault-IAM auth |

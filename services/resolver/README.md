# Resolver

RBAC enforcement and message routing gateway for the Neuro-Network.

## What It Does

Every user query from a connector passes through the Resolver before reaching the AI layer. The Resolver:

1. **Validates identity** — confirms the user is known and has roles assigned
2. **Classifies intent** — determines what data the user is asking about (alerts, sign-in logs, MFA, etc.)
3. **Checks RBAC** — calls Vault-IAM to verify the user's roles permit access to the required resources
4. **Fetches data** — dispatches queries to the appropriate connectors (EntraID, Wazuh) via RabbitMQ
5. **Forwards to AI** — sends the enriched request (user query + authorization context + data) to the Agent Worker

If any RBAC check fails, the Resolver sends a denial response directly back to the originating connector — the AI layer never sees the request.

## Message Flow

```
Connector           Resolver              Vault-IAM    Connectors    AI Worker
    │                  │                     │            │              │
    │──user.query─────>│                     │            │              │
    │                  │──check_permission──>│            │              │
    │                  │<──permit/deny───────│            │              │
    │                  │                     │            │              │
    │                  │──entraid.query.*───────────────>│              │
    │                  │<─entraid.response.*─────────────│              │
    │                  │                     │            │              │
    │                  │──ai.request────────────────────────────────────>│
    │<─ai.response─────────────────────────────────────────────────────│
```

## Intent Classification

Currently uses keyword matching (sufficient for v1). Each intent maps to required RBAC resources:

| Intent | Trigger Keywords | Required Resource | Required Action |
|---|---|---|---|
| `security_alerts` | alert, threat, siem | `wazuh-alerts` | `query` |
| `vulnerability_query` | vulnerability, CVE, patch | `wazuh-vulnerability` | `query` |
| `signin_logs` | sign-in, login, failed login | `entra-signin-logs` | `query` |
| `mfa_status` | MFA, 2FA, authenticator | `entra-mfa-status` | `query` |
| `risky_users` | risky, compromised user | `entra-users` | `query` |
| `user_lookup` | user info, account status | `entra-users` | `view` |
| `group_query` | group, membership | `entra-groups` | `query` |
| `audit_query` | audit log, who accessed | `audit-logs` | `query` |
| `general` | (default) | none | — |

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `HCVAULT_ROLE_ID` | Yes | — | AppRole role ID for secrets |
| `HCVAULT_SECRET_ID` | Yes | — | AppRole secret ID |
| `VAULT_IAM_SERVICE_TOKEN` | Yes | — | Token for Vault-IAM auth |
| `RABBITMQ_HOST` | No | `rabbitmq` | RabbitMQ hostname |
| `RABBITMQ_PASSWORD` | Yes | — | RabbitMQ password |

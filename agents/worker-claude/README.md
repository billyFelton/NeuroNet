# Agent-Worker-Claude

Anthropic Claude AI worker for the Neuro-Network.

## What It Does

Consumes `ai.request` messages from the Resolver, calls the Claude API with role-appropriate system prompts and injected data context, and publishes the response back to the originating connector.

## Role-Based System Prompts

Each RBAC role gets a different system prompt that constrains what Claude will discuss:

| Role | Can Discuss | Cannot Discuss |
|---|---|---|
| `security-admin` | Everything — alerts, sign-in logs, MFA, risky users, remediation actions | — |
| `security-analyst` | Alerts, sign-in logs, MFA, vulnerabilities (read-only analysis) | Remediation actions, admin functions |
| `it-support` | Account status, MFA enrollment | Alerts, sign-in logs, vulnerabilities |
| `general-user` | General Q&A, security awareness, own account | Any security data, other users |

This is defense-in-depth: even if RBAC at the Resolver level somehow leaked data into the context, Claude's system prompt instructs it not to discuss topics outside the user's role.

## Data Context Injection

When the Resolver pre-fetches data from connectors (EntraID sign-in logs, Wazuh alerts, etc.), that data is formatted and injected into the prompt before the user's question. Claude sees something like:

```
[SYSTEM DATA]
### Sign-in Log Data
Summary: 47 sign-ins, 3 failures, 2 risky, 4 unique IPs
Recent events (showing 10 of 47):
- 2026-02-11T14:23:00Z | Jane Doe | Microsoft Teams | 10.0.1.50 | ✓ | risk: none
- 2026-02-11T14:18:00Z | Jane Doe | Exchange Online | 203.0.113.42 | ✗ (error 50126) | risk: medium
...
[END SYSTEM DATA]
```

## Store Secrets in HashiCorp Vault

```bash
vault kv put neuro-secrets/anthropic \
    api_key="sk-ant-..." \
    default_model="claude-sonnet-4-5-20250929" \
    max_tokens="4096"
```

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `HCVAULT_ROLE_ID` | Yes | — | AppRole role ID |
| `HCVAULT_SECRET_ID` | Yes | — | AppRole secret ID |
| `RABBITMQ_HOST` | No | `rabbitmq` | RabbitMQ hostname |
| `RABBITMQ_PASSWORD` | Yes | — | RabbitMQ password |
| `VAULT_IAM_SERVICE_TOKEN` | Yes | — | Token for Vault-IAM auth |

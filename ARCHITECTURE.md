# NeuroNet Architecture

## Overview

NeuroNet is an AI-powered security operations platform that provides a conversational AI interface (Kevin) for querying infrastructure, managing incidents, and executing diagnostics. It runs on Docker Compose with RabbitMQ as the central message bus.

## System Components

| Component | Role | Technology |
|-----------|------|------------|
| **Kevin (AI Agent)** | Conversational AI assistant | Claude Sonnet via Anthropic API |
| **Resolver** | Intent classification + RBAC gateway | Regex + Claude Haiku fallback |
| **Slack Connector** | User interface via Slack DMs | Socket Mode + User Token |
| **Email Connector** | M365 mailbox + user queries | Microsoft Graph API |
| **EntraID Connector** | Identity, sign-in logs, MFA | Microsoft Graph API |
| **Wazuh Connector (×2)** | SIEM alerts + agent inventory | Wazuh Manager API + OpenSearch |
| **ZenDesk Connector** | Ticket management | ZenDesk API v2 |
| **Meraki Connector** | Network infrastructure | Cisco Meraki API v1 |
| **PowerShell Connector** | Remote Windows execution | WinRM/NTLM |
| **RabbitMQ** | Message bus (all inter-service) | AMQP with topic exchange |
| **HashiCorp Vault** | Secrets management | KV v2 engine (`neuro-secrets`) |
| **PostgreSQL (Vault-DB)** | IAM + Knowledge Base | Two schemas: `iam`, `knowledge` |

## Message Flow

### Phase 1: Startup — Service Authentication

Every service authenticates with HashiCorp Vault on startup via AppRole to retrieve its secrets:

```
Slack Connector  ──→  HCVault  →  Slack tokens (user + bot + app-level)
Email Connector  ──→  HCVault  →  Graph API credentials (tenant, client, secret)
EntraID Connector ─→  HCVault  →  Graph API credentials
Wazuh Connector  ──→  HCVault  →  Wazuh Manager API credentials
ZenDesk Connector ─→  HCVault  →  ZenDesk API token
Meraki Connector  ─→  HCVault  →  Meraki API key
PowerShell Conn.  ─→  HCVault  →  WinRM credentials (hutlocadmin)
Kevin (Worker)   ──→  HCVault  →  Anthropic API key
Resolver         ──→  Vault-DB →  IAM database connection
```

### Phase 2: Message Flow — User Asks a Question

```
┌──────┐    ┌───────┐    ┌──────────┐    ┌───────────┐    ┌───────────┐    ┌───────────┐
│ User │    │ Slack │    │ Resolver │    │ Vault-IAM │    │ Connector │    │ Kevin(AI) │
└──┬───┘    └───┬───┘    └────┬─────┘    └─────┬─────┘    └─────┬─────┘    └─────┬─────┘
   │            │             │                │               │               │
   │  DM/mention│             │                │               │               │
   ├───────────►│             │                │               │               │
   │            │             │                │               │               │
   │            │ Socket Mode │                │               │               │
   │            │ event recv  │                │               │               │
   │            │             │                │               │               │
   │            │ Membership  │                │               │               │
   │            │ check (cache│                │               │               │
   │            │ or API)     │                │               │               │
   │            │             │                │               │               │
   │            │  RabbitMQ   │                │               │               │
   │            ├────────────►│                │               │               │
   │            │             │                │               │               │
   │            │             │  Lookup user   │               │               │
   │            │             ├───────────────►│               │               │
   │            │             │                │               │               │
   │            │             │  Roles+policies│               │               │
   │            │             │◄───────────────┤               │               │
   │            │             │                │               │               │
   │            │             │ ┌────────────┐ │               │               │
   │            │             │ │  Classify   │ │               │               │
   │            │             │ │  intent     │ │               │               │
   │            │             │ │ (regex→LLM) │ │               │               │
   │            │             │ └────────────┘ │               │               │
   │            │             │                │               │               │
   │            │             │ ┌────────────┐ │               │               │
   │            │             │ │ RBAC check  │ │               │               │
   │            │             │ │ (role has   │ │               │               │
   │            │             │ │  policy?)   │ │               │               │
   │            │             │ └────────────┘ │               │               │
   │            │             │                │               │               │
   │            │             │  Data query (RabbitMQ)         │               │
   │            │             ├────────────────────────────────►│               │
   │            │             │  e.g. wazuh.query.alerts       │               │
   │            │             │                │               │               │
   │            │             │                │  ┌──────────┐ │               │
   │            │             │                │  │ API call  │ │               │
   │            │             │                │  │ (Wazuh/   │ │               │
   │            │             │                │  │  Graph/   │ │               │
   │            │             │                │  │  Meraki)  │ │               │
   │            │             │                │  └──────────┘ │               │
   │            │             │                │               │               │
   │            │             │  Data response (RabbitMQ)      │               │
   │            │             │◄────────────────────────────────┤               │
   │            │             │  e.g. wazuh.response.alerts    │               │
   │            │             │                │               │               │
   │            │             │  ai.request + data_context (RabbitMQ)          │
   │            │             ├────────────────────────────────────────────────►│
   │            │             │                │               │               │
```

### Phase 3: AI Processing — Kevin Builds Response

```
Kevin (Worker) receives ai.request:

  1. Select system prompt by role
     ├── ai-admin     → security-admin + KB management
     ├── security-admin → full capabilities
     ├── security-analyst → read-only security
     ├── it-support   → troubleshooting
     └── general-user → security awareness only

  2. Load user context from PostgreSQL (knowledge schema)
     ├── User profile (name, title, department)
     ├── Active conversation session (topic, summary, pending items)
     ├── Recent message history (last 6 exchanges)
     └── Relevant knowledge (assets, incidents, facts)

  3. Format [SYSTEM DATA] from connector responses
     ├── _format_zendesk_data()    → ticket summary
     ├── _format_signin_data()     → sign-in log summary
     ├── _format_m365_users_data() → user inventory
     ├── _format_alerts_data()     → Wazuh alerts
     ├── _format_meraki_data()     → network devices
     └── Generic JSON (capped at 4KB) for other data
     Total [SYSTEM DATA] capped at 16KB

  4. Call Claude Sonnet API
     └── System prompt + user memory + [SYSTEM DATA] + user message

  5. Return response text
```

### Phase 4: Post-Processing — Cache, Learn, Act

After Claude responds, the worker performs these steps:

```
Kevin (Worker) post-processing:

  1. Cache query results → knowledge.query_cache (30min TTL)
     └── Enables follow-up queries without re-querying connectors

  2. Auto-populate assets → knowledge.assets
     ├── Wazuh agents → hostname, OS, IP, agent_id, instance
     └── Meraki devices → hostname, model, IP, MAC, serial

  3. Store conversation → knowledge.message_history
     └── Both user message and Kevin's response

  4. Update session → knowledge.conversation_sessions
     └── Haiku LLM generates rolling summary

  5. Extract knowledge → knowledge.entries
     └── Haiku LLM extracts facts about hosts, incidents, contacts

  6. Detect action headers in Kevin's response:
     ├── **Ticket Subject:** → Create ZenDesk ticket (via email)
     ├── **Ticket ID:**      → Update/comment ZenDesk ticket (via API)
     ├── **To:** + **Subject:** → Send email (via Graph API)
     ├── **DM To:**          → Send Slack DM (via bot token)
     └── **KB Update User:** → Update knowledge base (ai-admin only)

  7. Publish ai.response → RabbitMQ → Slack connector → user
```

### Phase 5: Response — Back to User

```
  Worker ──ai.response──► RabbitMQ ──► Slack Connector
                                           │
                                           ├── Match correlation_id to channel
                                           ├── Post Kevin's reply to Slack
                                           └── Post debug trace (optional, in thread)
```

## RabbitMQ Routing Convention

All messages follow the pattern: `service.command.action` or `service.query.action`

Responses use: `service.response.action`

| Routing Key | Direction | Description |
|-------------|-----------|-------------|
| `resolver.inbox` | Slack → Resolver | User messages for classification |
| `ai.request` | Resolver → Worker | Classified message + data context |
| `ai.response` | Worker → Slack | Kevin's response |
| `wazuh.query.alerts` | Resolver → Wazuh | Alert query |
| `wazuh.response.alerts` | Wazuh → Resolver | Alert data |
| `wazuh.query.agents` | Resolver → Wazuh | Agent inventory query |
| `entraid.query.signin-logs` | Resolver → EntraID | Sign-in log query |
| `entraid.query.user` | Resolver → EntraID | User profile lookup |
| `email.query.active-users` | Resolver → Email | M365 user inventory |
| `email.command.send` | Worker → Email | Send email |
| `zendesk.query.search` | Resolver → ZenDesk | Ticket search |
| `zendesk.command.create` | Worker → ZenDesk | Create ticket (via email) |
| `zendesk.command.comment` | Worker → ZenDesk | Comment on ticket |
| `meraki.query.devices` | Resolver → Meraki | Network device query |
| `meraki.query.summary` | Resolver → Meraki | Network summary |
| `slack.command.dm` | Worker → Slack | Send DM to user |
| `powershell.command.propose` | Worker → PowerShell | Propose command |
| `powershell.command.execute` | Resolver → PowerShell | Execute approved command |

## RBAC Model

Roles are mapped from EntraID security groups via `iam.group_role_mappings`:

| EntraID Group | NeuroNet Role | Key Permissions |
|---------------|---------------|-----------------|
| Security-Admins | `security-admin` | Full access: alerts, email, PowerShell, tickets, network |
| Security-Analysts | `security-analyst` | Read-only: alerts, sign-in logs, user profiles |
| AI-Admin | `ai-admin` | All security-admin + knowledge base management |
| (IT Support group) | `it-support` | Alerts, device status, troubleshooting |
| (Default) | `general-user` | Security awareness only, no data access |

Role hierarchy: `ai-admin` > `security-admin` > `security-analyst` > `it-support` > `general-user`

## Database Schema

### IAM Schema (`iam.*`)

Synced from EntraID via `entra_sync.py`:

- `iam.users` — All EntraID users (~420)
- `iam.groups` — All EntraID groups (~358)
- `iam.user_groups` — Group memberships
- `iam.roles` — NeuroNet roles (5)
- `iam.user_roles` — Role assignments
- `iam.group_role_mappings` — EntraID group → NeuroNet role
- `iam.policies` — Resource + action + effect per role
- `iam.resources` — Protected resources (17)

### Knowledge Schema (`knowledge.*`)

Kevin's memory and learning:

- `knowledge.user_profiles` — User relationship data (name, preferences, rapport)
- `knowledge.message_history` — Every conversation exchange
- `knowledge.conversation_sessions` — Rolling conversation summaries (4h TTL)
- `knowledge.query_cache` — Cached connector responses (30min TTL)
- `knowledge.entries` — Learned facts about the environment
- `knowledge.assets` — Device/host inventory (auto-populated from Wazuh/Meraki)
- `knowledge.powershell_executions` — PowerShell command proposals and results
- `knowledge.scheduled_tasks` — Automated sweep configuration

## Infrastructure

- **Host**: Ubuntu server "hal"
- **Container Runtime**: Docker Compose v1.29.2
- **Network**: `neuro-network` (all containers)
- **Vault**: HashiCorp Vault 1.15.6 (KV v2, `neuro-secrets`)
- **Database**: PostgreSQL (`neuro_vault` database, `iam` + `knowledge` schemas)
- **Message Bus**: RabbitMQ (vhost `/neuro`, topic exchange `neuro.exchange`)
- **AI**: Claude Sonnet (main), Claude Haiku (intent classification, knowledge extraction)

### Docker Services

| Container | Service | Notes |
|-----------|---------|-------|
| `neuro-rabbitmq` | RabbitMQ | Message bus |
| `neuro-hcvault` | HashiCorp Vault | Seals on restart — use `vault-unseal.sh` |
| `neuro-vault-db` | PostgreSQL | IAM + Knowledge schemas |
| `neuro-vault-iam` | Vault-IAM service | RBAC API |
| `neuro-resolver` | Resolver | Intent + RBAC gateway |
| `neuro-agent-claude` | Kevin (Worker) | AI processing |
| `neuro-connector-slack` | Slack connector | Socket Mode |
| `neuro-connector-email` | Email/M365 connector | Graph API |
| `neuro-connector-entraid` | EntraID connector | Graph API |
| `neuro-connector-wazuh` | Wazuh Desktop | wazuh-dt instance |
| `neuro-connector-wazuh-infra` | Wazuh Infrastructure | wazuh-inf instance |
| `neuro-connector-zendesk` | ZenDesk connector | Ticket API |
| `neuro-connector-meraki` | Meraki connector | Runs outside Compose (`docker run`) |
| `neuro-connector-powershell` | PowerShell/WinRM | Remote execution |

## Key Design Decisions

1. **RabbitMQ over direct calls**: Loose coupling, async processing, replay capability
2. **Hybrid intent classification**: Regex first (instant, free), LLM fallback (5s, ~$0.0001)
3. **Header-based action detection**: Kevin includes `**Ticket Subject:**` etc. in responses — worker parses and dispatches regardless of intent classification
4. **Query cache for follow-ups**: "Create a ticket with those results" works because the M365 data is cached in PostgreSQL for 30 minutes
5. **Auto-populate assets**: Every Wazuh/Meraki data query automatically upserts devices into `knowledge.assets`
6. **User token for Slack**: Kevin appears as a real user, not a bot — conversations feel natural
7. **DM privacy**: Kevin only responds in DM channels where he is a verified participant
8. **[SYSTEM DATA] cap at 16KB**: Smart formatters summarize large datasets; full data cached in KB for follow-ups

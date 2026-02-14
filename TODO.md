# NeuroNet — Project TODO

*Last updated: February 14, 2026*

---

## 🔴 Critical — Fix Now

- [ ] **EntraID connector** — Build and deploy. Users asking about risky logins, user profiles, sign-in logs get no data. Graph permissions granted (read-only): `IdentityRiskEvent.Read.All`, `IdentityRiskyUser.Read.All`, `AuditLog.Read.All`, `UserAuthenticationMethod.Read.All`, `Directory.Read.All`
- [ ] **Hallucination hardening** — Kevin still occasionally fabricates data when context is ambiguous. Anti-hallucination prompt and NO DATA injection added but needs continued testing. Monitor closely.
- [ ] **Wazuh infra queue naming bug** — Queue is `neuro.connector-connector-wazuh.inbox` (doubled prefix). Service name `connector-wazuh-infra` gets `connector-` prepended again in `setup_queues`. Cosmetic but confusing.

---

## 🟡 High Priority

### Deployment & Infrastructure

- [ ] **Harden & simplify deployment** — Current setup requires manual Vault init, AppRole creation, secret seeding, .env configuration, and per-service docker-compose entries. Needs to be streamlined for repeatable installs and onboarding new environments.
- [ ] **Timeout handling for missing connectors** — Periodic timeout check added (`call_later` every 5s) but needs production testing. Verify Kevin always responds within 15s even when connectors are down.
- [ ] **Token renewal failures** — Scheduler logs `Token renewal failed: permission denied` every 30 minutes. May need `auth/token/renew-self` capability in Vault policy.
- [ ] **Daily Security Summary cron schedule** — Task ran when forced but `next_run` wasn't initialized correctly on creation. Verify it fires Monday Feb 16 at 8 AM UTC automatically.

### Conductor — Admin Portal & Install Wizard

- [ ] **Conductor web service** — Full-stack web app (FastAPI + React) that serves as the setup wizard and ongoing admin portal for NeuroNet.

#### Setup Wizard (first-run experience)
- [ ] Vault initialization — auto-unseal config, root token, enable KV engine
- [ ] Database migrations — create schemas (iam, knowledge, audit), seed tables
- [ ] RabbitMQ setup — vhost, exchanges, user credentials
- [ ] Connector marketplace — browse available connectors, select which to enable
- [ ] Per-connector config forms — API URLs, credentials, instance labels, test connection
- [ ] Agent builder — select AI model, name, persona, avatar, system prompt, connector access
- [ ] RBAC bootstrap — import users from EntraID/CSV, assign initial roles
- [ ] Auto-generate `.env`, AppRole credentials, Vault policies
- [ ] One-click deploy — spin up selected containers via Docker API

#### Health & Monitoring
- [ ] Real-time service status dashboard (container state, RabbitMQ consumer counts)
- [ ] Container metrics — CPU, memory, uptime, restart count per service
- [ ] RabbitMQ dashboard — queue depth, consumer counts, message rates, dead letters
- [ ] API latency tracking — Claude/Grok/ChatGPT response times per request
- [ ] Cost dashboard — token usage per agent, per model, per day, estimated monthly spend
- [ ] Alerting — service down, queue backup, cost threshold, error rate spike
- [ ] Notification channels — email, Slack, webhook with escalation rules

#### Audit & Compliance
- [ ] Searchable audit log viewer — filter by user, action, resource, time range, outcome
- [ ] RBAC denial report — who tried what and was blocked
- [ ] AI usage report — queries per user, tokens consumed, cost by model
- [ ] Export to CSV/PDF for SOC2 audits
- [ ] Hash chain verification status and integrity checks
- [ ] Data retention policies — auto-archive old audit entries

#### Agent Management
- [ ] Agent list with status, model, token usage, last activity
- [ ] Create new agent — name, persona, system prompt editor (with preview), model selection, avatar
- [ ] Assign connectors per agent (which data sources it can access)
- [ ] Assign RBAC scope per agent (which roles can talk to it)
- [ ] Knowledge base manager — view, add, edit, delete, import entries per agent
- [ ] Scheduled tasks manager — create, modify, enable/disable, view run history per agent
- [ ] Test chat — talk to any agent directly from the portal
- [ ] Agent templates — pre-built configs for common use cases (security, engineering, finance, HR)

#### Connector Management
- [ ] Connector list with health, last activity, error count
- [ ] Add new connector — pick type from registry, enter credentials, test connection
- [ ] Edit connector config — hot-reload without full restart where possible
- [ ] Enable/disable connectors without removing
- [ ] Per-connector metrics — queries served, errors, avg response time
- [ ] Credential rotation — update secrets in Vault, restart connector

#### Users & RBAC
- [ ] User directory (synced from EntraID or manual)
- [ ] Role assignment UI — drag users into roles
- [ ] Role editor — create custom roles, define resource permissions per agent
- [ ] Sync controls — force re-sync from EntraID, view sync history
- [ ] Per-user activity log — what did they ask, what data did they access

#### Settings
- [ ] Vault policy editor with syntax highlighting
- [ ] RabbitMQ exchange/routing configuration
- [ ] Email settings (sender address, Graph/SMTP config)
- [ ] Slack workspace configuration
- [ ] Backup & restore — database dumps, Vault snapshots, one-click restore
- [ ] Update management — pull new images, rolling restart, version tracking

### Multi-Agent Support

- [ ] **Agent abstraction layer** — Refactor `agent-worker-claude` into a generic agent worker that loads persona, model, and connector config from database/Conductor
- [ ] **Multi-agent routing** — Resolver routes to the correct agent based on Slack bot identity, channel, or user intent
- [ ] **Agent personas:**
  - **Kevin Tutela** (Security) — Wazuh, EntraID, email investigation, security alerts
  - **Engineering agent** — GitHub/GitLab, CI/CD pipelines, Jira/Linear, code review, incident response
  - **Finance agent** — ERP/accounting data, expense reports, budget tracking, forecasting
  - **HR agent** — Onboarding workflows, PTO tracking, policy questions, benefits
  - **IT Helpdesk agent** — Ticket triage, password resets, device management, FAQ
- [ ] Each agent gets its own Slack bot identity, RBAC scope, Vault policy, and knowledge base
- [ ] Shared infrastructure (RabbitMQ, Vault, PostgreSQL) with isolated data per agent

### Agent Service Modes (Trust Levels)

Each agent progresses through trust levels as it proves reliability in the environment. Admins promote/demote agents via Conductor. Mode is enforced at the Resolver level before any action is dispatched.

- [ ] **Mode 1 — Observer (Read-Only)**
  - Agent can only read and analyze data — no write actions of any kind
  - Queries: alerts, logs, user profiles, dashboards, reports
  - Messaging: can respond in Slack/Teams conversations
  - Purpose: learn the environment, people, procedures, naming conventions, normal baselines
  - All agents start here on initial deployment
  - Builds knowledge base organically from interactions and scheduled data sweeps
  - Conductor shows "learning progress" — how many users interacted, topics covered, data sources explored

- [ ] **Mode 2 — Assisted (Human-in-the-Loop)**
  - Agent can propose write actions but every action requires human approval before execution
  - Proposals appear in a dedicated Slack channel or Conductor approval queue
  - Approval flow: Agent proposes → notification to approver(s) → approve/deny/modify → execute or cancel
  - Approved actions: disable account, revoke sessions, create ticket, send alert email, modify firewall rule, etc.
  - Messaging is unrestricted (no approval needed to respond in chat or send routine notifications)
  - Scheduled tasks can generate reports but proposed remediations require approval
  - Audit trail tracks: who approved, when, original proposal vs. what was executed
  - Timeout: if no approval within configurable window (e.g., 1 hour), action expires with notification

- [ ] **Mode 3 — Autonomous (Supervised)**
  - Agent can execute certain pre-approved action categories without human approval
  - Admin configures which actions are auto-approved vs. still require review per agent:
    - **Auto-approved examples:** send notification emails, create low-priority tickets, block known-malicious IPs, force password reset on compromised accounts
    - **Still requires approval:** disable user accounts, modify security policies, access sensitive mailboxes, make financial transactions, deploy code changes
  - High-severity or unusual actions still routed to approval queue (anomaly detection on agent behavior)
  - All autonomous actions logged with full audit trail and rollback capability where possible
  - Conductor dashboard shows: actions taken autonomously vs. approved vs. denied, with success/failure rates

- [ ] **Mode 4 — Trusted (Full Autonomy)**
  - Reserved for mature agents with proven track record
  - All actions within the agent's RBAC scope are auto-executed
  - Emergency brake: admin can instantly demote any agent back to Observer from Conductor
  - Anomaly detection: if agent behavior deviates significantly from baseline (e.g., sudden spike in account disables), auto-demote to Assisted and alert admins
  - Periodic review: Conductor prompts admins to review Trusted agents quarterly

- [ ] **Mode transitions:**
  - Promotion requires admin approval in Conductor with justification
  - Demotion can be instant (emergency) or scheduled
  - Mode history tracked in audit log
  - Conductor recommends promotion when metrics indicate readiness (e.g., "Kevin has been in Observer for 30 days with 500+ interactions and zero hallucination incidents — consider promoting to Assisted")
  - Automatic demotion triggers: hallucination detected, unauthorized action attempt, error rate spike, admin override

- [ ] **Resolver enforcement:**
  - Resolver checks agent mode before dispatching any write action
  - Observer: block all write routing keys, return "I can analyze this but can't take action yet — I'm currently in observation mode"
  - Assisted: route write actions to approval queue instead of directly to connector
  - Autonomous: check action against auto-approved list, route accordingly
  - Trusted: route directly to connector

### Agent Learning, Training & Context Retention

Kevin loses conversation context because of three compounding issues. These fixes apply to all agents.

#### Problem 1: Short conversation window
- Slack connector only sends last 10 messages as history
- With Kevin's verbose replies + [SYSTEM DATA] blocks, that's ~3-4 conversational turns
- Once a topic scrolls out of this window, Kevin has zero recall

#### Problem 2: Knowledge extraction is too selective
- Only extracts from security-related conversations with data context
- Skips general chitchat and short messages
- Doesn't extract investigation context ("we were looking at mchen's account")
- Doesn't store what the user asked Kevin to do or what was discussed

#### Problem 3: Knowledge retrieval is keyword-based
- Full-text search only matches if exact words overlap
- No semantic search — "tell me about that risky user" won't match a stored fact about mchen
- No awareness of active investigations or ongoing conversations

#### Fixes — Conversation Context

- [ ] **Conversation summary table** — New `knowledge.conversations` table that stores a running summary per user per session. After every exchange, use Haiku to update a 200-word summary of "what we've been discussing." Inject this as context on every message.
  ```sql
  CREATE TABLE knowledge.conversations (
    id SERIAL PRIMARY KEY,
    user_email VARCHAR(255) NOT NULL,
    agent_id VARCHAR(100) NOT NULL,
    channel_id VARCHAR(100),
    summary TEXT,           -- Rolling summary of conversation
    key_entities TEXT[],    -- Users, hosts, IPs mentioned
    open_questions TEXT[],  -- Things user asked that aren't resolved
    last_action TEXT,       -- Last thing Kevin did or recommended
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ  -- Auto-expire after 24h of inactivity
  );
  ```

- [ ] **Increase DM history to 20-30 messages** — More turns in the sliding window. Balance against token cost.

- [ ] **Smart history compression** — Instead of raw messages, use Haiku to compress older messages into a summary. Send: [summary of earlier conversation] + [last 10 raw messages]. This gives Kevin awareness of the full conversation without blowing up the context window.

- [ ] **Session continuity** — Track "active session" per user. If a user messages Kevin within 30 minutes of their last message, treat it as the same conversation and inject the conversation summary. After 30 min gap, start fresh but still have access to knowledge base.

#### Fixes — Knowledge Extraction

- [ ] **Extract from ALL conversations** — Remove the filter that skips general/short messages. Every interaction may contain useful context.
- [ ] **Extract investigation state** — When Kevin is investigating something (risky user, alert, incident), store the investigation context: who, what, current findings, next steps, user's instructions.
- [ ] **Extract user preferences** — How they like reports formatted, what they care about, their team, their responsibilities.
- [ ] **Extract decisions and outcomes** — "Billy decided to disable mchen's account" — important to remember.
- [ ] **Deduplication** — Current `ON CONFLICT DO NOTHING` means facts never update. Switch to upsert that merges/updates existing facts with new info.
- [ ] **Confidence scoring** — Facts from explicit "remember this" get high confidence. Facts extracted implicitly start lower and increase with repeated references.

#### Fixes — Knowledge Retrieval

- [ ] **Semantic search (embeddings)** — Add a vector column to `knowledge.entries`. Use an embedding model (Anthropic voyage, OpenAI ada, or local) to embed facts. Retrieve by cosine similarity instead of keyword match. This lets "that risky user we discussed" find the mchen entry.
- [ ] **Active investigation context** — Always inject any open/active investigation entries for the current user, regardless of keyword match.
- [ ] **User-specific context** — Always inject facts tagged with the current user's email (their preferences, past questions, their team).
- [ ] **Recency boost** — Recently stored facts get retrieval priority over old ones.

#### Fixes — Training & Onboarding

- [ ] **Environment learning mode** — When agent is in Observer mode, schedule regular data sweeps that build the knowledge base:
  - Crawl EntraID for org structure, departments, managers
  - Crawl Wazuh for host inventory, network topology, normal alert baselines
  - Index email distribution lists and key contacts
  - Store naming conventions, IP ranges, server roles
- [ ] **Admin-provided context** — Conductor UI for admins to directly add knowledge entries: "Our CFO is Jane Smith", "The finance servers are in the 10.20.x.x range", "We use Jira for ticketing"
- [ ] **Feedback loop** — When Kevin gets something wrong and the user corrects him, extract the correction as a high-confidence fact. "No, mchen is in Engineering not Finance" → update the stored fact.
- [ ] **Runbook ingestion** — Upload SOPs, runbooks, incident response plans as documents. Parse and store as structured knowledge entries that Kevin can reference.
- [ ] **Periodic knowledge review** — Conductor shows all stored knowledge per agent. Admins can verify, correct, or delete entries. Flag low-confidence entries for review.

- [ ] **Model-agnostic worker** — Abstract the AI worker to support multiple LLM providers behind a unified interface
- [ ] **Anthropic (Claude)** — Currently implemented. Sonnet 4.5 default, Opus 4.6 for premium tasks
- [ ] **xAI (Grok)** — Grok-2/Grok-3 API integration. Store API key in Vault under `xai` secret
- [ ] **OpenAI (ChatGPT)** — GPT-4o / GPT-5 / o1 API integration. Store API key in Vault under `openai` secret
- [ ] **Google (Gemini)** — Gemini 2.0 API integration for orgs in the Google ecosystem
- [ ] **Ollama / Local models** — Support self-hosted open models (Llama, Mistral, etc.) for air-gapped or cost-sensitive deployments
- [ ] **Per-agent model assignment** — Each agent can use a different model (e.g., Kevin on Claude Opus, engineering agent on GPT-4o, helpdesk on Grok)
- [ ] **Per-task model selection** — Scheduled tasks and conversational queries can use different models (Opus for daily summaries, Sonnet for chat)
- [ ] **Model fallback chain** — If primary model API is down, auto-fall back to secondary (e.g., Claude → Grok → GPT)
- [ ] **Cost comparison** — Track spend per model in Conductor dashboard, recommend optimal model per use case
- [ ] **Prompt adaptation layer** — Each provider may need different system prompt formatting. Abstract prompt templates per provider.
- [ ] **Unified response normalization** — Normalize different API response formats into a single internal format for the rest of the pipeline

---

## 🟢 Medium Priority

### Existing Connectors — Enhancements

- [ ] **EntraID write actions** — `User.ReadWrite.All` to disable accounts, `User.RevokeSessions.All` to revoke sessions. Enable after hallucination issue is fully resolved.
- [ ] **OneDrive/SharePoint connector** — M365 Graph API for searching org documents, file metadata, sharing permissions
- [ ] **Teams connector** — Query Teams messages, channel history for investigation
- [ ] **Kevin should query IAM directly for roles** — Currently uses knowledge base entry. Should query `iam.user_roles` table when asked "who has access to X"

### New Connectors — Security & Infrastructure

- [ ] **CrowdStrike/SentinelOne connector** — EDR alerts, threat intelligence, device quarantine
- [ ] **Qualys/Tenable connector** — Vulnerability scan results, compliance reports
- [ ] **PagerDuty/OpsGenie connector** — Incident management, on-call schedules, alert routing
- [ ] **Splunk/Elastic connector** — Alternative SIEM log search for orgs not using Wazuh
- [ ] **Okta connector** — Alternative identity provider for non-Microsoft orgs
- [ ] **AWS connector** — CloudWatch logs, EC2 status, S3 access logs, IAM analysis, cost explorer
- [ ] **Azure connector** — Azure Monitor, VM status, resource health, cost management
- [ ] **Intune/JAMF connector** — Device compliance, software inventory, patch status

### New Connectors — Engineering & DevOps

- [ ] **GitHub connector** — Repos, PRs, issues, commits, Actions status, code search
- [ ] **GitLab connector** — Same as GitHub for GitLab-based orgs
- [ ] **Jira connector** — Tickets, sprints, backlogs, workload, SLA tracking
- [ ] **Linear connector** — Modern alternative to Jira for engineering teams
- [ ] **Confluence connector** — Wiki search, documentation lookup, runbook retrieval
- [ ] **Notion connector** — Alternative wiki/docs connector
- [ ] **ServiceNow connector** — ITSM tickets, CMDB, change management
- [ ] **Docker/Kubernetes connector** — Container status, pod health, deployment management

### New Connectors — Business & Finance

- [ ] **Salesforce connector** — CRM data, pipeline, accounts, opportunities
- [ ] **HubSpot connector** — Alternative CRM for SMBs
- [ ] **QuickBooks connector** — Accounting data, invoices, P&L
- [ ] **Xero connector** — Alternative accounting for international orgs
- [ ] **BambooHR connector** — HR data, PTO, org chart, onboarding
- [ ] **Workday connector** — Enterprise HR and finance

### New Connectors — Communication

- [ ] **Microsoft Teams connector** — Bot in Teams as alternative/addition to Slack
- [ ] **Discord connector** — For dev/gaming-oriented teams
- [ ] **Webhook connector** — Generic inbound/outbound webhooks for custom integrations
- [ ] **SMS/Twilio connector** — Text-based alerts and interactions

### Infrastructure Hardening

- [ ] **TLS everywhere** — RabbitMQ, Vault, PostgreSQL all running unencrypted. Add TLS for production.
- [ ] **Vault auto-unseal** — AWS KMS, Azure Key Vault, or transit-based auto-unseal
- [ ] **Rate limiting** — Per-user rate limits on agent interactions to prevent abuse and control API costs
- [ ] **Monitoring/alerting** — Prometheus metrics, Grafana dashboards (may be superseded by Conductor dashboard)

---

## 🔵 Nice to Have

- [ ] **Kevin personality tuning** — Continue refining tone, reduce verbosity, improve context retention
- [ ] **Slack thread support** — Threaded conversations for complex investigations
- [ ] **Interactive Slack actions** — Buttons for "Disable account", "Revoke sessions", "Run full scan"
- [ ] **Knowledge base auto-pruning** — Confidence decay over time, auto-archive stale entries
- [ ] **Multi-tenant support** — Isolated orgs sharing the same NeuroNet deployment
- [ ] **Backup strategy** — PostgreSQL backups, Vault backup, audit log archival to cold storage
- [ ] **Plugin SDK** — Standardized interface for third-party connector development using NeuroKit
- [ ] **Connector marketplace** — Community-contributed connectors installable from Conductor UI
- [ ] **Agent template marketplace** — Share and import agent personas (security, DevOps, finance, etc.)
- [ ] **Mobile app** — Push notifications for critical alerts, quick agent chat on the go
- [ ] **Voice interface** — Talk to agents via Slack huddles or phone integration
- [ ] **RAG pipeline** — Ingest org documents into vector store for enhanced agent knowledge retrieval
- [ ] **Multi-language support** — Agents respond in the user's preferred language

---

## ✅ Completed

- [x] NeuroKit v0.2.0 — shared library for all services
- [x] RabbitMQ message bus with topic + fanout exchanges
- [x] HashiCorp Vault with AppRole per service
- [x] PostgreSQL with IAM, knowledge, and audit schemas
- [x] Vault-IAM service — 420 users synced from EntraID
- [x] RBAC enforcement in resolver
- [x] Slack connector with Socket Mode + DM history
- [x] Wazuh connector (desktops) — alerts, agents, vulnerabilities, FIM
- [x] Wazuh connector (infrastructure) — second instance with env-var config
- [x] Email connector — send, search mailboxes, org-wide search
- [x] Scheduler — alert sweep, daily summary, critical monitor
- [x] Claude worker with role-based prompts and knowledge base
- [x] Audit trail — PostgreSQL + daily JSONL files
- [x] Anti-hallucination prompt + NO DATA injection
- [x] NeuroNet health awareness — Kevin knows what's online/offline
- [x] User identity injection — Kevin knows who he's talking to
- [x] Dual Wazuh instances with labeled responses
- [x] Scheduler Vault policy fix (wazuh secret access)
- [x] Architecture diagram

---

*Managed by: Billy Felton & Claude | Host: hal (Ubuntu 24)*

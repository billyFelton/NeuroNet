# NeuroNet Data Access Policy

## Role Definitions

| Role | Who | Purpose |
|------|-----|---------|
| **security-admin** | Security team leads, CISO | Full access, investigations, response actions |
| **security-analyst** | SOC analysts, security engineers | Monitor, investigate, analyze — no destructive actions |
| **it-support** | Helpdesk, IT staff | Same visibility as analyst for troubleshooting — read-only, no write actions |
| **general-user** | All other employees | Security awareness, general help. Knows Kevin assists the security team but no details |

## Data Access Matrix

### Wazuh — Security Alerts

| Capability | security-admin | security-analyst | it-support | general-user |
|-----------|:-:|:-:|:-:|:-:|
| View alert summaries (both instances) | ✅ | ✅ | ✅ | ❌ |
| View alert details / deep dive | ✅ | ✅ | ✅ | ❌ |
| Filter alerts by host/severity/rule | ✅ | ✅ | ✅ | ❌ |
| View alert trends / statistics | ✅ | ✅ | ✅ | ❌ |

### Wazuh — Agent Health & Status

| Capability | security-admin | security-analyst | it-support | general-user |
|-----------|:-:|:-:|:-:|:-:|
| View agent list and status | ✅ | ✅ | ✅ | ❌ |
| View agent details (OS, version, IP) | ✅ | ✅ | ✅ | ❌ |
| View disconnected/inactive agents | ✅ | ✅ | ✅ | ❌ |

### Wazuh — Vulnerability Data

| Capability | security-admin | security-analyst | it-support | general-user |
|-----------|:-:|:-:|:-:|:-:|
| View vulnerability summaries | ✅ | ✅ | ✅ | ❌ |
| View vulnerability details by host | ✅ | ✅ | ✅ | ❌ |
| View CVE details and remediation | ✅ | ✅ | ✅ | ❌ |

### Email — Kevin's Mailbox

| Capability | security-admin | security-analyst | it-support | general-user |
|-----------|:-:|:-:|:-:|:-:|
| Kevin sends/replies to email | ✅ | ✅ | ❌ | ❌ |
| View Kevin's inbox | ✅ | ✅ | ❌ | ❌ |

### Email — Org-wide Mailbox Search

| Capability | security-admin | security-analyst | it-support | general-user |
|-----------|:-:|:-:|:-:|:-:|
| Search other users' mailboxes | ✅ | ❌ | ❌ | ❌ |
| View email content from search | ✅ | ❌ | ❌ | ❌ |

### EntraID / IAM — User Profiles

| Capability | security-admin | security-analyst | it-support | general-user |
|-----------|:-:|:-:|:-:|:-:|
| Look up any user profile | ✅ | ✅ | ✅ | ❌ |
| View group memberships | ✅ | ✅ | ✅ | ❌ |
| View sign-in logs | ✅ | ✅ | ✅ | ❌ |
| View MFA status | ✅ | ✅ | ✅ | ❌ |

### Write Actions (Current + Future)

| Capability | security-admin | security-analyst | it-support | general-user |
|-----------|:-:|:-:|:-:|:-:|
| Disable user account | ✅ | ❌ | ❌ | ❌ |
| Enable user account | ✅ | ❌ | ❌ | ❌ |
| Revoke user sessions | ✅ | ❌ | ❌ | ❌ |
| Reset user password | ✅ | ❌ | ❌ | ❌ |
| Block IP address | ✅ | ❌ | ❌ | ❌ |
| Isolate host | ✅ | ❌ | ❌ | ❌ |
| Create/modify firewall rules | ✅ | ❌ | ❌ | ❌ |

### Knowledge & Context

| Capability | security-admin | security-analyst | it-support | general-user |
|-----------|:-:|:-:|:-:|:-:|
| Security knowledge base (hosts, incidents, assets) | ✅ | ✅ | ✅ | ❌ |
| NeuroNet system health status | ✅ | ✅ | ✅ | ❌ |
| Conversation memory (personal) | ✅ | ✅ | ✅ | ✅ |
| User profile memory (preferences) | ✅ | ✅ | ✅ | ✅ |
| Security awareness guidance | ✅ | ✅ | ✅ | ✅ |

## Kevin's Behavior by Role

### security-admin
- Full access to all data sources and actions
- Can investigate users, search mailboxes, take response actions
- Kevin proactively highlights risks and recommends actions
- Kevin will execute write actions when asked (with confirmation)

### security-analyst
- Full read access to all security data
- Can investigate alerts, users, vulnerabilities
- Can use Kevin's email for security communications
- **Cannot** search other users' mailboxes
- **Cannot** take any write/destructive actions
- Kevin will explain what actions *could* be taken but refer to security-admin to execute

### it-support
- Same read visibility as security-analyst for troubleshooting
- Can look up users, check agent health, review alerts
- **Cannot** use Kevin's email capabilities
- **Cannot** search other users' mailboxes
- **Cannot** take any write actions
- Kevin helps with device troubleshooting, agent issues, user account questions

### general-user
- Security awareness education only
- Kevin is a helpful assistant who also works with the security team
- **No access** to any security data, monitoring, or internal tools
- **Does not reveal** tool names, architecture, or what is monitored
- Redirects security data requests to the Heads Up security team
- Follows up with "Are you experiencing any technical issues?"
- Can discuss: phishing, password hygiene, threat trends, safe practices, reporting procedures

## Enforcement Points

1. **Resolver** — Checks role before routing data queries to connectors
2. **Claude Worker** — Selects role-appropriate system prompt, controls context injection
3. **Vault-IAM** — Resolves roles from EntraID group mappings
4. **Audit Log** — All requests logged with role, intent, and data accessed

## Role Assignment

Roles are derived exclusively from EntraID group membership:

| EntraID Group | NeuroNet Role |
|---------------|---------------|
| Security-Admins | security-admin |
| Security-Analysts | security-analyst |
| IT-Support | it-support |
| *(no matching group)* | general-user |

No manual role assignment. Remove someone from the EntraID group → next sync (5 min) → role revoked automatically.

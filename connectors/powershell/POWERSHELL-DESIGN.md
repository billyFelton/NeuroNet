# PowerShell / WinRM Connector

## Overview

Gives Kevin the ability to execute PowerShell commands on any domain-joined 
Windows machine via WinRM. All commands require human approval before execution.
Security-admin only.

## Architecture

```
User (Slack) → Resolver → Claude Worker → RabbitMQ → PowerShell Connector
                                                            ↓
                                                     Approval Queue (Slack)
                                                            ↓
                                                     Admin approves/denies
                                                            ↓
                                                     WinRM → Target Machine
                                                            ↓
                                                     Results → Claude Worker → User
```

## Flow

### 1. User Request
"Kevin, can you check what processes are running on DESKTOP-TICJH0K?"

### 2. Kevin Proposes Command
Kevin generates the PowerShell command based on the request:
```
Target: DESKTOP-TICJH0K
Command: Get-Process | Select-Object ProcessName, Id, CPU, WorkingSet | Sort-Object CPU -Descending | Format-Table -AutoSize
Reason: User requested process list for investigation
```

### 3. Approval Request
Posted to #security-approvals Slack channel (or DM to requester):
```
🔒 PowerShell Execution Request
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Requested by: Billy Felton (security-admin)
Target host:  DESKTOP-TICJH0K
Command:
  Get-Process | Select-Object ProcessName, Id, CPU, WorkingSet | 
  Sort-Object CPU -Descending | Format-Table -AutoSize
Reason: User requested process list for investigation

React ✅ to approve or ❌ to deny
Expires in 10 minutes
```

### 4. Execution
On approval, connector executes via WinRM and returns results to Kevin.
On denial or timeout, Kevin tells the user the command was not approved.

### 5. Kevin Presents Results
Kevin analyzes the output and presents findings conversationally.

## Connector Design

### Service: connector-powershell

**Queue:** neuro.connector-powershell.inbox
**Bindings:** powershell.execute

**Message Types:**
- `powershell.execute` — Execute a command (requires approval)
- `powershell.result` — Results returned to AI worker

**Authentication:**
- Service account with WinRM access to domain machines
- Kerberos or NTLM authentication via domain credentials
- Credentials stored in Vault: `neuro-secrets/powershell`

**Vault Secrets:**
```
neuro-secrets/powershell:
  domain: headsup.local
  username: svc-neuronet-ps
  password: <stored in vault>
  auth_method: kerberos    # or ntlm
  port: 5985               # http WinRM (5986 for https)
  use_ssl: true
```

### Approval System

**Approval Queue:** `neuro.approvals.inbox`
**Approval Channel:** #security-approvals (Slack)

Approval flow:
1. Connector receives execute request
2. Stores pending command in `knowledge.pending_approvals` table
3. Posts approval request to Slack channel via Slack connector
4. Waits for reaction (✅ or ❌) or timeout (10 min default)
5. On approve: execute, store result, publish to AI
6. On deny/timeout: publish denial to AI

### Database Tables

```sql
CREATE TABLE knowledge.powershell_executions (
    id SERIAL PRIMARY KEY,
    request_id UUID NOT NULL UNIQUE,
    requested_by VARCHAR(255) NOT NULL,    -- email of requester
    target_host VARCHAR(255) NOT NULL,
    command TEXT NOT NULL,
    reason TEXT DEFAULT '',
    
    -- Approval
    status VARCHAR(50) DEFAULT 'pending',  -- pending, approved, denied, expired, 
                                           -- executing, completed, failed
    approved_by VARCHAR(255),
    approved_at TIMESTAMPTZ,
    
    -- Execution
    output TEXT,
    error_output TEXT,
    exit_code INT,
    execution_time_ms INT,
    executed_at TIMESTAMPTZ,
    
    -- Audit
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
```

### Safety Guardrails

1. **All commands require human approval** — no exceptions
2. **Timeout** — unapproved commands expire after 10 minutes
3. **Audit trail** — every command, approval, and result logged
4. **Command sanitization** — block obvious destructive patterns:
   - `Format-C`, `Remove-Item -Recurse`, `Stop-Computer`
   - `Invoke-Expression` with encoded payloads
   - Registry deletions
   - Service account creation
   (These get auto-denied, not even sent for approval)
5. **Rate limiting** — max 10 pending commands per user per hour
6. **Output truncation** — results capped at 50KB to prevent flooding
7. **Credential isolation** — WinRM credentials never leave the connector
8. **Network scoping** — connector can only reach internal network

### Pre-built Investigation Commands

Kevin would have a library of common investigation commands he can propose:

**Process Investigation:**
- `Get-Process | Sort-Object CPU -Descending | Select -First 20`
- `Get-Process | Where-Object {$_.StartTime -gt (Get-Date).AddHours(-1)}`
- `Get-WmiObject Win32_Process | Select Name, ProcessId, ParentProcessId, CommandLine`

**Network Investigation:**
- `Get-NetTCPConnection | Where-Object State -eq 'Established'`
- `Get-NetTCPConnection | Where-Object RemotePort -notin 80,443`
- `Get-DnsClientCache | Sort-Object Entry`

**User/Account Investigation:**
- `Get-LocalUser`
- `Get-LocalGroupMember -Group "Administrators"`
- `Get-WinEvent -LogName Security -MaxEvents 50 | Where-Object Id -in 4624,4625,4634`

**Service Investigation:**
- `Get-Service | Where-Object Status -eq 'Running'`
- `Get-ScheduledTask | Where-Object State -eq 'Ready'`
- `Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`

**File System:**
- `Get-ChildItem -Path C:\Users\* -Include *.exe -Recurse -ErrorAction SilentlyContinue`
- `Get-ChildItem -Path C:\Temp -Recurse | Sort-Object LastWriteTime -Descending`

### RBAC

- Resource: `powershell-execute`
- Action: `execute`
- Only `security-admin` gets this permission
- Resolver blocks before it even reaches the connector for other roles

### Future Enhancements

- **Auto-approve safe commands** — promote read-only commands like Get-Process 
  to auto-approved after confidence is built
- **Command templates** — structured investigation playbooks
- **Batch execution** — run same command across multiple hosts
- **Live session** — interactive PowerShell session (complex, needs websocket)
- **Linux support** — SSH connector for Linux hosts using same approval flow

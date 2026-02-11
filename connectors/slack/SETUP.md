# Slack Agent Setup Guide

## Overview

The Neuro-Network Slack agent operates as a **real workspace user**, not a bot.
Messages appear from a normal team member account with no "APP" badge.

## Step 1: Create the Agent User Account

Create a dedicated Slack workspace account for the agent:

- **Email**: `neuro-agent@yourcompany.com` (or similar)
- **Display Name**: Choose something your team will recognize (e.g., "Aria", "Atlas", "Neuro")
- **Avatar**: Set a distinctive but professional profile picture
- **Title**: "AI Security Assistant" or similar

This account needs a paid Slack seat.

## Step 2: Create the Slack App

1. Go to https://api.slack.com/apps
2. Click **Create New App** → **From scratch**
3. Name it something internal (e.g., "Neuro Agent Backend") — users won't see this
4. Select your workspace

### Enable Socket Mode

1. Go to **Socket Mode** in the left sidebar
2. Toggle **Enable Socket Mode** ON
3. Generate an **App-Level Token** with the `connections:write` scope
4. Save this token — it goes into HashiCorp Vault as `slack/app_level_token`

### Configure OAuth Scopes (User Token Scopes)

Go to **OAuth & Permissions**. Under **User Token Scopes** (NOT Bot Token Scopes), add:

**Required scopes:**
| Scope | Purpose |
|---|---|
| `channels:history` | Read messages in public channels |
| `channels:read` | List and get channel info |
| `chat:write` | Post messages as the agent user |
| `groups:history` | Read messages in private channels the agent is in |
| `groups:read` | List private channels |
| `im:history` | Read DM messages |
| `im:read` | List DMs |
| `im:write` | Open DMs |
| `mpim:history` | Read group DM messages |
| `mpim:read` | List group DMs |
| `reactions:read` | See reactions on messages |
| `reactions:write` | Add/remove reactions |
| `users:read` | Get user info for identity resolution |
| `users:read.email` | Get user email for EntraID mapping |
| `users.profile:write` | Set agent's online status |

### Configure Event Subscriptions

Go to **Event Subscriptions**:

1. Toggle **Enable Events** ON
2. Under **Subscribe to events on behalf of users**, add:
   - `message.channels` — Messages in public channels
   - `message.groups` — Messages in private channels
   - `message.im` — Direct messages
   - `message.mpim` — Group direct messages
   - `app_mention` — When someone @mentions the agent (optional — also caught via message events)
   - `reaction_added` — Emoji reaction triggers

## Step 3: Install and Authorize as the Agent User

This is the critical step. You must install the app **while logged in as the agent user account**.

1. Log into Slack **as the agent user** (e.g., `neuro-agent@yourcompany.com`)
2. Go to the app's **Install App** page
3. Click **Install to Workspace**
4. Authorize the requested scopes
5. Copy the **User OAuth Token** (starts with `xoxp-`)

This `xoxp-` token is what allows the connector to act as the agent user.

## Step 4: Store Secrets in HashiCorp Vault

Store both tokens in HashiCorp Vault under the `slack` path:

```bash
vault kv put neuro-secrets/slack \
  user_token="xoxp-your-user-oauth-token" \
  app_level_token="xapp-your-app-level-token"
```

Create an AppRole policy for the Slack connector:

```hcl
# policies/connector-slack.hcl
path "neuro-secrets/data/slack" {
  capabilities = ["read"]
}
path "neuro-secrets/data/slack/*" {
  capabilities = ["read"]
}
```

```bash
vault policy write connector-slack policies/connector-slack.hcl
vault write auth/approle/role/connector-slack \
  token_policies="connector-slack" \
  token_ttl=1h \
  token_max_ttl=4h
```

## Step 5: Map Slack Users to EntraID

For RBAC to work, Slack user IDs need to be mapped to EntraID identities.
The Vault-IAM `identity_mappings` table handles this.

**Option A: Automatic mapping by email**
The Slack connector can look up a user's email via the `users:read.email` scope,
then Vault-IAM matches it to the EntraID user with the same email.

**Option B: Manual mapping**
Insert mappings directly:
```sql
INSERT INTO iam.identity_mappings (provider, external_id, user_id, verified)
VALUES ('slack', 'U12345ABC', 'entraid-object-id-uuid', true);
```

**Option C: Self-service verification**
Users DM the agent with a verification command, and the agent sends a
verification email to their EntraID address. Not yet implemented.

## Step 6: Invite the Agent to Channels

The agent user needs to be invited to (or join) any channels where it should
be able to respond:

- Invite to security channels: `/invite @Aria`
- Invite to support channels as needed
- DMs work automatically — anyone can DM the agent

## Agent Behavior

| Trigger | Response |
|---|---|
| Direct message | Always responds |
| @mention in channel | Always responds |
| Reply in active thread | Responds (maintains conversation) |
| Keyword match in monitored channel | Responds (configurable) |
| Emoji reaction trigger | Analyzes the reacted message |
| Unprompted in channel | Silent — never speaks unsolicited |

### Reaction Indicators

| Emoji | Meaning |
|---|---|
| :eyes: | "I see your message, processing..." |
| :white_check_mark: | "Done — response sent" |
| :warning: | "I understood but can't help with that (RBAC denial)" |
| :x: | "Something went wrong" |

## Troubleshooting

**Agent not responding to mentions:**
- Verify the agent user is a member of the channel
- Check Socket Mode is connected (container logs)
- Verify the `app_mention` event subscription is enabled

**Messages show as bot:**
- You're using a bot token (`xoxb-`) instead of user token (`xoxp-`)
- Reinstall the app while logged in as the agent user

**RBAC denials:**
- Check that the Slack user has an identity mapping in `iam.identity_mappings`
- Verify the user's EntraID account has appropriate roles assigned
- Check audit logs for the denial reason

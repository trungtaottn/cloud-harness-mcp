---
title: Getting Started Guide
description: Step-by-step walkthrough for opening a workspace, executing tools, and closing safely.
---

# Getting Started Guide

## The 4-Step Lifecycle

Working with Cloud Harness MCP follows a disciplined lifecycle:

```
1. Open Workspace ──► 2. Inspect & Code ──► 3. Test & Commit ──► 4. Close Workspace
```

---

### Step 1: Open a Workspace

Call `workspace_open` with a credential-free HTTPS repository URL and a random idempotency key:

```json
{
  "repositoryUrl": "https://github.com/my-org/my-project.git",
  "idempotencyKey": "init-2026-08-19-a1b2c3d4",
  "ref": "main"
}
```

**Response:**
```json
{
  "workspaceId": "ws_abcdef1234567890abcdef123456",
  "status": "ready",
  "expiresAt": "2026-08-19T10:15:00.000Z"
}
```

::: warning Keep the Workspace ID
Save the returned `workspaceId`. All subsequent tool invocations (reading files, executing tests, running git operations) require this identifier.
:::

---

### Step 2: Inspect Files & Code

List directory entries or search symbols:

```json
// Tool: files_list
{
  "workspaceId": "ws_abcdef1234567890abcdef123456",
  "path": "src"
}

// Tool: grep_search
{
  "workspaceId": "ws_abcdef1234567890abcdef123456",
  "pattern": "export function authenticate"
}
```

Edit files surgically or write new content:

```json
// Tool: files_write
{
  "workspaceId": "ws_abcdef1234567890abcdef123456",
  "path": "src/auth.ts",
  "content": "export function authenticate() { return true; }"
}
```

---

### Step 3: Run Tests & Commit

Execute test commands inside the container:

```json
// Tool: exec_run
{
  "workspaceId": "ws_abcdef1234567890abcdef123456",
  "command": "npm test"
}
```

Commit changes to the local branch:

```json
// Tool: git_commit
{
  "workspaceId": "ws_abcdef1234567890abcdef123456",
  "message": "feat(auth): implement token validation"
}
```

Push to origin (requires GitHub App installation):

```json
// Tool: git_push
{
  "workspaceId": "ws_abcdef1234567890abcdef123456",
  "refspec": "HEAD:refs/heads/feature/auth"
}
```

---

### Step 4: Finish or retain the Workspace

Close a disposable Docker workspace only after preserving the work you need.
For a retained Kata or InstaBox workspace, finish tasks and terminals, then
stop it so the checkout and installed software remain available for the same
workspace to resume. If work is incomplete, save or checkpoint what is useful
before stopping; do not close the workspace as a checkpoint operation.

Stop a retained workspace with `workspace_recover`:

```json
// Tool: workspace_recover
{
  "workspaceId": "ws_abcdef1234567890abcdef123456",
  "mode": "stop"
}
```

Use `workspace_close` only when you intend to release the workspace data:

```json
// Tool: workspace_close
{
  "workspaceId": "ws_abcdef1234567890abcdef123456"
}
```

Disposable workspaces are automatically terminated when their idle or wall TTL
expires. Retained Kata and InstaBox workspaces stop compute and remain reserved
until an explicit close. Remote InstaBox networking is provider-managed and is
not the local host-firewall-attested `dependency-access` profile.

Operators enabling InstaBox must prepare guests with Node.js, Bash and Python 3
with Linux child-subreaper support. Bootstrap checks this prerequisite so
cancelled or completed jobs cannot leave detached child processes running.

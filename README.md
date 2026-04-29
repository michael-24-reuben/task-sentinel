# Task Sentinel

Task Sentinel is a workspace scaffold for a desktop-first activity monitoring and policy engine.

## Structure

```text
task-sentinel/
  apps/
    desktop/              # React desktop UI
  packages/
    collector/            # process, CPU, RAM, network collection
    classifier/           # vitality/domain/behavior tagging
    policy-engine/        # rules, trust score, decision logic
    action-engine/        # remediation and response actions
    ledger/               # SQLite or SQLCipher persistence
    security/             # hash, signature, and path checks
    shared/               # schemas, enums, shared types
  docs/
  .github/
    ISSUE_TEMPLATE/
    workflows/
```

## Getting Started

Install dependencies from the repository root:

```bash
npm install
```

Run the desktop app:

```bash
npm run dev
```

Build all library packages:

```bash
npm run build:packages
```

Build the full project:

```bash
npm run build
```

## Current Status

- `apps/desktop` contains the initial React + Vite UI scaffold.
- `packages/*` are reserved for the service and domain modules listed above.
- `docs/` contains the initial architecture, scope, and security placeholders.

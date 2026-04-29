# AGENTS.md - Task Sentinel Developer Guide

## Project Overview

**Task Sentinel** is a desktop-first **activity monitoring and policy engine** for Windows environments. It's a monorepo scaffold that collects system process data, classifies it against behavioral rules, applies security policies, and executes remediation actions.

### The Problem It Solves
Monitors workspace activity (processes, CPU, RAM, network) and enforces security policies through automated decision-making and response actions. Think of it as a runtime security policy engine with execution capabilities.

---

## Architecture & Components

### Core Module Structure
```
packages/
├── collector/      → Process & resource telemetry collection (Windows adapter)
├── classifier/     → Behavioral/vitality/domain tagging of processes
├── policy-engine/  → Rule evaluation, trust scoring, safety boundaries
├── action-engine/  → Reserved scaffold for remediation responses
├── ledger/         → Reserved scaffold for SQLite/SQLCipher persistence
├── security/       → Reserved scaffold for hash/signature/path validation
└── shared/         → Enums, types, constants for all modules
```

Only `packages/collector`, `packages/classifier`, `packages/policy-engine`, and `packages/shared` currently have source files; the other package folders are placeholders.

`apps/observer-cli` now contains source and runs the live collector → classifier → policy/diff pipeline in terminal mode.

### Data Flow
1. **Collector** (Windows adapter) → gathers raw process/resource snapshots
2. **Mapper** (`packages/collector/src/mappers/mapRawProcess.ts`) → normalizes raw OS data into shared `ActiveProcessSnapshot` types
3. **Classifier** → enriches snapshots with vitality and deterministic behavior/resource flags
4. **Policy Engine** → evaluates safety boundaries and user decision rules against classified snapshots
5. **Logging / smoke tests** (`packages/policy-engine/src/logging/PolicyLogger.ts`, `scripts/dev-test.ts`) → exercise the pipeline during manual runs
6. **Observer CLI** (`apps/observer-cli/src/main.ts`, `apps/observer-cli/src/observer.ts`) → runs continuous scans and emits diff events between snapshots
7. **Desktop UI** (`apps/desktop/src/App.tsx`) → still the default Vite scaffold and not yet wired into the pipeline

**Key Insight**: Modules use shared types from `packages/shared` to maintain contract consistency. Each package is independently testable but tightly integrated through the pipeline.

One current exception: `packages/policy-engine/src/logging/PolicyLogger.ts` imports `ScriptSection` from `@task-sentinel/collector`, so not every cross-package dependency is shared-only yet.

---

## Developer Workflows

### Getting Started
```bash
# Root level commands (defined in /package.json)
npm install          # Install all workspace dependencies
npm run dev          # Start desktop app dev server (Vite HMR enabled)
npm run build:packages # Build workspace package references only
npm run build:observer # Build the observer CLI app only
npm run build:desktop # Build the desktop app only
npm run build        # Build React desktop app with TypeScript
npm run lint         # ESLint check (static analysis only, no fix)
npm run preview      # Preview built desktop app
npm run typecheck    # Run workspace type checks
npm run dev:test     # Run the collector → classifier → policy smoke test
npm run dev:observer-cli # Run live observer CLI loop (supports --fast/--once/etc args)
```

### Build Pipeline for Desktop
The desktop build (`npm run build`) runs `npm run build:packages` first and then `npm run build:desktop`.
1. `tsc -b tsconfig.packages.json` – TypeScript compilation for package project references
2. `apps/desktop` build – `tsc -b` followed by `vite build` in the desktop workspace

This ensures type checking before bundling. TypeScript project references in `tsconfig.json` enable incremental builds.

### Debugging & Testing
- **Desktop**: Open `http://localhost:5173` when running `npm run dev` (Vite default)
- **Pipeline smoke test**: `npm run dev:test` runs `scripts/dev-test.ts`, which wires `ProcessCollector`, `ProcessClassifier`, `PolicyEngine`, and `PolicyLogger`
- **Live observer loop**: `npm run dev:observer-cli -- --fast` runs `scripts/dev-observer-cli.ts`, which boots `@task-sentinel/observer-cli`
- **Package modules**: No formal test framework is configured yet; `packages/collector/src/test.ts` is the current package-local harness
- **Type safety**: Run `npm run lint` and `npm run typecheck` to catch ESLint and compiler issues before commit

---

## Key Patterns & Conventions

### TypeScript Structure
- **Strict mode enabled** (tsconfig standards)
- **Project references** in `tsconfig.json` for monorepo coordination
- **Flat ESLint config** (ESLint v10+ format, not legacy `.eslintrc`)
- All source files: `.ts` (packages) or `.tsx` (React components), and local ESM imports/exports use explicit `.js` extensions in TypeScript source

### Module Public Interfaces
Each package exports from its `src/index.ts`. All modules use shared types:
```typescript
// Example pattern from collector/src/index.ts
export * from './PProcessCollector.js';
export * from './types.js';
// Consumed by other packages as: import { PProcessCollector } from '@task-sentinel/collector'
```

**Naming Convention**: Class names are PascalCase and descriptive (e.g., `ProcessCollector`, `PolicyEngine`, `ProcessClassifier`). These are the primary entry points.

### Types & Enums Location
- **Process types** → `packages/shared/src/types/process.ts`
- **Policy types** → `packages/shared/src/types/policy.ts`
- **Enums** (process states, severity levels) → `packages/shared/src/constants/enums.ts`
- **Protected processes list** → `packages/shared/src/constants/protected-processes.ts`

**Why shared**: Prevents circular dependencies and ensures all modules speak the same language (e.g., `ProcessState.RUNNING`, `Severity.CRITICAL`).

### Windows Integration
- **Main OS dependency**: `Windows processes, CPU, RAM, network` collection
- **Adapter pattern**: `packages/collector/src/adapters/WindowsProcessAdapter.ts` encapsulates OS-specific APIs
- **Data mapping**: `packages/collector/src/mappers/mapRawProcess.ts` normalizes raw OS data to shared `Process` types
- **Implication**: Core domain logic remains OS-agnostic; Windows-isms are isolated in adapters

### React & Vite Standards
- **React 19.2.5** with modern hooks (no class components)
- **Vite 8.0.10** for dev/build (fast HMR enabled by default)
- **React Refresh** via ESLint plugin ensures HMR works with Fast Refresh
- **No bundled component libraries yet** – use utility-first CSS or add shadcn/ui if needed
- **Asset imports** work directly: `import logo from './assets/vite.svg'` (Vite handles)

### ESLint Configuration
- **Flat config format** (JavaScript config, no JSON)
- **Enabled plugins**: React hooks, React Refresh (Fast Refresh), TypeScript ESLint
- **Global ignores**: `dist/` (build output)
- **Rule scope**: All `.ts` and `.tsx` files
- **Linting command**: `npm run lint` (no auto-fix by default; must add `lint:fix` if needed)

---

## Integration Points & Dependencies

### Inter-Package Dependencies
Declare in individual package's `package.json`:
```json
{
  "dependencies": {
    "@task-sentinel/shared": "file:../shared"
  }
}
```
Use npm workspaces; local package dependencies in `packages/*` are declared with file paths. Most domain types flow through `@task-sentinel/shared`, but `packages/policy-engine/src/logging/PolicyLogger.ts` currently imports `ScriptSection` from `@task-sentinel/collector`.

`apps/observer-cli/package.json` uses local workspace package dependencies for `@task-sentinel/collector`, `@task-sentinel/classifier`, `@task-sentinel/policy-engine`, and `@task-sentinel/shared`.

### External Dependencies (Currently Minimal)
- **Runtime**: `react@19.2.5`, `react-dom@19.2.5`
- **Dev**: TypeScript, Vite, ESLint, React plugins, `tsx` (root and observer CLI dev runner)
- **To Add Later**: 
  - `better-sqlite3` or `@databases/sqlite` for ledger queries
  - Crypto for security module (e.g., `crypto-js` or Node's `crypto`)
  - Possibly a backend IPC layer (if not using Electron)

### Critical Files for Understanding Scope
- `docs/MVP_SCOPE.md` – intended MVP feature boundaries (currently empty; establish early)
- `docs/SECURITY_MODEL.md` – threat model & controls (currently empty; critical for policy engine)
- `README.md` – command reference and high-level structure
- `scripts/dev-test.ts` – current end-to-end collector → classifier → policy smoke test
- `scripts/dev-observer-cli.ts` – root-level observer runner used by `npm run dev:observer-cli`
- `apps/observer-cli/src/main.ts` – observer CLI entrypoint and flag parsing
- `apps/observer-cli/src/observer.ts` – live observer loop and scan diff output
- `apps/desktop/src/App.tsx` – default Vite desktop scaffold

---

## Testing & Quality Standards

### Current Status
- **No test framework configured yet** – establish Jest/Vitest early in development
- **Linting**: ESLint enforced before commits (set up Husky or similar pre-commit hook)
- **Type safety**: TypeScript strict mode; leverage compiler errors over runtime surprises

### Recommendations
- **Unit tests**: Jest or Vitest for packages/collector, packages/classifier rules
- **Integration tests**: Policy engine + action engine workflows
- **E2E**: Desktop UI interactions (Playwright/Cypress when UI solidifies)

---

## When Adding New Features

1. **Define types first** → `packages/shared/src/types/`
2. **Add enums if needed** → `packages/shared/src/constants/enums.ts`
3. **Implement domain logic** in the appropriate package (e.g., new classifier rule → `packages/classifier/src/rules/`)
4. **Export from package index** → `packages/[name]/src/index.ts`
5. **Update shared telemetry schema** if adding new metrics → `packages/shared/src/types/telemetry.ts`
6. **Import shared types** in consuming packages; never re-declare types
7. **Run linting and type-check before PR** → `npm run lint && npm run typecheck && npm run build`

---

## Project Philosophy

- **Modular boundaries**: Each package owns one responsibility (single responsibility principle)
- **Shared foundations**: Types and enums live in shared; domain logic stays isolated
- **Windows-first but abstracted**: Adapter pattern keeps OS specifics from polluting core logic
- **Early-stage scaffold**: Most files are empty stubs; establish conventions as you implement
- **Type-safe**: Full TypeScript; avoid `any` types and enforce strict mode

---

## Quick Reference

| What                          | Where                        | Command                                               |
|-------------------------------|------------------------------|-------------------------------------------------------|
| Start dev server              | `apps/desktop`               | `npm run dev`                                         |
| Build library packages        | `packages/`                  | `npm run build:packages`                              |
| Build observer CLI app        | `apps/observer-cli`          | `npm run build:observer`                              |
| Build desktop app             | `apps/desktop`               | `npm run build:desktop`                               |
| Build for production          | `apps/desktop`               | `npm run build`                                       |
| Type check workspaces         | `npm` (root)                 | `npm run typecheck`                                   |
| Type check + bundle           | `npm` (root)                 | `npm run build`                                       |
| Lint code                     | `npm` (root)                 | `npm run lint`                                        |
| Run pipeline smoke test       | `scripts/dev-test.ts`        | `npm run dev:test`                                    |
| Run live observer CLI         | `scripts/dev-observer-cli.ts`| `npm run dev:observer-cli -- --fast`                  |
| Add new package               | `packages/`                  | Create folder + add to root `package.json` workspaces |
| Define shared type            | `packages/shared/src/types/` | Add `.ts` file and export from `index.ts`             |
| Access shared types elsewhere | any package                  | `import { SomeType } from '@task-sentinel/shared'`    |

---

## Gotchas & Lessons

- **Project references matter**: TypeScript `tsc -b` builds in dependency order; misconfigured references cause build failures
- **Flat ESLint config is new**: Don't mix with legacy `.eslintrc` files; use flat config everywhere
- **Vite HMR requires React Refresh plugin**: Ensure `@vitejs/plugin-react` is active and ESLint plugin configured
- **Observer command naming differs in docs**: `docs/scripts/OBSERVER.md` examples currently use `dev:observer`; root scripts expose `dev:observer-cli`
- **Windows adapter is not portable**: Process collection uses Windows APIs; macOS/Linux will need separate adapters
- **Shared types are import-only**: Never add runtime logic to `packages/shared`; it's for schemas and constants only


# Task Sentinel Live Observer

**[observer.ts 🔗](../../apps/observer-cli/dev-observer.ts)**

A real-time process monitor that detects changes between scans: new processes, exits, CPU spikes, memory surges, and suspicious binaries.

## Quick Start

Run the observer with demo data (no system calls needed):

```bash
npm run dev:observer -- --demo --no-clear
```

Run against live system processes (full scan, slow):

```bash
npm run dev:observer
```

Run against live system with fast scanning (recommended):

```bash
npm run dev:observer -- --fast
```

## Performance Profiles

The observer supports two **collection profiles** and three **scan levels** to balance speed vs. detail:

### Profiles

| Profile                                | Details                                                              | Speed Impact        |
|----------------------------------------|----------------------------------------------------------------------|---------------------|
| `SURVEILLANCE` (default with `--fast`) | Minimal: CPU%, RAM, threads, handles only                            | Very fast (1-3 sec) |
| `FULL` (default)                       | Complete: execution path, command line, user, disk I/O, network, GPU | Slow (4-6 min)      |

### Scan Levels

| Level                  | Sections                                         | Speed Impact         |
|------------------------|--------------------------------------------------|----------------------|
| `FAST` (with `--fast`) | memory, cpu, threads, handles                    | Very fast (1-3 sec)  |
| `STANDARD`             | + disk, CIM metadata (process state, parent PID) | Moderate (30-60 sec) |
| `FULL` (default)       | + network connections, GPU, owner enrichment     | Very slow (4-6 min)  |

## Usage Examples

### Fastest (Recommended for Continuous Monitoring)

```bash
npm run dev:observer -- --fast
```

Collects only CPU, RAM, threads, handles. Typically **1–3 seconds per scan**. Sufficient for detecting resource drains and new processes.

### Standard (Balanced)

```bash
npm run dev:observer -- --profile=SURVEILLANCE --scan-level=STANDARD
```

Adds CIM metadata (parent PID, process state) and disk I/O. Typically **30–60 seconds per scan**.

### Full (Complete Telemetry)

```bash
npm run dev:observer
```

All available fields (command line, user, network, GPU, owner). Typically **4–6 minutes per scan**. Use when full audit trail is needed.

## Command-Line Options

| Option            | Values                     | Default | Example                              |
|-------------------|----------------------------|---------|--------------------------------------|
| `--fast`          | flag                       | off     | `--fast`                             |
| `--profile`       | `SURVEILLANCE`, `FULL`     | `FULL`  | `--profile=SURVEILLANCE`             |
| `--scan-level`    | `FAST`, `STANDARD`, `FULL` | `FULL`  | `--scan-level=FAST`                  |
| `--interval`      | milliseconds               | 40000   | `--interval=60000`                   |
| `--sample-window` | milliseconds               | 750     | `--sample-window=1000`               |
| `--cpu-spike`     | percent                    | 20      | `--cpu-spike=30`                     |
| `--memory-surge`  | MB                         | 200     | `--memory-surge=500`                 |
| `--once`          | flag                       | off     | `--once` (run one scan only)         |
| `--no-clear`      | flag                       | off     | `--no-clear` (keep output on screen) |
| `--demo`          | flag                       | off     | `--demo` (use test data)             |
| `--max-scans`     | number                     | none    | `--max-scans=5`                      |

## Output Format

Each change event shows:

```
[MEDIUM] CPU_SPIKE chrome.exe PID 2048 | policy=NOTIFY
Path: C:\Program Files\Google\Chrome\Application\chrome.exe
CPU: 65.0% (+25.0%)
RAM: 1,240 MB
Flags: HIGH_RESOURCE_DRAIN
Reason: Risk flags detected: HIGH_RESOURCE_DRAIN.
```

### Severity Levels

- **LOW**: New process (benign), process exit
- **MEDIUM**: CPU/memory spike
- **HIGH**: Suspicious binary (1 flag), high resource spike
- **CRITICAL**: Suspicious binary (2+ flags)

### Change Types

- **NEW_PROCESS**: Process appeared in this scan
- **EXITED_PROCESS**: Process no longer present
- **CPU_SPIKE**: CPU usage increased by threshold
- **MEMORY_SURGE**: Memory usage increased by threshold
- **NEW_SUSPICIOUS_BINARY**: Process gained suspicious flags (UNSIGNED, SUSPICIOUS_PATH)

## Demo Mode

Test the observer with synthetic data:

```bash
npm run dev:observer -- --demo
```

Runs three scans showing:
1. Two benign processes starting (alpha.exe, beta.exe)
2. CPU spike in alpha, suspicious binary gamma.exe appears, beta exits
3. Memory surge in gamma, new process delta starts

## Performance Tips

1. **Use `--fast` for continuous monitoring** (1–3 sec/scan, every 40 sec = 2% overhead)
2. **Use `--standard` for periodic deep dives** (30–60 sec/scan, every 2–3 min)
3. **Use full scan sparingly** (4–6 min, for forensics only)
4. **Adjust thresholds** to reduce event noise: `--cpu-spike=50 --memory-surge=500`
5. **Run with `--once`** for one-off snapshots

## Architecture

The observer reuses the core pipeline:

```
Collector (process snapshots)
    ↓
Classifier (behavior rules, flags)
    ↓
Policy Engine (safety boundaries, rules)
    ↓
Diff Engine (memory of previous scan)
    ↓
Observer Output (terminal display)
```

The **diff engine** (`packages/policy-engine/src/evaluators/evaluateProcessScanDiff.ts`) compares current scan against previous state to emit only change events, avoiding alert fatigue.

## See Also

- `packages/policy-engine/src/evaluators/evaluateProcessScanDiff.ts` – Pure diffing logic (reusable)
- `packages/collector/src/adapters/WindowsProcessAdapter.ts` – WMI/PowerShell data collection
- `packages/classifier/src/rules/` – Behavior detection rules


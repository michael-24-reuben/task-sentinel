import type {UserDecisionRule} from '@task-sentinel/shared';
import {FAST_SCAN, FULL_AUDIT, FULL_PROFILE, type ProcessCollectionProfile, ProcessCollector, type ScriptSection, STANDARD_SCAN, SURVEILLANCE_PROFILE,} from '@task-sentinel/collector';
import {runObserver,} from './observer.js';
import {CliOptions, DEFAULT_OPTIONS} from "./cliOptions.js";

function parseNumberArg(args: string[], name: string, fallback: number): number {
    const prefix = `--${name}=`;
    const match = args.find((arg) => arg.startsWith(prefix));
    if (!match) return fallback;

    const parsed = Number(match.slice(prefix.length));
    return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function parseOptionalNumberArg(args: string[], name: string): number | undefined {
    const prefix = `--${name}=`;
    const match = args.find((arg) => arg.startsWith(prefix));
    if (!match) return undefined;

    const parsed = Number(match.slice(prefix.length));
    return Number.isFinite(parsed) && parsed > 0 ? parsed : undefined;
}

function parseProfile(args: string[]): ProcessCollectionProfile {
    const match = args.find((arg) => arg.startsWith('--profile='));
    if (!match) return DEFAULT_OPTIONS.profile;

    switch (match.slice('--profile='.length).toUpperCase()) {
        case 'SURVEILLANCE':
            return SURVEILLANCE_PROFILE;
        case 'FULL':
            return FULL_PROFILE;
        default:
            return DEFAULT_OPTIONS.profile;
    }
}

function parseScanLevel(args: string[]): ScriptSection[] {
    const match = args.find((arg) => arg.startsWith('--scan-level='));
    if (!match) return DEFAULT_OPTIONS.scanLevel;

    switch (match.slice('--scan-level='.length).toUpperCase()) {
        case 'FAST':
            return FAST_SCAN;
        case 'STANDARD':
            return STANDARD_SCAN;
        case 'FULL':
            return FULL_AUDIT;
        default:
            return DEFAULT_OPTIONS.scanLevel;
    }
}

function parseArgs(args: string[]): CliOptions {
    const fast = args.includes('--fast');

    return {
        intervalMs: parseNumberArg(args, 'interval', DEFAULT_OPTIONS.intervalMs),
        sampleWindowMs: parseNumberArg(args, 'sample-window', DEFAULT_OPTIONS.sampleWindowMs),
        cpuSpikePercent: parseNumberArg(args, 'cpu-spike', DEFAULT_OPTIONS.cpuSpikePercent!),
        memorySurgeMb: parseNumberArg(args, 'memory-surge', DEFAULT_OPTIONS.memorySurgeMb!),
        once: args.includes('--once'),
        clearScreen: !args.includes('--no-clear'),
        maxScans: parseOptionalNumberArg(args, 'max-scans'),
        profile: fast ? SURVEILLANCE_PROFILE : parseProfile(args),
        scanLevel: fast ? FAST_SCAN : parseScanLevel(args),
    };
}

/**
 * CLI application entrypoint for Task Sentinel Observer Mode.
 *
 * Responsibilities:
 * - Reads and parses command-line arguments from `process.argv`.
 * - Builds runtime configuration (scan cadence, thresholds, profiles, scan depth).
 * - Initializes in-memory user decision rules.
 * - Constructs the `ProcessCollector`, which gathers live process snapshots.
 * - Delegates execution to `runObserver(...)`, the continuous scan loop.
 *
 * This function intentionally owns bootstrap concerns only.
 * Process classification, policy evaluation, and scan rendering are handled
 * inside the observer runtime layer.
 *
 * Flow:
 * 1. Parse CLI args into strongly-typed options.
 * 2. Create user rules ledger (currently in-memory).
 * 3. Create ProcessCollector with selected profile + sampling window.
 * 4. Start observer runtime using collector + rules + options.
 *
 * Example:
 * `node main.js --fast --interval=8000`
 *
 * Supported notable flags:
 * - `--once`              Run one scan then exit.
 * - `--fast`              Uses SURVEILLANCE profile + FAST scan level.
 * - `--interval=<ms>`     Delay between scans.
 * - `--max-scans=<n>`     Stop after n scans.
 * - `--profile=FULL`
 * - `--scan-level=FULL`
 *
 * Exit Behavior:
 * - Resolves when observer loop ends normally.
 * - Errors should be handled by the caller:
 *
 * `main().catch(...)`
 *
 * Future Expansion:
 * - Load rules from SQL ledger / encrypted store
 * - Attach UI mode
 * - JSON export mode
 * - Auto-action enforcement mode
 * - Threat intelligence integrations
 */
async function main(): Promise<void> {
    const options = parseArgs(process.argv.slice(2));

    const rules: UserDecisionRule[] = [];

    const collector = new ProcessCollector({
        sampleWindowMs: options.sampleWindowMs,
        logicalCpuCount: 6,
        profile: options.profile,
    });

    await runObserver({
        collector,
        rules,
        options,
    });
}

main().catch((error) => {
    console.error('[OBSERVER FATAL]', error);
    process.exitCode = 1;
});
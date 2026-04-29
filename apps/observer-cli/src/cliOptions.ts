import type {ObserverRuntimeOptions} from "./observer.js";
import {FAST_SCAN, ProcessCollectionProfile, SURVEILLANCE_PROFILE} from "@task-sentinel/collector";

export interface CliOptions extends ObserverRuntimeOptions {
    sampleWindowMs: number;
    profile: ProcessCollectionProfile;
}

export const DEFAULT_OPTIONS: CliOptions = {
    intervalMs: 5000, // Runs after every 5 second interval
    sampleWindowMs: 750, // Interval window to fetching a comparison data (recommended to keep a small time window for effective polling)
    cpuSpikePercent: 20,
    memorySurgeMb: 200,
    once: false, // Run once. Overrides maxScans value
    clearScreen: true, // Clear screen on new batch
    maxScans: undefined, // Max amount of scans before stopping. Undefined means it will run indefinitely until manually stopped.
    profile: SURVEILLANCE_PROFILE, /*FULL_PROFILE, SURVEILLANCE_PROFILE*/
    scanLevel: FAST_SCAN, /*FULL_AUDIT, STANDARD_SCAN, FAST_SCAN*/
};
import {ActiveProcessSnapshot, ProcessState, ProcessTrustSignals} from '@task-sentinel/shared';

import {FULL_AUDIT} from "./adapters/constants.js";
import {SnapshotProjection} from "./projectors/projectSnapshot.js";

export interface ProcessCollectorOptions {
    /**
     * Time window (in milliseconds) between two process samples used to
     * calculate delta-based telemetry such as CPU usage and read/write rates.
     *
     * Example:
     * - 1000 = compare snapshots taken 1 second apart
     *
     * Lower values:
     * - faster refresh
     * - more reactive readings
     * - potentially noisier metrics
     *
     * Higher values:
     * - smoother averages
     * - less CPU overhead from scanning
     * - slower reaction time
     *
     * In Task Sentinel, the collector uses two samples and elapsed time to
     * enrich raw counters into live telemetry. :contentReference[oaicite:0]{index=0}
     */
    sampleWindowMs?: number;

    /**
     * Number of logical CPU cores/threads available on the system.
     *
     * Used to normalize total CPU consumption into a percentage so a process
     * can be measured consistently across different hardware.
     *
     * Example:
     * - 8 logical CPUs = 8 schedulable threads
     *
     * If omitted, this can be auto-detected from the host machine.
     */
    logicalCpuCount?: number;

    /**
     * Selects which data collection preset the adapter should use.
     *
     * Controls how much process information is gathered and how expensive
     * the scan becomes.
     *
     * Typical profiles:
     * - FAST_SCAN     : minimal fields, lowest overhead
     * - STANDARD_SCAN : balanced telemetry
     * - FULL_PROFILE  : maximum available process detail
     *
     * Earlier architecture notes describe profile-based collection and scan
     * presets for performance-sensitive monitoring.
     */
    profile?: ProcessCollectionProfile;

    /**
     * Optional output shaping / field projection for ActiveProcessSnapshot.
     *
     * Allows callers to include, hide, or trim properties depending on use case.
     *
     * Useful for:
     * - lightweight dashboards
     * - CLI summaries
     * - privacy-sensitive output
     * - performance-focused views
     *
     * Example:
     * - omit commandLine
     * - omit trust signals
     * - include telemetry only
     */
    projection?: SnapshotProjection;
}

export type ScriptSection =
    | 'cim'
    | 'owner'
    | 'network'
    | 'gpu'
    | 'disk'
    | 'cpu'
    | 'memory'
    | 'threads'
    | 'handles';

export interface ProcessCollectionProfile {
    includeParentPid?: boolean;
    includeExecutionPath?: boolean;

    includeCommandLine?: boolean;
    includeUser?: boolean;

    includeCpu?: boolean;
    includeMemory?: boolean;
    includeDisk?: boolean;
    includeNetwork?: boolean;
    includeGpu?: boolean;

    includeThreads?: boolean;
    includeHandles?: boolean;
}

export interface RawProcessCounters {
    /** Cumulative CPU time in seconds. Used to calculate CPU % between samples. */
    cpuSeconds: number;

    /** Cumulative process IO read bytes. Used to calculate disk read rate between samples. */
    ioReadBytes: number;

    /** Cumulative process IO write bytes. Used to calculate disk write rate between samples. */
    ioWriteBytes: number;
}

export interface RawProcessInstantMetrics {
    memoryMb: number;
    threads: number;
    handles: number;
    networkConnectionCount: number;
    gpuUsagePercent: number;
    gpuDedicatedMemoryMb?: number;
    gpuSharedMemoryMb?: number;
    gpuEngine?: string;
}

export interface RawProcessTelemetry {
    cpuPercent: number;
    memoryMb: number;
    diskReadBytesPerSecond: number;
    diskWriteBytesPerSecond: number;
    networkReceiveBytesPerSecond: number;
    networkSendBytesPerSecond: number;
    networkConnectionCount: number;
    gpuUsagePercent: number;
    gpuDedicatedMemoryMb?: number;
    gpuSharedMemoryMb?: number;
    gpuEngine?: string;
    threads: number;
    handles: number;
}


export interface RawProcess {
    pid: number;
    parentPid?: number;
    executableName: string;
    executionPath?: string;
    commandLine?: string;
    user?: string;
    state?: ProcessState;

    /** Raw cumulative OS counters. Collector converts these into rates. */
    counters: RawProcessCounters;

    /** Instant values directly reported by the OS. */
    instant: RawProcessInstantMetrics;

    /** Normalized values produced by ProcessCollector. */
    telemetry?: RawProcessTelemetry;
}

export interface ProcessAdapter {
    listProcesses(approval?: ScriptSection[], profile?: ProcessCollectionProfile): Promise<RawProcess[]>;
}
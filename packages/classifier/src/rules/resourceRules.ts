import { BEHAVIOR_TAG, type ActiveProcessSnapshot, type BehaviorTag } from '@task-sentinel/shared';

export interface ResourceThresholds {
    highCpuPercent: number;
    highMemoryMb: number;
    highDiskBytesPerSecond: number;
    highNetworkBytesPerSecond: number;
    highGpuPercent: number;
    highThreadCount: number;
    highHandleCount: number;
}

// A threshold to determine for how much a process must be utilizing resources before we flag it for high resource drain.
// These are intentionally set to be somewhat aggressive to avoid false positives, but can be tuned as needed.
export const DEFAULT_RESOURCE_THRESHOLDS: ResourceThresholds = {
    highCpuPercent: 70,
    highMemoryMb: 1_500,
    highDiskBytesPerSecond: 50 * 1024 * 1024,
    highNetworkBytesPerSecond: 25 * 1024 * 1024,
    highGpuPercent: 75,
    highThreadCount: 250,
    highHandleCount: 10_000,
};

export function resourceRules(
    process: ActiveProcessSnapshot,
    thresholds: ResourceThresholds = DEFAULT_RESOURCE_THRESHOLDS,
): BehaviorTag[] {
    const flags = new Set<BehaviorTag>();
    const { telemetry } = process;

    if (telemetry.cpuPercent >= thresholds.highCpuPercent || telemetry.memoryMb >= thresholds.highMemoryMb) {
        flags.add(BEHAVIOR_TAG.HIGH_RESOURCE_DRAIN);
    }

    if (telemetry.disk.totalBytesPerSecond >= thresholds.highDiskBytesPerSecond) {
        flags.add(BEHAVIOR_TAG.DISK_HEAVY);
    }

    if (telemetry.network.totalBytesPerSecond >= thresholds.highNetworkBytesPerSecond) {
        flags.add(BEHAVIOR_TAG.NETWORK_HEAVY);
    }

    if ((telemetry.gpu.usagePercent ?? 0) >= thresholds.highGpuPercent) {
        flags.add(BEHAVIOR_TAG.GPU_HEAVY);
    }

    if (telemetry.threads >= thresholds.highThreadCount) {
        flags.add(BEHAVIOR_TAG.THREAD_LEAK_SUSPECTED);
    }

    if (telemetry.handles >= thresholds.highHandleCount) {
        flags.add(BEHAVIOR_TAG.HANDLE_LEAK_SUSPECTED);
    }

    return [...flags];
}

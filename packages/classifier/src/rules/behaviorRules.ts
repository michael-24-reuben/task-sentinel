import { BEHAVIOR_TAG, PROCESS_STATE, type ActiveProcessSnapshot, type BehaviorTag } from '@task-sentinel/shared';

// Patterns indicating execution from temporary or user-writable directories, which can be a sign of suspicious behavior.
const SUSPICIOUS_PATH_PATTERNS = [
    /\\appdata\\local\\temp\\/i,
    /\\downloads\\/i,
    /\\users\\public\\/i,
    /\\windows\\temp\\/i,
];

export function behaviorRules(process: ActiveProcessSnapshot): BehaviorTag[] {
    const flags = new Set<BehaviorTag>();
    const path = process.executionPath ?? '';

    if (path && SUSPICIOUS_PATH_PATTERNS.some((pattern) => pattern.test(path))) {
        flags.add(BEHAVIOR_TAG.SUSPICIOUS_PATH);
    }

    const hasHighCpu = process.telemetry.cpuPercent >= 40;
    const hasNoDiskOrNetwork =
        process.telemetry.disk.totalBytesPerSecond === 0 &&
        process.telemetry.network.totalBytesPerSecond === 0;

    if (hasHighCpu && hasNoDiskOrNetwork) {
        flags.add(BEHAVIOR_TAG.GHOST_PROCESS);
    }

    if (process.state === PROCESS_STATE.ZOMBIE || process.state === PROCESS_STATE.STOPPED) {
        flags.add(BEHAVIOR_TAG.ORPHANED);
    }

    return [...flags];
}

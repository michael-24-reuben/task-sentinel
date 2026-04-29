import {ActiveProcessSnapshot} from "@task-sentinel/shared";

export type SnapshotField =
    | 'commandLine'
    | 'user'
    | 'trust'
    | 'telemetry'
    | 'telemetry.disk'
    | 'telemetry.network'
    | 'telemetry.gpu'
    | 'telemetry.threads'
    | 'telemetry.handles';

export interface SnapshotProjection {
    omit?: SnapshotField[];
}

export function projectSnapshot(
    snapshot: ActiveProcessSnapshot,
    projection: SnapshotProjection = {},
): ActiveProcessSnapshot {
    const omit = new Set(projection.omit ?? []);

    return {
        ...snapshot,

        commandLine: omit.has('commandLine') ? undefined : snapshot.commandLine,
        user: omit.has('user') ? undefined : snapshot.user,
        trust: omit.has('trust') ? {} : snapshot.trust,

        telemetry: omit.has('telemetry')
            ? {
                cpuPercent: 0,
                memoryMb: 0,
                disk: {
                    readBytesPerSecond: 0,
                    writeBytesPerSecond: 0,
                    totalBytesPerSecond: 0,
                },
                network: {
                    receiveBytesPerSecond: 0,
                    sendBytesPerSecond: 0,
                    totalBytesPerSecond: 0,
                    connectionCount: 0,
                },
                gpu: {
                    usagePercent: 0,
                },
                threads: 0,
                handles: 0,
            }
            : {
                ...snapshot.telemetry,
                disk: omit.has('telemetry.disk')
                    ? {
                        readBytesPerSecond: 0,
                        writeBytesPerSecond: 0,
                        totalBytesPerSecond: 0,
                    }
                    : snapshot.telemetry.disk,
                network: omit.has('telemetry.network')
                    ? {
                        receiveBytesPerSecond: 0,
                        sendBytesPerSecond: 0,
                        totalBytesPerSecond: 0,
                        connectionCount: 0,
                    }
                    : snapshot.telemetry.network,
                gpu: omit.has('telemetry.gpu')
                    ? {
                        usagePercent: 0,
                    }
                    : snapshot.telemetry.gpu,
                threads: omit.has('telemetry.threads') ? 0 : snapshot.telemetry.threads,
                handles: omit.has('telemetry.handles') ? 0 : snapshot.telemetry.handles,
            },
    };
}
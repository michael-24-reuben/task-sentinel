import {
    DOMAIN,
    PROCESS_STATE,
    VITALITY,
    type ActiveProcessSnapshot,
    type ResourceTelemetry, ProcessTrustSignals,
} from '@task-sentinel/shared';
import type { RawProcess } from '../types.js';

function mapTelemetry(raw: RawProcess): ResourceTelemetry {
    const telemetry = raw.telemetry;

    if (!telemetry) {
        return {
            cpuPercent: 0,
            memoryMb: raw.instant.memoryMb,
            disk: {
                readBytesPerSecond: 0,
                writeBytesPerSecond: 0,
                totalBytesPerSecond: 0,
            },
            network: {
                receiveBytesPerSecond: 0,
                sendBytesPerSecond: 0,
                totalBytesPerSecond: 0,
                connectionCount: raw.instant.networkConnectionCount,
            },
            gpu: {
                usagePercent: raw.instant.gpuUsagePercent,
                dedicatedMemoryMb: raw.instant.gpuDedicatedMemoryMb,
                sharedMemoryMb: raw.instant.gpuSharedMemoryMb,
                engine: raw.instant.gpuEngine,
            },
            threads: raw.instant.threads,
            handles: raw.instant.handles,
        };
    }

    return {
        cpuPercent: telemetry.cpuPercent,
        memoryMb: telemetry.memoryMb,
        disk: {
            readBytesPerSecond: telemetry.diskReadBytesPerSecond,
            writeBytesPerSecond: telemetry.diskWriteBytesPerSecond,
            totalBytesPerSecond: telemetry.diskReadBytesPerSecond + telemetry.diskWriteBytesPerSecond,
        },
        network: {
            receiveBytesPerSecond: telemetry.networkReceiveBytesPerSecond,
            sendBytesPerSecond: telemetry.networkSendBytesPerSecond,
            totalBytesPerSecond: telemetry.networkReceiveBytesPerSecond + telemetry.networkSendBytesPerSecond,
            connectionCount: telemetry.networkConnectionCount,
        },
        gpu: {
            usagePercent: telemetry.gpuUsagePercent,
            dedicatedMemoryMb: telemetry.gpuDedicatedMemoryMb,
            sharedMemoryMb: telemetry.gpuSharedMemoryMb,
            engine: telemetry.gpuEngine,
        },
        threads: telemetry.threads,
        handles: telemetry.handles,
    };
}

export function mapRawProcess(raw: RawProcess, trustSignals: ProcessTrustSignals, observedAtEpochMs = Date.now()): ActiveProcessSnapshot {
    return {
        pid: raw.pid,
        parentPid: raw.parentPid,
        executableName: raw.executableName,
        executionPath: raw.executionPath,
        commandLine: raw.commandLine,
        user: raw.user,
        state: raw.state ?? PROCESS_STATE.UNKNOWN,
        vitality: VITALITY.USER_LAND,
        domain: DOMAIN.UNKNOWN,
        telemetry: mapTelemetry(raw),
        activeFlags: [],
        trust: trustSignals,
        observedAtEpochMs,
    };
}

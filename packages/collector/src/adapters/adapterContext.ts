import {ProcessAdapter, ProcessCollectionProfile, RawProcess, RawProcessTelemetry} from "../types.js";
import {WindowsHashProvider} from "../trust/windows/WindowsHashProvider.js";
import {WindowsSignatureProvider} from "../trust/windows/WindowsSignatureProvider.js";
import {WindowsKnownPathChecker} from "../trust/windows/WindowsKnownPathChecker.js";
import {FULL_PROFILE} from "./constants.js";
import {DefaultProcessTrustResolver} from "../trust/DefaultProcessTrustResolver.js";
import {WindowsProcessAdapter} from "./windows/WindowsProcessAdapter.js";
import {osSystem} from "../utils.js";


function byPid(processes: RawProcess[]): Map<number, RawProcess> {
    return new Map(processes.map((process) => [process.pid, process]));
}

function getDeps() {
    // Decide dependency by `osSystem`
    return {
        hashProvider: new WindowsHashProvider(),
        signatureProvider: new WindowsSignatureProvider(),
        knownPathChecker: new WindowsKnownPathChecker(),
    };
}

function buildTelemetry(before: RawProcess | undefined, after: RawProcess, elapsedSeconds: number, logicalCpuCount: number, profile: ProcessCollectionProfile = FULL_PROFILE,): RawProcessTelemetry {
    const cpuDeltaSeconds = profile.includeCpu
        ? Math.max(
            0,
            after.counters.cpuSeconds -
            (before?.counters.cpuSeconds ?? after.counters.cpuSeconds),
        )
        : 0;

    const readDeltaBytes = profile.includeDisk
        ? Math.max(
            0,
            after.counters.ioReadBytes -
            (before?.counters.ioReadBytes ?? after.counters.ioReadBytes),
        )
        : 0;

    const writeDeltaBytes = profile.includeDisk
        ? Math.max(
            0,
            after.counters.ioWriteBytes -
            (before?.counters.ioWriteBytes ?? after.counters.ioWriteBytes),
        )
        : 0;

    return {
        cpuPercent: profile.includeCpu ? Math.min(100, (cpuDeltaSeconds / elapsedSeconds / logicalCpuCount) * 100) : 0,

        memoryMb: profile.includeMemory ? after.instant.memoryMb : 0,

        diskReadBytesPerSecond: profile.includeDisk ? readDeltaBytes / elapsedSeconds : 0,

        diskWriteBytesPerSecond: profile.includeDisk ? writeDeltaBytes / elapsedSeconds : 0,

        networkReceiveBytesPerSecond: 0,
        networkSendBytesPerSecond: 0,

        networkConnectionCount: profile.includeNetwork ? after.instant.networkConnectionCount : 0,

        gpuUsagePercent: profile.includeGpu ? after.instant.gpuUsagePercent : 0,
        gpuDedicatedMemoryMb: profile.includeGpu ? after.instant.gpuDedicatedMemoryMb : undefined,
        gpuSharedMemoryMb: profile.includeGpu ? after.instant.gpuSharedMemoryMb : undefined,
        gpuEngine: profile.includeGpu ? after.instant.gpuEngine : undefined,

        threads: profile.includeThreads ? after.instant.threads : 0,
        handles: profile.includeHandles ? after.instant.handles : 0,
    };
}


export function evalProcessTrustSignals() {
    return new DefaultProcessTrustResolver(getDeps(), {
        includeHash: true,
        includeSignature: true,
        includeKnownPath: true,
    });
}

export function enrichWithTelemetry(
    previous: RawProcess[],
    current: RawProcess[],
    elapsedSeconds: number,
    logicalCpuCount: number,
    profile: ProcessCollectionProfile = FULL_PROFILE,
): RawProcess[] {
    const previousByPid = byPid(previous);

    return current.map((process) => ({
        ...process,
        telemetry: buildTelemetry(
            previousByPid.get(process.pid),
            process,
            elapsedSeconds,
            logicalCpuCount,
            profile,
        ),
    }));
}

export function evalOSAdapter(): ProcessAdapter {
    // Detects the OS and return different adapters.
    switch (osSystem) {
        /*case "android": return undefined;*/
        /*case "macos": return undefined;*/
        /*case "linux": return undefined;*/
        case "windows": // all other cases default to windows
        default:
            return new WindowsProcessAdapter();
    }
}
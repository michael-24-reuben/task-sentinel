export interface DiskTelemetry {
    readBytesPerSecond: number;
    writeBytesPerSecond: number;
    totalBytesPerSecond: number;
}

export interface NetworkTelemetry {
    receiveBytesPerSecond: number;
    sendBytesPerSecond: number;
    totalBytesPerSecond: number;
    connectionCount?: number;
}

export interface GpuTelemetry {
    usagePercent?: number;
    dedicatedMemoryMb?: number;
    sharedMemoryMb?: number;
    engine?: string;
}

export interface ResourceTelemetry {
    cpuPercent: number;
    memoryMb: number;
    disk: DiskTelemetry;
    network: NetworkTelemetry;
    gpu: GpuTelemetry;
    threads: number;
    handles: number;
}

export interface TelemetrySnapshot {
    collectedAtEpochMs: number;
    processCount: number;
    totalCpuPercent: number;
    totalMemoryMb: number;
    totalDiskBytesPerSecond: number;
    totalNetworkBytesPerSecond: number;
    totalGpuPercent?: number;
}
export interface WindowsProcessRow {
    ProcessId?: number;
    ParentProcessId?: number;
    Name?: string;
    ExecutablePath?: string;
    CommandLine?: string;
    User?: string;
    ThreadCount?: number;
    HandleCount?: number;
    WorkingSetMb?: number;
    CPU?: number;
    ReadTransferCount?: number;
    WriteTransferCount?: number;
    TcpConnectionCount?: number;
    GpuUsagePercent?: number;
    GpuEngine?: string;
}
import {promisify} from 'node:util';
import {execFile} from 'node:child_process';
import type {ProcessAdapter, ProcessCollectionProfile, RawProcess, ScriptSection} from '../../types.js';
import {FULL_AUDIT, FULL_PROFILE, ScriptApproval} from "../constants.js";
import {WindowsProcessRow} from "./WindowsProcessRow.js";

const execFileAsync = promisify(execFile);

function toArray<T>(value: T | T[] | null | undefined): T[] {
    if (!value) return [];
    return Array.isArray(value) ? value : [value];
}

function safeNumber(value: unknown, fallback = 0): number {
    return typeof value === 'number' && Number.isFinite(value) ? value : fallback;
}

function resolveVisibility<T>(show: boolean | undefined, value: T | undefined): T | undefined {
    return show ? value : undefined;
}

export class WindowsProcessAdapter implements ProcessAdapter {
    async listProcesses(approval: ScriptSection[] = FULL_AUDIT, profile: ProcessCollectionProfile = FULL_PROFILE): Promise<RawProcess[]> {
        const script = this.getScript(
            (section) => approval.includes(section),
            profile,
        );

        const {stdout} = await execFileAsync(
            'powershell.exe',
            ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', script],
            {windowsHide: true, maxBuffer: 1024 * 1024 * 16},
        );

        const rows = toArray(JSON.parse(stdout || '[]') as WindowsProcessRow | WindowsProcessRow[]);

        if (rows.length > 0) {
            const firstTen = rows.slice(0, 10).map(r => ({
                name: r.Name,
                processId: r.ProcessId,
            }));
            // Log at most once per batch to avoid spam
            if (Math.random() < 0.1) {
                console.log('[DEBUG] Raw adapter rows (sample):', firstTen);
            }
        }

        return rows
            .filter((row) => Number.isFinite(Number(row.ProcessId)) && typeof row.Name === 'string')
            .map((row) => ({
                pid: row.ProcessId as number,
                parentPid: row.ParentProcessId,
                executableName: row.Name as string,
                executionPath: row.ExecutablePath,
                commandLine: resolveVisibility(profile.includeCommandLine, row.CommandLine),
                user: resolveVisibility(profile.includeUser, row.User),
                state: 'RUNNING',
                counters: {
                    cpuSeconds: profile.includeCpu ? safeNumber(row.CPU) : 0,
                    ioReadBytes: profile.includeDisk ? safeNumber(row.ReadTransferCount) : 0,
                    ioWriteBytes: profile.includeDisk ? safeNumber(row.WriteTransferCount) : 0,
                },
                instant: {
                    memoryMb: profile.includeMemory ? safeNumber(row.WorkingSetMb) : 0,
                    threads: profile.includeThreads ? safeNumber(row.ThreadCount) : 0,
                    handles: profile.includeHandles ? safeNumber(row.HandleCount) : 0,
                    networkConnectionCount: profile.includeNetwork
                        ? safeNumber(row.TcpConnectionCount)
                        : 0,
                    gpuUsagePercent: profile.includeGpu ? safeNumber(row.GpuUsagePercent) : 0,
                    gpuEngine: profile.includeGpu ? row.GpuEngine : undefined,
                },
            }));
    }

    private getScript(shouldFetch: ScriptApproval, profile: ProcessCollectionProfile,): string {
        const needsCim =
            shouldFetch('cim') &&
            (profile.includeCommandLine ||
                profile.includeUser ||
                profile.includeParentPid ||
                profile.includeExecutionPath);

        const needsOwner = shouldFetch('owner') && profile.includeUser;
        const needsNetwork = shouldFetch('network') && profile.includeNetwork;
        const needsGpu = shouldFetch('gpu') && profile.includeGpu;

        return `
$ErrorActionPreference = 'SilentlyContinue'

$cimByPid = @{}
$tcpCounts = @{}
$gpuByPid = @{}

${needsCim ? this.getCimBlock(needsOwner) : ''}

${needsNetwork ? this.getNetworkBlock() : ''}

${needsGpu ? this.getGpuBlock() : ''}

Get-Process | ForEach-Object {
  # Use descriptive variable name to avoid conflicts with PowerShell's automatic $PID variable
  $processId = [int]$_.Id
  $cim = $cimByPid[$processId]

  [pscustomobject]@{
    ProcessId = $processId
    ParentProcessId = ${needsCim && profile.includeParentPid ? 'if ($cim) { $cim.ParentProcessId } else { $null }' : '$null'}
    Name = $_.ProcessName + '.exe'
    ExecutablePath = ${profile.includeExecutionPath ? "if ($_.Path) { $_.Path } elseif ($cim) { $cim.ExecutablePath } else { $null }" : '$null'}
    CommandLine = ${profile.includeCommandLine ? 'if ($cim) { $cim.CommandLine } else { $null }' : '$null'}
    User = ${profile.includeUser ? 'if ($cim) { $cim.User } else { $null }' : '$null'}

    ThreadCount = ${profile.includeThreads ? '$_.Threads.Count' : '0'}
    HandleCount = ${profile.includeHandles ? '$_.HandleCount' : '0'}
    WorkingSetMb = ${profile.includeMemory ? '[math]::Round($_.WorkingSet64 / 1MB, 2)' : '0'}
    CPU = ${profile.includeCpu ? "if ($_.CPU) { [double]$_.CPU } else { 0 }" : '0'}

    ReadTransferCount = ${profile.includeDisk ? "if ($_.ReadTransferCount) { [double]$_.ReadTransferCount } else { 0 }" : '0'}
    WriteTransferCount = ${profile.includeDisk ? "if ($_.WriteTransferCount) { [double]$_.WriteTransferCount } else { 0 }" : '0'}

    TcpConnectionCount = ${needsNetwork ? 'if ($tcpCounts.ContainsKey($processId)) { [int]$tcpCounts[$processId] } else { 0 }' : '0'}

    GpuUsagePercent = ${needsGpu ? 'if ($gpuByPid.ContainsKey($processId)) { [math]::Round($gpuByPid[$processId].Usage, 2) } else { 0 }' : '0'}
    GpuEngine = ${needsGpu ? 'if ($gpuByPid.ContainsKey($processId)) { $gpuByPid[$processId].Engine } else { $null }' : '$null'}
  }
} | ConvertTo-Json -Depth 4
`;
    }

    private getCimBlock(includeOwner: boolean = true): string {
        return `
Get-CimInstance Win32_Process | ForEach-Object {
  $user = $null

  ${includeOwner ? `
  $owner = $_ | Invoke-CimMethod -MethodName GetOwner
  $user = if ($owner.User) { $owner.Domain + '\\\\' + $owner.User } else { $null }
  ` : ''}

  $cimByPid[[int]$_.ProcessId] = [pscustomobject]@{
    ParentProcessId = $_.ParentProcessId
    ExecutablePath = $_.ExecutablePath
    CommandLine = $_.CommandLine
    User = $user
  }
}
`;
    }

    private getNetworkBlock(): string {
        return `
Get-NetTCPConnection | Where-Object { $_.OwningProcess -gt 0 } | Group-Object OwningProcess | ForEach-Object {
  $tcpCounts[[int]$_.Name] = $_.Count
}
`;
    }

    private getGpuBlock(): string {
        return `
try {
  $gpuSamples = Get-Counter '\\\\GPU Engine(*)\\\\Utilization Percentage' -ErrorAction SilentlyContinue
  foreach ($sample in $gpuSamples.CounterSamples) {
    if ($sample.InstanceName -match 'pid_(\\\\d+).*?(engtype_[^_]+)') {
      # Use descriptive variable name to avoid conflicts with PowerShell's automatic $PID variable
      $gpuPid = [int]$Matches[1]
      $engine = $Matches[2]

      if (-not $gpuByPid.ContainsKey($gpuPid)) {
        $gpuByPid[$gpuPid] = [pscustomobject]@{ Usage = 0; Engine = $engine }
      }

      $gpuByPid[$gpuPid].Usage += [double]$sample.CookedValue
    }
  }
} catch {}
`;
    }
}

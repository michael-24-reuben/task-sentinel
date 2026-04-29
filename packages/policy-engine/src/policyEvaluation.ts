import {BehaviorTag, ProcessEvent, ProcessTrustSignals} from "@task-sentinel/shared";

/*
BehaviorTag = "HIGH_RESOURCE_DRAIN" | "NETWORK_HEAVY" | "DISK_HEAVY" | "GPU_HEAVY" | "HANDLE_LEAK_SUSPECTED" | "THREAD_LEAK_SUSPECTED" | "BLOATWARE" | "ORPHANED" | "GHOST_PROCESS" | "UNSIGNED" | "SUSPICIOUS_PATH" | "USER_VERIFIED" | "PENDING_REVIEW" | "POLICY_VIOLATION"

ProcessEvent = "GHOST_PROCESS" | "PROCESS_STARTED" | "PROCESS_EXITED" | "CPU_SPIKE" | "RAM_SPIKE" | "PROCESS_CHANGED" | "NETWORK_SPIKE" | "NEW_SUSPICIOUS_BINARY" | "ORPHAN_DETECTED" | "POLICY_MATCHED" | "ACTION_RECOMMENDED" | "ACTION_TAKEN"

ProcessTrustSignals {
    sha256?: string
    metadataPublisher?: string
    signaturePublisher?: string
    hasValidSignature?: boolean
    isKnownPath?: boolean
}*/
export type ScanDiffSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface CompactNetworkRate extends CompactIoRate {
    c: number; // connection count
}

export interface CompactIoRate {
    r: number; // read / receive bytes per second
    w: number; // write / send bytes per second
    t: number; // total bytes per second
}

export interface ProcessTelemetry {
    cpuPercent: number;
    memoryMb: number;
    disk?: CompactIoRate;      // { r, w, t }
    network?: CompactNetworkRate; // { r, w, t, c }
    threads?: number;
    handles?: number;
}

export interface TelemetryHistoryEntry {
    observedAtEpochMs: number;
    telemetry: ProcessTelemetry;
    activeFlags: BehaviorTag[];
    events: ProcessEvent[];
}

export interface StandardPolicyEvaluation {
    mode: 'STANDARD';
    process: {
        pid: number;
        parentPid: number | null;
        executableName: string;
        executionPath?: string | null;
        severity: ScanDiffSeverity;
        state: 'RUNNING' | 'EXITED' | 'UNKNOWN';
        vitality: string;
        domain: string;
        telemetry: ProcessTelemetry;
        activeFlags: string[];
        trust?:  ProcessTrustSignals;
        observedAtEpochMs: number;
    };
    telemetryHistoryLimit: number;
    telemetryHistory: TelemetryHistoryEntry[];
    events: ProcessEvent[];
    action: string;
    reasons: string[];
    matchedRuleIds: string[];
    safeToAutoAct: boolean;
}

export interface FullPolicyEvaluation extends Omit<StandardPolicyEvaluation, 'mode'> {
    mode: 'FULL';
    process: StandardPolicyEvaluation['process'] & {
        commandLine?: string | null;
        parentExecutableName?: string | null;
        hash?: {
            sha256?: string;
        };
        signature?: {
            signed?: boolean;
            valid?: boolean;
            publisher?: string | null;
        };
    };
}

export type PolicyEvaluationResult = StandardPolicyEvaluation | FullPolicyEvaluation;


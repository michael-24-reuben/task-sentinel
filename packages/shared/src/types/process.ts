import type { BehaviorTag, ProcessDomain, ProcessState, Vitality } from '../constants/enums.js';
import type { ResourceTelemetry } from './telemetry.js';

export interface ProcessIdentity {
    pid: number;
    parentPid?: number;
    executableName: string;
    executionPath?: string;
    commandLine?: string;
    user?: string;
}

export interface ProcessTrustSignals {
    sha256?: string;
    metadataPublisher?: string;
    signaturePublisher?: string;
    hasValidSignature?: boolean;
    isKnownPath?: boolean;
}

export interface ActiveProcessSnapshot extends ProcessIdentity {
    state: ProcessState;
    vitality: Vitality;
    domain: ProcessDomain;
    telemetry: ResourceTelemetry;
    activeFlags: BehaviorTag[];
    trust: ProcessTrustSignals;
    observedAtEpochMs: number;
}

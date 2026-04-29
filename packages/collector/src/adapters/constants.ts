import type {ProcessCollectionProfile, ScriptSection} from "../types.js";

export const SURVEILLANCE_PROFILE: ProcessCollectionProfile = {
    includeParentPid: true,
    includeExecutionPath: false,
    includeCommandLine: false,
    includeUser: false,
    includeCpu: true,
    includeMemory: true,
    includeDisk: false,
    includeNetwork: false,
    includeGpu: false,
    includeThreads: true,
    includeHandles: true,
};
export const FULL_PROFILE: ProcessCollectionProfile = {
    includeParentPid: true,
    includeExecutionPath: true,
    includeCommandLine: true,
    includeUser: true,
    includeCpu: true,
    includeMemory: true,
    includeDisk: true,
    includeNetwork: true,
    includeGpu: true,
    includeThreads: true,
    includeHandles: true,
};
export type ScriptApproval = (section: ScriptSection) => boolean;
export const FAST_SCAN: ScriptSection[] = [
    'memory',
    'cpu',
    'threads',
    'handles'
];
export const STANDARD_SCAN: ScriptSection[] = [
    'memory',
    'cpu',
    'threads',
    'handles',
    'disk',
    'cim',
];
export const FULL_AUDIT: ScriptSection[] = [
    'memory',
    'cpu',
    'threads',
    'handles',
    'disk',
    'cim',
    'network',
    'gpu',
    'owner',
];
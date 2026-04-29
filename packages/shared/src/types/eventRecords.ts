export type ProcessEvent =
    | 'PROCESS_STARTED'
    | 'PROCESS_EXITED'
    | 'CPU_SPIKE'
    | 'RAM_SPIKE'
    | 'PROCESS_CHANGED'
    | 'NETWORK_SPIKE'
    | 'NEW_SUSPICIOUS_BINARY'
    | 'ORPHAN_DETECTED'
    | 'GHOST_PROCESS'
    | 'POLICY_MATCHED'
    | 'ACTION_RECOMMENDED'
    | 'ACTION_TAKEN';

export interface ProcessEventThresholds {
    CPU_SPIKE: number;             // cpu % increase or absolute threshold
    RAM_SPIKE: number;             // memory increase in MB
    NETWORK_SPIKE: number;         // new connections / bytes delta
    ORPHAN_DETECTED: number;       // grace period ms after parent exit
    GHOST_PROCESS: number;         // consecutive scans meeting ghost criteria
    PROCESS_CHANGED: number;       // change score threshold
    POLICY_MATCHED: number;        // confidence score if heuristic-based
    ACTION_RECOMMENDED: number;    // risk score needed to recommend action
    ACTION_TAKEN: number;          // risk/confidence score for execution
    NEW_SUSPICIOUS_BINARY: number; // confidence score threshold for flagging new binaries as suspicious
}

export const DEFAULT_PROCESS_EVENT_THRESHOLDS: ProcessEventThresholds = {
    CPU_SPIKE: 2,
    RAM_SPIKE: 25,
    NETWORK_SPIKE: 1,
    ORPHAN_DETECTED: 300000,     // 5 min
    GHOST_PROCESS: 3,
    PROCESS_CHANGED: 1,
    POLICY_MATCHED: 1,
    ACTION_RECOMMENDED: 60,
    ACTION_TAKEN: 90,
    NEW_SUSPICIOUS_BINARY: 70,
};


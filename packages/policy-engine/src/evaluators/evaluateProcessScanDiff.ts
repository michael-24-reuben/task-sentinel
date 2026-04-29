import {FullPolicyEvaluation, PolicyEvaluationResult, ProcessTelemetry, ScanDiffSeverity, StandardPolicyEvaluation, TelemetryHistoryEntry} from "../policyEvaluation.js";
import {ActiveProcessSnapshot, DEFAULT_PROCESS_EVENT_THRESHOLDS, ProcessEvent, ProcessEventThresholds} from "@task-sentinel/shared";

export type PolicyEvaluationMode = 'STANDARD' | 'FULL';

export interface EvaluateProcessScanDiffOptions {
    mode?: PolicyEvaluationMode;
    thresholds?: Partial<ResolvedProcessEventThresholds>;

    /**
     * Default: 5. This is in-memory live history for decision context only.
     * Persist long-term history in the ledger/audit database instead.
     */
    telemetryHistoryLimit?: number;

    /**
     * Default: false. When false, only snapshots with one or more events are returned.
     */
    emitUnchanged?: boolean;

    /**
     * Default: false. When false, likely background PID churn can be suppressed.
     */
    includeNoise?: boolean;

    /**
     * Optional mutable state that lets the evaluator keep history across scans.
     */
    state?: ProcessScanDiffState;

    /**
     * Process names that are noisy on Windows and should not dominate diff output.
     * Matching is case-insensitive. Only low-risk start/exit churn is suppressed.
     */
    noiseProcessNames?: string[];

    /**
     * Default: 5 minutes. Used for restart/churn tracking.
     */
    restartWindowMs?: number;

    /**
     * Default: 3. Number of logical restarts within restartWindowMs before it is no longer suppressed as noise.
     */
    restartLoopThreshold?: number;
}

export interface ProcessScanDiffState {
    telemetryHistoryByIdentity: Map<string, TelemetryHistoryEntry[]>;
    ghostConsecutiveByIdentity: Map<string, number>;
    restartEpochsByIdentity: Map<string, number[]>;
}

type SnapshotIndex = {
    byPid: Map<number, ActiveProcessSnapshot>;
    byIdentity: Map<string, ActiveProcessSnapshot[]>;
};

export type ResolvedProcessEventThresholds = ProcessEventThresholds & {
    NEW_SUSPICIOUS_BINARY: number;
};

type MatchedPrior = {
    prior?: ActiveProcessSnapshot;
    matchedBy: 'PID' | 'IDENTITY' | 'NONE';
};

const DEFAULT_TELEMETRY_HISTORY_LIMIT = 5;
const DEFAULT_NEW_SUSPICIOUS_BINARY_SCORE = 70;
const DEFAULT_RESTART_WINDOW_MS = 5 * 60 * 1000;
const DEFAULT_RESTART_LOOP_THRESHOLD = 3;

const DEFAULT_NOISE_PROCESS_NAMES = new Set([
    'yourphoneappproxy.exe',
    'phoneexperiencehost.exe',
    'searchhost.exe',
    'startmenuexperiencehost.exe',
    'runtimebroker.exe',
    'widgetservice.exe',
    'widgets.exe',
]);

const POLICY_EVENTS = new Set<ProcessEvent>([
    'POLICY_MATCHED',
    'ACTION_RECOMMENDED',
    'ACTION_TAKEN',
]);

export function createProcessScanDiffState(): ProcessScanDiffState {
    return {
        telemetryHistoryByIdentity: new Map(),
        ghostConsecutiveByIdentity: new Map(),
        restartEpochsByIdentity: new Map(),
    };
}

/**
 * Produces scan-diff PolicyEvaluation records from previous/current snapshots.
 *
 * This evaluator is intentionally limited to observer/diff events. It does not apply
 * user policy rules or execute actions. Policy/action engines should append
 * POLICY_MATCHED, ACTION_RECOMMENDED, and ACTION_TAKEN after this step.
 */
export function evaluateProcessScanDiff(
    previous: Iterable<ActiveProcessSnapshot>,
    current: Iterable<ActiveProcessSnapshot>,
    options: EvaluateProcessScanDiffOptions = {},
): PolicyEvaluationResult[] {
    const mode = options.mode ?? 'STANDARD';
    const thresholds = resolveThresholds(options.thresholds);
    const telemetryHistoryLimit = options.telemetryHistoryLimit ?? DEFAULT_TELEMETRY_HISTORY_LIMIT;
    const emitUnchanged = options.emitUnchanged ?? false;
    const includeNoise = options.includeNoise ?? false;
    const state = options.state ?? createProcessScanDiffState();
    const restartWindowMs = options.restartWindowMs ?? DEFAULT_RESTART_WINDOW_MS;
    const restartLoopThreshold = options.restartLoopThreshold ?? DEFAULT_RESTART_LOOP_THRESHOLD;
    const noiseProcessNames = createNoiseSet(options.noiseProcessNames);

    const previousIndex = createSnapshotIndex(previous);
    const currentIndex = createSnapshotIndex(current);
    const matchedPreviousPids = new Set<number>();
    const results: PolicyEvaluationResult[] = [];

    for (const snapshot of currentIndex.byPid.values()) {
        const identityKey = makeProcessIdentityKey(snapshot);
        const match = findBestPrior(snapshot, previousIndex, matchedPreviousPids);
        const prior = match.prior;

        if (prior) matchedPreviousPids.add(prior.pid);

        const events = detectCurrentProcessEvents({
            snapshot,
            prior,
            matchedBy: match.matchedBy,
            previousIndex,
            currentIndex,
            thresholds,
            state,
            identityKey,
        });

        if (match.matchedBy === 'IDENTITY' && prior && prior.pid !== snapshot.pid) {
            recordRestart(state, identityKey, snapshot.observedAtEpochMs, restartWindowMs);
        }

        const suppressed = shouldSuppressAsNoise({
            snapshot,
            events,
            includeNoise,
            noiseProcessNames,
            state,
            identityKey,
            restartLoopThreshold,
        });

        if (!suppressed && (emitUnchanged || events.length > 0)) {
            results.push(
                createPolicyEvaluation({
                    mode,
                    snapshot,
                    prior,
                    events,
                    telemetryHistoryLimit,
                    state,
                    identityKey,
                }),
            );
        }

        updateStateForSnapshot(state, snapshot, events, telemetryHistoryLimit, identityKey);
    }

    for (const snapshot of previousIndex.byPid.values()) {
        if (matchedPreviousPids.has(snapshot.pid)) continue;
        if (currentIndex.byPid.has(snapshot.pid)) continue;

        const identityKey = makeProcessIdentityKey(snapshot);
        const events: ProcessEvent[] = ['PROCESS_EXITED'];

        const suppressed = shouldSuppressAsNoise({
            snapshot,
            events,
            includeNoise,
            noiseProcessNames,
            state,
            identityKey,
            restartLoopThreshold,
        });

        if (!suppressed) {
            results.push(
                createPolicyEvaluation({
                    mode,
                    snapshot: markExited(snapshot),
                    prior: snapshot,
                    events,
                    telemetryHistoryLimit,
                    state,
                    identityKey,
                }),
            );
        }
    }

    pruneState(state, currentIndex, telemetryHistoryLimit);

    return results;
}

export function makeProcessIdentityKey(snapshot: Pick<ActiveProcessSnapshot, 'executableName' | 'executionPath' | 'commandLine'>): string {
    const path = normalizeIdentityPart(snapshot.executionPath);
    if (path) return `path:${path}`;

    const command = normalizeIdentityPart(snapshot.commandLine);
    const name = normalizeIdentityPart(snapshot.executableName) || 'unknown-process';

    // Command line is useful when path is unavailable, but do not let an empty/null path collapse every process together.
    return command ? `name:${name}|cmd:${command}` : `name:${name}`;
}

export function makeProcessPidKey(snapshot: Pick<ActiveProcessSnapshot, 'pid'>): string {
    return `pid:${snapshot.pid}`;
}

function detectCurrentProcessEvents(args: {
    snapshot: ActiveProcessSnapshot;
    prior?: ActiveProcessSnapshot;
    matchedBy: MatchedPrior['matchedBy'];
    previousIndex: SnapshotIndex;
    currentIndex: SnapshotIndex;
    thresholds: ResolvedProcessEventThresholds;
    state: ProcessScanDiffState;
    identityKey: string;
}): ProcessEvent[] {
    const { snapshot, prior, matchedBy, previousIndex, currentIndex, thresholds, state, identityKey } = args;
    const events = new Set<ProcessEvent>();

    if (!prior) {
        events.add('PROCESS_STARTED');

        if (scoreSuspiciousBinary(snapshot) >= thresholds.NEW_SUSPICIOUS_BINARY) {
            events.add('NEW_SUSPICIOUS_BINARY');
        }
    }

    if (prior) {
        const cpuDelta = snapshot.telemetry.cpuPercent - prior.telemetry.cpuPercent;
        const memoryDelta = snapshot.telemetry.memoryMb - prior.telemetry.memoryMb;
        const networkDelta = getNetworkTotal(snapshot.telemetry) - getNetworkTotal(prior.telemetry);
        const connectionDelta = getConnectionCount(snapshot.telemetry) - getConnectionCount(prior.telemetry);
        const changeScore = scoreProcessChange(snapshot, prior, matchedBy);

        if (matchedBy === 'IDENTITY' && prior.pid !== snapshot.pid) {
            events.add('PROCESS_STARTED');
            events.add('PROCESS_CHANGED');
        }

        if (cpuDelta >= thresholds.CPU_SPIKE) events.add('CPU_SPIKE');
        if (memoryDelta >= thresholds.RAM_SPIKE) events.add('RAM_SPIKE');

        if (networkDelta >= thresholds.NETWORK_SPIKE || connectionDelta >= thresholds.NETWORK_SPIKE) {
            events.add('NETWORK_SPIKE');
        }

        if (changeScore >= thresholds.PROCESS_CHANGED) {
            events.add('PROCESS_CHANGED');
        }
    }

    if (isOrphaned(snapshot, prior, currentIndex, previousIndex, thresholds.ORPHAN_DETECTED)) {
        events.add('ORPHAN_DETECTED');
    }

    if (isGhostProcess(snapshot, state, identityKey, thresholds.GHOST_PROCESS)) {
        events.add('GHOST_PROCESS');
    }

    for (const policyEvent of POLICY_EVENTS) {
        events.delete(policyEvent);
    }

    return [...events];
}

function createPolicyEvaluation(args: {
    mode: PolicyEvaluationMode;
    snapshot: ActiveProcessSnapshot;
    prior?: ActiveProcessSnapshot;
    events: ProcessEvent[];
    telemetryHistoryLimit: number;
    state: ProcessScanDiffState;
    identityKey: string;
}): PolicyEvaluationResult {
    const { mode, snapshot, prior, events, telemetryHistoryLimit, state, identityKey } = args;
    const severity = getSeverity(snapshot, events);
    const action = getObserverAction(events, severity);
    const reasons = createReasons(events, snapshot, prior);

    const base: StandardPolicyEvaluation = {
        mode: 'STANDARD',
        process: {
            pid: snapshot.pid,
            parentPid: snapshot.parentPid ?? null,
            executableName: snapshot.executableName,
            executionPath: snapshot.executionPath ?? null,
            severity,
            state: normalizeProcessState(snapshot.state),
            vitality: String(snapshot.vitality),
            domain: String(snapshot.domain),
            telemetry: compactTelemetry(snapshot.telemetry),
            activeFlags: snapshot.activeFlags.map(String),
            trust: snapshot.trust ?? {},
            observedAtEpochMs: snapshot.observedAtEpochMs,
        },
        telemetryHistoryLimit,
        telemetryHistory: createTelemetryHistory(state, prior, telemetryHistoryLimit, identityKey),
        events,
        action,
        reasons,
        matchedRuleIds: [],
        safeToAutoAct: false,
    };

    if (mode === 'STANDARD') return base;

    return {
        ...base,
        mode: 'FULL',
        process: {
            ...base.process,
            commandLine: snapshot.commandLine ?? null,
            parentExecutableName: prior?.executableName ?? null,
            hash: {
                sha256: snapshot.trust?.sha256,
            },
            signature: {
                signed: snapshot.trust?.hasValidSignature,
                valid: snapshot.trust?.hasValidSignature,
                publisher: snapshot.trust?.signaturePublisher ?? null,
            },
        },
    };
}

function createTelemetryHistory(
    state: ProcessScanDiffState,
    prior: ActiveProcessSnapshot | undefined,
    limit: number,
    identityKey: string,
): TelemetryHistoryEntry[] {
    if (limit <= 0) return [];

    const existing = state.telemetryHistoryByIdentity.get(identityKey) ?? [];

    // Fallback for callers that do not pass a persistent state object.
    if (existing.length === 0 && prior) {
        return [snapshotToHistoryEntry(prior, [])].slice(-limit);
    }

    return existing.slice(-limit);
}

function updateStateForSnapshot(
    state: ProcessScanDiffState,
    snapshot: ActiveProcessSnapshot,
    events: ProcessEvent[],
    limit: number,
    identityKey: string,
): void {
    const history = state.telemetryHistoryByIdentity.get(identityKey) ?? [];
    const next = [...history, snapshotToHistoryEntry(snapshot, events)].slice(-Math.max(0, limit));

    state.telemetryHistoryByIdentity.set(identityKey, next);

    const flags = new Set(snapshot.activeFlags.map(String));
    const previousGhostCount = state.ghostConsecutiveByIdentity.get(identityKey) ?? 0;
    state.ghostConsecutiveByIdentity.set(identityKey, flags.has('GHOST_PROCESS') ? previousGhostCount + 1 : 0);
}

function snapshotToHistoryEntry(snapshot: ActiveProcessSnapshot, events: ProcessEvent[]): TelemetryHistoryEntry {
    return {
        observedAtEpochMs: snapshot.observedAtEpochMs,
        telemetry: compactTelemetry(snapshot.telemetry),
        activeFlags: snapshot.activeFlags,
        events,
    };
}

function resolveThresholds(thresholds: EvaluateProcessScanDiffOptions['thresholds'] = {}): ResolvedProcessEventThresholds {
    return {
        ...DEFAULT_PROCESS_EVENT_THRESHOLDS,
        NEW_SUSPICIOUS_BINARY: DEFAULT_NEW_SUSPICIOUS_BINARY_SCORE,
        ...thresholds,
    };
}

function createSnapshotIndex(snapshots: Iterable<ActiveProcessSnapshot>): SnapshotIndex {
    const byPid = new Map<number, ActiveProcessSnapshot>();
    const byIdentity = new Map<string, ActiveProcessSnapshot[]>();

    for (const snapshot of snapshots) {
        byPid.set(snapshot.pid, snapshot);

        const identityKey = makeProcessIdentityKey(snapshot);
        const group = byIdentity.get(identityKey) ?? [];
        group.push(snapshot);
        byIdentity.set(identityKey, group);
    }

    return { byPid, byIdentity };
}

function findBestPrior(
    snapshot: ActiveProcessSnapshot,
    previousIndex: SnapshotIndex,
    matchedPreviousPids: Set<number>,
): MatchedPrior {
    const pidMatch = previousIndex.byPid.get(snapshot.pid);
    if (pidMatch && !matchedPreviousPids.has(pidMatch.pid)) {
        return { prior: pidMatch, matchedBy: 'PID' };
    }

    const identityKey = makeProcessIdentityKey(snapshot);
    const candidates = (previousIndex.byIdentity.get(identityKey) ?? []).filter((candidate) => !matchedPreviousPids.has(candidate.pid));

    if (candidates.length === 0) return { matchedBy: 'NONE' };

    const best = candidates
        .map((candidate) => ({ candidate, score: scorePriorCandidate(snapshot, candidate) }))
        .sort((a, b) => b.score - a.score)[0]?.candidate;

    return best ? { prior: best, matchedBy: 'IDENTITY' } : { matchedBy: 'NONE' };
}

function scorePriorCandidate(snapshot: ActiveProcessSnapshot, prior: ActiveProcessSnapshot): number {
    let score = 0;

    if ((snapshot.parentPid ?? null) === (prior.parentPid ?? null)) score += 5;
    if (normalizeIdentityPart(snapshot.commandLine) === normalizeIdentityPart(prior.commandLine)) score += 4;
    if (normalizeIdentityPart(snapshot.executionPath) === normalizeIdentityPart(prior.executionPath)) score += 4;
    if ((snapshot.trust?.sha256 ?? null) === (prior.trust?.sha256 ?? null)) score += 3;
    if ((snapshot.trust?.signaturePublisher ?? null) === (prior.trust?.signaturePublisher ?? null)) score += 2;

    const memoryDelta = Math.abs(snapshot.telemetry.memoryMb - prior.telemetry.memoryMb);
    if (memoryDelta < 10) score += 2;
    else if (memoryDelta < 100) score += 1;

    return score;
}

function compactTelemetry(telemetry: ActiveProcessSnapshot['telemetry']): ProcessTelemetry {
    return {
        cpuPercent: telemetry.cpuPercent,
        memoryMb: telemetry.memoryMb,
        disk: telemetry.disk
            ? {
                  r: telemetry.disk.readBytesPerSecond ?? 0,
                  w: telemetry.disk.writeBytesPerSecond ?? 0,
                  t: telemetry.disk.totalBytesPerSecond ?? 0,
              }
            : undefined,
        network: telemetry.network
            ? {
                  r: telemetry.network.receiveBytesPerSecond ?? 0,
                  w: telemetry.network.sendBytesPerSecond ?? 0,
                  t: telemetry.network.totalBytesPerSecond ?? 0,
                  c: telemetry.network.connectionCount ?? 0,
              }
            : undefined,
        threads: telemetry.threads,
        handles: telemetry.handles,
    };
}

function getNetworkTotal(telemetry: ActiveProcessSnapshot['telemetry']): number {
    return telemetry.network?.totalBytesPerSecond ?? 0;
}

function getConnectionCount(telemetry: ActiveProcessSnapshot['telemetry']): number {
    return telemetry.network?.connectionCount ?? 0;
}

function scoreProcessChange(
    snapshot: ActiveProcessSnapshot,
    prior: ActiveProcessSnapshot,
    matchedBy: MatchedPrior['matchedBy'],
): number {
    let score = 0;

    if (matchedBy === 'IDENTITY' && snapshot.pid !== prior.pid) score += 1;
    if ((snapshot.parentPid ?? null) !== (prior.parentPid ?? null)) score += 1;
    if ((snapshot.executionPath ?? null) !== (prior.executionPath ?? null)) score += 1;
    if ((snapshot.commandLine ?? null) !== (prior.commandLine ?? null)) score += 1;
    if ((snapshot.trust?.sha256 ?? null) !== (prior.trust?.sha256 ?? null)) score += 1;
    if ((snapshot.trust?.signaturePublisher ?? null) !== (prior.trust?.signaturePublisher ?? null)) score += 1;
    if ((snapshot.trust?.hasValidSignature ?? null) !== (prior.trust?.hasValidSignature ?? null)) score += 1;

    return score;
}

function scoreSuspiciousBinary(snapshot: ActiveProcessSnapshot): number {
    let score = 0;
    const flags = new Set(snapshot.activeFlags.map(String));

    if (flags.has('SUSPICIOUS_PATH')) score += 35;
    if (flags.has('UNSIGNED')) score += 30;
    if (flags.has('PENDING_REVIEW')) score += 20;
    if (flags.has('POLICY_VIOLATION')) score += 40;
    if (flags.has('NETWORK_HEAVY')) score += 10;
    if (snapshot.trust?.hasValidSignature === false) score += 25;
    if (!snapshot.trust?.signaturePublisher) score += 10;
    if (!snapshot.executionPath) score += 5;

    return Math.min(score, 100);
}

function isOrphaned(
    snapshot: ActiveProcessSnapshot,
    prior: ActiveProcessSnapshot | undefined,
    currentIndex: SnapshotIndex,
    previousIndex: SnapshotIndex,
    gracePeriodMs: number,
): boolean {
    if (!snapshot.parentPid) return false;
    if (currentIndex.byPid.has(snapshot.parentPid)) return false;

    const parentPreviouslyExisted = previousIndex.byPid.has(snapshot.parentPid);
    const elapsedMs = prior ? snapshot.observedAtEpochMs - prior.observedAtEpochMs : 0;

    return parentPreviouslyExisted && elapsedMs >= gracePeriodMs;
}

function isGhostProcess(
    snapshot: ActiveProcessSnapshot,
    state: ProcessScanDiffState,
    identityKey: string,
    requiredScans: number,
): boolean {
    const flags = new Set(snapshot.activeFlags.map(String));
    if (!flags.has('GHOST_PROCESS')) return false;
    if (requiredScans <= 1) return true;

    const previousCount = state.ghostConsecutiveByIdentity.get(identityKey) ?? 0;
    return previousCount + 1 >= requiredScans;
}

function recordRestart(state: ProcessScanDiffState, identityKey: string, observedAtEpochMs: number, windowMs: number): void {
    const existing = state.restartEpochsByIdentity.get(identityKey) ?? [];
    const next = [...existing, observedAtEpochMs].filter((epochMs) => observedAtEpochMs - epochMs <= windowMs);
    state.restartEpochsByIdentity.set(identityKey, next);
}

function shouldSuppressAsNoise(args: {
    snapshot: ActiveProcessSnapshot;
    events: ProcessEvent[];
    includeNoise: boolean;
    noiseProcessNames: Set<string>;
    state: ProcessScanDiffState;
    identityKey: string;
    restartLoopThreshold: number;
}): boolean {
    const { snapshot, events, includeNoise, noiseProcessNames, state, identityKey, restartLoopThreshold } = args;

    if (includeNoise) return false;
    if (events.length === 0) return false;
    if (!noiseProcessNames.has(normalizeIdentityPart(snapshot.executableName))) return false;

    const highSignalEvents: ProcessEvent[] = [
        'CPU_SPIKE',
        'RAM_SPIKE',
        'NETWORK_SPIKE',
        'NEW_SUSPICIOUS_BINARY',
        'ORPHAN_DETECTED',
        'GHOST_PROCESS',
        'POLICY_MATCHED',
        'ACTION_RECOMMENDED',
        'ACTION_TAKEN',
    ];

    if (events.some((event) => highSignalEvents.includes(event))) return false;

    const restartCount = state.restartEpochsByIdentity.get(identityKey)?.length ?? 0;
    if (restartCount >= restartLoopThreshold) return false;

    return events.every((event) => event === 'PROCESS_STARTED' || event === 'PROCESS_EXITED' || event === 'PROCESS_CHANGED');
}

function getSeverity(snapshot: ActiveProcessSnapshot, events: ProcessEvent[]): ScanDiffSeverity {
    const flags = new Set(snapshot.activeFlags.map(String));

    if (events.includes('NEW_SUSPICIOUS_BINARY') || flags.has('POLICY_VIOLATION')) return 'CRITICAL';
    if (events.includes('GHOST_PROCESS') || events.includes('ORPHAN_DETECTED')) return 'HIGH';
    if (events.includes('CPU_SPIKE') || events.includes('RAM_SPIKE') || events.includes('NETWORK_SPIKE')) return 'MEDIUM';
    if (events.length > 0) return 'LOW';

    return 'LOW';
}

function getObserverAction(events: ProcessEvent[], severity: ScanDiffSeverity): string {
    if (events.length === 0) return 'OBSERVE';
    if (severity === 'CRITICAL') return 'REQUIRE_CONFIRMATION';
    if (severity === 'HIGH' || severity === 'MEDIUM') return 'NOTIFY';
    return 'OBSERVE';
}

function createReasons(events: ProcessEvent[], snapshot: ActiveProcessSnapshot, prior?: ActiveProcessSnapshot): string[] {
    if (events.length === 0) return ['No scan-diff events detected. Observer mode only.'];

    return events.map((event) => {
        switch (event) {
            case 'PROCESS_STARTED':
                return prior && prior.pid !== snapshot.pid
                    ? `${snapshot.executableName} restarted with a new PID (${prior.pid} -> ${snapshot.pid}).`
                    : `${snapshot.executableName} appeared in the current scan.`;
            case 'PROCESS_EXITED':
                return `${snapshot.executableName} exited since the previous scan.`;
            case 'CPU_SPIKE':
                return `${snapshot.executableName} crossed the CPU spike threshold.`;
            case 'RAM_SPIKE':
                return `${snapshot.executableName} crossed the RAM spike threshold.`;
            case 'NETWORK_SPIKE':
                return `${snapshot.executableName} crossed the network activity threshold.`;
            case 'PROCESS_CHANGED':
                return `${snapshot.executableName} changed PID, parent, command, path, hash, or signature signals.`;
            case 'NEW_SUSPICIOUS_BINARY':
                return `${snapshot.executableName} is newly observed and has suspicious trust or behavior signals.`;
            case 'ORPHAN_DETECTED':
                return `${snapshot.executableName} appears to be running after its parent process exited.`;
            case 'GHOST_PROCESS':
                return `${snapshot.executableName} repeatedly matches ghost-process behavior.`;
            case 'POLICY_MATCHED':
            case 'ACTION_RECOMMENDED':
            case 'ACTION_TAKEN':
                return `${event} is reserved for the policy/action engine.`;
            default:
                return `${snapshot.executableName} triggered ${event}.`;
        }
    });
}

function markExited(snapshot: ActiveProcessSnapshot): ActiveProcessSnapshot {
    return {
        ...snapshot,
        state: 'EXITED' as ActiveProcessSnapshot['state'],
    };
}

function normalizeProcessState(state: ActiveProcessSnapshot['state']): 'RUNNING' | 'EXITED' | 'UNKNOWN' {
    const normalized = String(state ?? 'UNKNOWN').toUpperCase();
    if (normalized === 'RUNNING' || normalized === 'EXITED') return normalized;
    return 'UNKNOWN';
}

function createNoiseSet(extraNames: string[] | undefined): Set<string> {
    const names = new Set(DEFAULT_NOISE_PROCESS_NAMES);

    for (const name of extraNames ?? []) {
        const normalized = normalizeIdentityPart(name);
        if (normalized) names.add(normalized);
    }

    return names;
}

function pruneState(state: ProcessScanDiffState, currentIndex: SnapshotIndex, historyLimit: number): void {
    const currentIdentityKeys = new Set(currentIndex.byIdentity.keys());

    for (const [identityKey, history] of state.telemetryHistoryByIdentity.entries()) {
        if (currentIdentityKeys.has(identityKey)) {
            state.telemetryHistoryByIdentity.set(identityKey, history.slice(-Math.max(0, historyLimit)));
            continue;
        }

        // Keep a small amount of recent exited-process context for restart matching/noise suppression.
        state.telemetryHistoryByIdentity.set(identityKey, history.slice(-1));
    }

    for (const [identityKey, count] of state.ghostConsecutiveByIdentity.entries()) {
        if (!currentIdentityKeys.has(identityKey) && count === 0) {
            state.ghostConsecutiveByIdentity.delete(identityKey);
        }
    }
}

function normalizeIdentityPart(value: string | undefined): string {
    return value?.trim().toLowerCase() ?? '';
}

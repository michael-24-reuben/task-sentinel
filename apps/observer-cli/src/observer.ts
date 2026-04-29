import {
    ActiveProcessSnapshot, DEFAULT_PROCESS_EVENT_THRESHOLDS,
    UserDecisionRule
} from '@task-sentinel/shared';
import {ProcessCollector, ScriptSection} from '@task-sentinel/collector';
import {DEFAULT_RESOURCE_THRESHOLDS, ProcessClassifier} from '@task-sentinel/classifier';
import {createProcessScanDiffState, evaluateProcessScanDiff} from "@task-sentinel/policy-engine";

export interface ObserverRuntimeOptions {
    intervalMs: number;
    once: boolean;
    clearScreen: boolean;
    maxScans?: number;
    scanLevel: ScriptSection[];
    cpuSpikePercent?: number;
    memorySurgeMb?: number;
}

export interface ObserverRuntimeConfig {
    collector: ProcessCollector;
    rules: UserDecisionRule[];
    options: ObserverRuntimeOptions;
    classifier?: ProcessClassifier;
}

function sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

function normalizeIdentityPart(value: string | undefined): string {
    return value?.trim().toLowerCase() ?? '';
}

function makeProcessKey(process: Pick<ActiveProcessSnapshot, 'pid' | 'executionPath' | 'executableName'>): string {
    const identity = normalizeIdentityPart(process.executionPath) || normalizeIdentityPart(process.executableName);

    return `${process.pid}::${identity}`;
}

function snapshotByKey(processes: ActiveProcessSnapshot[]): Map<string, ActiveProcessSnapshot> {
    return new Map(processes.map((process) => [makeProcessKey(process), process]));
}


export async function runObserver(config: ObserverRuntimeConfig): Promise<void> {
    const {
        collector,
        rules,
        options,
        classifier = new ProcessClassifier(),
    } = config;

    const scanDiffState = createProcessScanDiffState();
    let scanCount = 0;
    let scanContext: {
        classifiedSnapshots: ActiveProcessSnapshot[];
        pendingEvaluations: Promise<void>[];
    } | null = null;

    // IMPORTANT: Register callback ONCE outside the loop to avoid duplicate listeners accumulating.
    collector.onSnapshotMapped((snapshot) => {
        if (!scanContext) return;

        const task = (async () => {
            const classified = classifier.classify(snapshot, {
                resourceThresholds: DEFAULT_RESOURCE_THRESHOLDS,
            });

            scanContext!.classifiedSnapshots.push(classified);
        })();

        scanContext.pendingEvaluations.push(task);
        return task;
    });

    let previousScan: ActiveProcessSnapshot[] = [];

    while (!options.maxScans || scanCount < options.maxScans) {
        const startedAt = Date.now();

        // Reset scanContext for this iteration (do not register callback here)
        scanContext = {
            classifiedSnapshots: [],
            pendingEvaluations: [],
        };

        await collector.collect(options.scanLevel);
        await Promise.all(scanContext.pendingEvaluations);

        const classifiedSnapshots = scanContext.classifiedSnapshots;

        if (scanCount === 0 && classifiedSnapshots.length > 0) {
            console.log('[DEBUG] First scan - sample of process PIDs:');
            console.log(classifiedSnapshots.slice(0, 10).map(p => ({
                pid: p.pid,
                name: p.executableName,
                identity: `${p.pid}::${p.executableName}`,
            })));
        }

        const events = evaluateProcessScanDiff(previousScan, classifiedSnapshots, {
            mode: 'FULL',
            thresholds: DEFAULT_PROCESS_EVENT_THRESHOLDS,
            telemetryHistoryLimit: 5,
            state: scanDiffState,
            emitUnchanged: false,
        });

        if (options.clearScreen) {
            console.clear();
        }

        console.log(`TASK SENTINEL — LIVE OBSERVER (${new Date().toLocaleTimeString()})`);
        console.log(`Processes scanned: ${classifiedSnapshots.length}`);
        console.log(`Change events: ${events.length}`);
        console.log(`Scan duration: ${Date.now() - startedAt}ms\n`);

        console.log(`[DEBUG] Previous scan: ${previousScan.length} processes, Current: ${classifiedSnapshots.length} processes`);

        console.log(JSON.stringify(events, null, 2));

        previousScan = classifiedSnapshots;
        scanContext = null;
        scanCount += 1;

        if (options.once || options.maxScans === scanCount) {
            break;
        }

        await sleep(options.intervalMs);
    }
}

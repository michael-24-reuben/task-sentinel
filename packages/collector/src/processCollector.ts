import type {ActiveProcessSnapshot} from '@task-sentinel/shared';
import {mapRawProcess} from './mappers/mapRawProcess.js';
import type {ProcessAdapter, ProcessCollectorOptions, RawProcess, ScriptSection} from './types.js';
import {projectSnapshot} from "./projectors/projectSnapshot.js";
import {FULL_AUDIT, FULL_PROFILE} from "./adapters/constants.js";
import {enrichWithTelemetry, evalOSAdapter, evalProcessTrustSignals} from "./adapters/adapterContext.js";
import {sleep} from "./utils.js";

interface ProcessCollectorEvents {
    onRawProcessCollected?: (raw: RawProcess) => void | Promise<void>;
    onSnapshotMapped?: (
        snapshot: ActiveProcessSnapshot,
        raw: RawProcess,
    ) => void | Promise<void>;
}

export class ProcessCollector {
    private readonly adapter: ProcessAdapter = evalOSAdapter();
    private readonly events: ProcessCollectorEvents = {};

    constructor(
        private readonly options: ProcessCollectorOptions = {
            profile: FULL_PROFILE,
            projection: {},
        },
    ) {
    }

    onRawProcessCollected(e: (raw: RawProcess) => void | Promise<void>): void | Promise<void> {
        this.events.onRawProcessCollected = e;
    }

    onSnapshotMapped(e: (snapshot: ActiveProcessSnapshot, raw: RawProcess,) => void | Promise<void>): void {
        this.events.onSnapshotMapped = e;
    }

    removeOnRawProcessCollected(): void {
        this.events.onRawProcessCollected = undefined;
    }

    removeOnSnapshotMapped(): void {
        this.events.onSnapshotMapped = undefined;
    }

    async collect(approval: ScriptSection[] = FULL_AUDIT): Promise<ActiveProcessSnapshot[]> {
        const sampleWindowMs = this.options.sampleWindowMs ?? 750;
        const logicalCpuCount = this.options.logicalCpuCount ?? 1;

        const firstSample = await this.adapter.listProcesses(approval, this.options.profile);
        const startedAt = Date.now();

        await sleep(sampleWindowMs);

        const secondSample = await this.adapter.listProcesses(approval, this.options.profile);
        const observedAtEpochMs = Date.now();
        const elapsedSeconds = Math.max(0.001, (observedAtEpochMs - startedAt) / 1000);

        const enrichedProcesses = enrichWithTelemetry(
            firstSample,
            secondSample,
            elapsedSeconds,
            logicalCpuCount,
            this.options.profile,
        );

        const snapshots: ActiveProcessSnapshot[] = [];

        for (const rawProcess of enrichedProcesses) {
            await this.emitRawProcessMapped(rawProcess);

            // FIXME: The following process does not evaluate `trust`. Create a trust evaluation
            const trustResolver = evalProcessTrustSignals();
            const processTrustSignals = await trustResolver.resolve(rawProcess);
            const mappedSnapshot = mapRawProcess(rawProcess, processTrustSignals, observedAtEpochMs);
            const projectedSnapshot = projectSnapshot(mappedSnapshot, this.options.projection);

            await this.emitActiveProcessSnapshotMapped(projectedSnapshot, rawProcess);

            snapshots.push(projectedSnapshot);
        }

        return snapshots;
    }

    private async emitRawProcessMapped(rawProcess: RawProcess): Promise<void> {
        await this.events.onRawProcessCollected?.(rawProcess);
    }

    private async emitActiveProcessSnapshotMapped(
        snapshot: ActiveProcessSnapshot,
        rawProcess: RawProcess,
    ): Promise<void> {
        await this.events.onSnapshotMapped?.(snapshot, rawProcess);
    }
}


import type {ActiveProcessSnapshot} from '@task-sentinel/shared';
import {behaviorRules} from './rules/behaviorRules.js';
import {resourceRules, type ResourceThresholds} from './rules/resourceRules.js';
import {inferVitality} from './rules/vitalityRules.js';

export interface ProcessClassifierOptions {
    resourceThresholds?: Partial<ResourceThresholds>;
}

/**
 * Applies deterministic classification rules to active process snapshots.
 *
 * `ProcessClassifier` is responsible for interpreting raw/normalized process
 * data and enriching it with inferred system-level meaning, such as vitality
 * and behavior flags. It does not decide whether a process should be killed,
 * ignored, trusted, or escalated to the user.
 *
 * This class operates before policy evaluation:
 *
 * - `ProcessClassifier` answers: "What is this process doing?"
 * - `PolicyEngine.evaluate` answers: "What should Task Sentinel do about it?"
 *
 * Classification is based on machine-observable facts such as telemetry,
 * process identity, resource usage, parent/child state, and rule-based
 * heuristics. Human decisions, saved user rules, whitelists, auto-kill
 * preferences, and confirmation requirements belong in the policy layer.
 *
 * The classifier should remain deterministic and explainable. It should not
 * rely on LLM judgment for core flags or safety-related classification.
 */
export class ProcessClassifier {
    /**
     * Classifies a single active process snapshot.
     *
     * This method enriches the provided snapshot by inferring its vitality and
     * applying deterministic resource and behavior rules. Existing flags are
     * preserved, and newly detected flags are merged without duplication.
     *
     * Optional classifier settings may override default thresholds, such as CPU,
     * memory, disk, network, GPU, thread, or handle limits.
     *
     * This method does not apply user policy decisions and does not choose an
     * action. The returned snapshot is intended to be passed to the policy engine
     * for action evaluation.
     */
    classify(process: ActiveProcessSnapshot, options: ProcessClassifierOptions = {}): ActiveProcessSnapshot {
        const resourceThresholds = options.resourceThresholds
            ? {...options.resourceThresholds}
            : undefined;

        const classified: ActiveProcessSnapshot = {
            ...process,
            vitality: inferVitality(process),
        };

        const flags = new Set([
            ...classified.activeFlags,
            ...resourceRules(classified, resourceThresholds as ResourceThresholds | undefined),
            ...behaviorRules(classified),
        ]);

        return {
            ...classified,
            activeFlags: [...flags],
        };
    }

    /**
     * Classifies multiple active process snapshots using the same classifier
     * options.
     *
     * This is a convenience wrapper around `classify` for batch processing after
     * process collection and mapping. Each snapshot is classified independently.
     *
     * This method does not evaluate user rules or produce policy actions.
     */
    classifyMany(processes: ActiveProcessSnapshot[], options: ProcessClassifierOptions = {}): ActiveProcessSnapshot[] {
        return processes.map((process) => this.classify(process, options));
    }
}

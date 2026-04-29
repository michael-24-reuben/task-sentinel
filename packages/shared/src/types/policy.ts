import type {
    PolicyAction,
    PolicyConstraint,
    PolicyMatchType,
    UserDecision,
} from '../constants/enums.js';
import type { ActiveProcessSnapshot } from './process.js';

export interface UserDecisionRule {
    ruleId: string;
    targetPattern: string;
    matchType: PolicyMatchType;
    decision: UserDecision;
    constraintType: PolicyConstraint;
    expirationEpochMs?: number | null;
    userNotes?: string;
}

export interface PolicyEvaluation {
    process: ActiveProcessSnapshot;
    action: PolicyAction;
    reasons: string[];
    matchedRuleIds: string[];
    safeToAutoAct: boolean;
}

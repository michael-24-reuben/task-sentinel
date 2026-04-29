import type { RawProcess } from '../types.js';
import type { ProcessTrustSignals } from '@task-sentinel/shared';

export interface ProcessTrustResolver {
  resolve(rawProcess: RawProcess): Promise<ProcessTrustSignals>;
}
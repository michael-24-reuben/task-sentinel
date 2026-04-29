import type { RawProcess } from '../types.js';
import type { ProcessTrustSignals } from '@task-sentinel/shared';
import type { ProcessTrustResolver } from './ProcessTrustResolver.js';
import type { TrustCollectionOptions } from './TrustCollectionOptions.js';
import type { HashProvider } from './HashProvider.js';
import type { SignatureProvider } from './SignatureProvider.js';
import type { KnownPathChecker } from './KnownPathChecker.js';

export class DefaultProcessTrustResolver implements ProcessTrustResolver {
  constructor(
    private readonly deps: {
      knownPathChecker: KnownPathChecker;
      hashProvider: HashProvider;
      signatureProvider: SignatureProvider;
    },
    private readonly options: TrustCollectionOptions = {},
  ) {}

  async resolve(rawProcess: RawProcess): Promise<ProcessTrustSignals> {
    const executionPath = rawProcess.executionPath;

    if (!executionPath) {
      return {
        metadataPublisher: rawProcess.metadataPublisher,
      };
    }

    const [sha256, signature, isKnownPath] = await Promise.all([
      this.options.includeHash
        ? this.deps.hashProvider.sha256(executionPath).catch(() => undefined)
        : Promise.resolve(undefined),

      this.options.includeSignature
        ? this.deps.signatureProvider.readSignature(executionPath).catch(() => undefined)
        : Promise.resolve(undefined),

      this.options.includeKnownPath
        ? this.deps.knownPathChecker.isKnownPath(executionPath).catch(() => false)
        : Promise.resolve(undefined),
    ]);

    return {
      sha256,
      metadataPublisher: rawProcess.metadataPublisher,
      signaturePublisher: signature?.publisher,
      hasValidSignature: signature?.isValid,
      isKnownPath,
    };
  }
}
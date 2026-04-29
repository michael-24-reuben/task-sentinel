import path from 'node:path';
import type { KnownPathChecker } from '../KnownPathChecker.js';

export class WindowsKnownPathChecker implements KnownPathChecker {
  async isKnownPath(filePath: string): Promise<boolean> {
    const normalized = path.normalize(filePath).toLowerCase();

    const knownRoots = [
      process.env.SystemRoot,
      process.env.ProgramFiles,
      process.env['ProgramFiles(x86)'],
      process.env.LOCALAPPDATA
        ? path.join(process.env.LOCALAPPDATA, 'Microsoft', 'WindowsApps')
        : undefined,
    ]
      .filter(Boolean)
      .map((entry) => path.normalize(entry as string).toLowerCase());

    return knownRoots.some((root) => normalized.startsWith(root));
  }
}
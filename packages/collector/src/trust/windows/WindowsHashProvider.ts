import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import type { HashProvider } from '../HashProvider.js';

export class WindowsHashProvider implements HashProvider {
  async sha256(filePath: string): Promise<string | undefined> {
    return new Promise((resolve) => {
      const hash = createHash('sha256');
      const stream = createReadStream(filePath);

      stream.on('data', (chunk) => hash.update(chunk));
      stream.on('end', () => resolve(hash.digest('hex')));
      stream.on('error', () => resolve(undefined));
    });
  }
}
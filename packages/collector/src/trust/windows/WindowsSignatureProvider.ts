import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type { SignatureProvider } from '../SignatureProvider.js';

const execFileAsync = promisify(execFile);

interface AuthenticodeResult {
  Status?: string;
  SignerCertificate?: {
    Subject?: string;
  };
}

export class WindowsSignatureProvider implements SignatureProvider {
  async readSignature(filePath: string): Promise<{
    publisher?: string;
    isValid?: boolean;
  } | undefined> {
    const script = `
      $sig = Get-AuthenticodeSignature -LiteralPath $args[0]
      [PSCustomObject]@{
        Status = $sig.Status.ToString()
        SignerCertificate = if ($sig.SignerCertificate) {
          [PSCustomObject]@{
            Subject = $sig.SignerCertificate.Subject
          }
        } else {
          $null
        }
      } | ConvertTo-Json -Depth 4
    `;

    try {
      const { stdout } = await execFileAsync(
        'powershell.exe',
        ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', script, filePath],
        {
          windowsHide: true,
          maxBuffer: 1024 * 1024,
        },
      );

      const parsed = JSON.parse(stdout || '{}') as AuthenticodeResult;

      return {
        publisher: extractPublisher(parsed.SignerCertificate?.Subject),
        isValid: parsed.Status === 'Valid',
      };
    } catch {
      return undefined;
    }
  }
}

function extractPublisher(subject?: string): string | undefined {
  if (!subject) return undefined;

  const cnMatch = subject.match(/CN=([^,]+)/i);
  if (cnMatch?.[1]) return cnMatch[1].trim();

  const oMatch = subject.match(/O=([^,]+)/i);
  if (oMatch?.[1]) return oMatch[1].trim();

  return subject;
}
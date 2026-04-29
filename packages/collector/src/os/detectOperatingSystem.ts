export type OperatingSystem =
  | 'windows'
  | 'macos'
  | 'linux'
  | 'android'
  | 'unknown';

export function detectOperatingSystem(): OperatingSystem {
  switch (process.platform) {
    case 'win32':
      return 'windows';

    case 'darwin':
      return 'macos';

    case 'linux':
      // Optional Android detection
      if (process.env.ANDROID_ROOT || process.env.ANDROID_DATA) {
        return 'android';
      }
      return 'linux';

    default:
      return 'unknown';
  }
}
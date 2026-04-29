export const CORE_OS_PROCESS_NAMES = new Set<string>([
    'system idle process',
    'secure system',
    'system',
    'registry',
    'smss.exe',
    'csrss.exe',
    'wininit.exe',
    'winlogon.exe',
    'services.exe',
    'lsass.exe',
    'lsm.exe',
    'dwm.exe',
]);

export const SYSTEM_SUPPORT_PROCESS_NAMES = new Set<string>([
    'explorer.exe',
    'svchost.exe',
    'spoolsv.exe',
    'taskhostw.exe',
    'runtimebroker.exe',
    'sihost.exe',
    'searchindexer.exe',
    'fontdrvhost.exe',
]);

export function normalizeProcessName(name: string): string {
    return name.trim().toLowerCase();
}

export function isCoreOsProcess(name: string): boolean {
    return CORE_OS_PROCESS_NAMES.has(normalizeProcessName(name));
}

export function isSystemSupportProcess(name: string): boolean {
    return SYSTEM_SUPPORT_PROCESS_NAMES.has(normalizeProcessName(name));
}
import {
    VITALITY,
    isCoreOsProcess,
    isSystemSupportProcess,
    type ActiveProcessSnapshot,
    type Vitality,
} from '@task-sentinel/shared';

export function inferVitality(process: Pick<ActiveProcessSnapshot, 'executableName'>): Vitality {
    if (isCoreOsProcess(process.executableName)) return VITALITY.CORE_OS;
    if (isSystemSupportProcess(process.executableName)) return VITALITY.SYSTEM_SUPPORT;
    return VITALITY.USER_LAND;
}

import {detectOperatingSystem} from "./os/detectOperatingSystem.js";

export const osSystem = detectOperatingSystem();

export function sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

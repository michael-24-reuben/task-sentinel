import {PolicyEvaluation} from "@task-sentinel/shared";
import {ScriptSection} from "@task-sentinel/collector";

export class PolicyLogger {
    /**
     * Entry point that handles different scan depths
     */
    static log(result: PolicyEvaluation, sections: ScriptSection[]): void {
        console.log(this.formatBySection(result, sections) + '\n');
    }

    private static formatBySection(result: PolicyEvaluation, sections: ScriptSection[]): string {
        const { process, action } = result;
        const time = this.formatTime(process.observedAtEpochMs);
        const level = this.resolveLevel(result);
        const severity = this.resolveSeverity(result);

        // 1. Header (Always present)
        const header = `[${time}] ${level.padEnd(5)} \"${process.executableName}\" PID:${process.pid} ${process.vitality} ${severity}`;

        // 2. Body Sections (Dynamic based on the enum provided)
        const body: string[] = [];

        // Grouping logic for clean multi-line output
        if (sections.includes('owner')) {
            body.push(`OWNER: ${process.user || 'SYSTEM'}`);
        }

        // Metrics Row (CPU, RAM, GPU)
        const perfRow: string[] = [];
        if (sections.includes('cpu')) perfRow.push(`CPU:${Math.round(process.telemetry.cpuPercent)}%`);
        if (sections.includes('memory')) perfRow.push(`RAM:${Math.round(process.telemetry.memoryMb)}MB`);
        if (sections.includes('gpu')) {
            const usage = process.telemetry.gpu?.usagePercent ?? 0;
            const engine = process.telemetry.gpu?.engine ? ` [${process.telemetry.gpu.engine}]` : '';
            perfRow.push(`GPU:${usage}%${engine}`);
        }
        if (perfRow.length > 0) body.push(perfRow.join(' '));

        // OS Resources Row (Threads, Handles)
        const resRow: string[] = [];
        if (sections.includes('threads')) resRow.push(`THR:${process.telemetry.threads}`);
        if (sections.includes('handles')) resRow.push(`HND:${process.telemetry.handles}`);
        if (resRow.length > 0) body.push(resRow.join(' '));

        // IO Rows
        if (sections.includes('disk')) {
            const { readBytesPerSecond: r, writeBytesPerSecond: w } = process.telemetry.disk;
            body.push(`DISK: R:${this.formatBytes(r)}/s W:${this.formatBytes(w)}/s`);
        }

        if (sections.includes('network')) {
            const { receiveBytesPerSecond: r, sendBytesPerSecond: s, connectionCount: c } = process.telemetry.network;
            body.push(`NET: RX:${this.formatBytes(r)}/s TX:${this.formatBytes(s)}/s CONNS:${c}`);
        }

        // CIM / Metadata
        if (sections.includes('cim')) {
            body.push(`CIM: [Win32_Process] State:${process.state} Domain:${process.domain}`);
        }

        // 3. Flags & Decisions
        if (process.activeFlags.length > 0) {
            body.push(`Flags: ${process.activeFlags.join(', ')}`);
        }

        body.push(`Action: ${action}`);

        if (result.reasons.length > 0) {
            body.push(`Reason: \"${result.reasons[0]}\"`);
        }

        return [header, ...body].join('\n');
    }

    // --- Helpers ---

    private static formatBytes(bytes: number): string {
        if (bytes === 0) return '0B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + sizes[i];
    }

    private static resolveLevel(result: PolicyEvaluation): string {
        if (['CONFIRM_REQUIRED', 'BLOCKED_BY_SAFETY_BOUNDARY'].includes(result.action)) return 'ALERT';
        if (result.action === 'NOTIFY' || result.process.activeFlags.length > 0) return 'WARN';
        return 'INFO';
    }

    private static resolveSeverity(result: PolicyEvaluation): string {
        const count = result.process.activeFlags.length;
        if (result.action === 'CONFIRM_REQUIRED' || count >= 3) return 'HIGH';
        if (count >= 1) return 'MEDIUM';
        return 'LOW';
    }

    private static formatTime(epoch: number): string {
        return new Date(epoch).toTimeString().split(' ')[0];
    }
}


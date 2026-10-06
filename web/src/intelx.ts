import type { RecordEntry } from './domain';

export interface IntelXResult {
    target: string;
    provider: string;
    status: 'found' | 'not_found' | 'error';
    records: RecordEntry[];
    count: number;
    truncated: boolean;
    warnings: { message: string }[];
    error?: { code: string; message: string };
}

interface FileRecord { systemId: string; bucket: string; name: string }
function object(value: unknown): value is Record<string, unknown> { return Boolean(value) && typeof value === 'object' && !Array.isArray(value); }

/** Complete IntelX's asynchronous search protocol without repeating start operations. */
export async function lookupIntelX(target: string, query: string, outerSignal: AbortSignal, maxFiles = 10): Promise<IntelXResult> {
    const controller = new AbortController();
    const abort = (): void => controller.abort();
    outerSignal.addEventListener('abort', abort, { once: true });
    if (outerSignal.aborted) controller.abort();
    const deadline = window.setTimeout(() => controller.abort(), 60000);
    let searchId: string | null = null;
    const records: RecordEntry[] = [];
    const seenFiles = new Set<string>();
    const warnings: { message: string }[] = [];
    let truncated = false;
    let complete = false;
    const request = async (operation: string, payload: Record<string, unknown>, signal = controller.signal): Promise<Record<string, unknown>> => {
        const response = await fetch('/api/intelx', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ operation, ...payload }), signal, cache: 'no-store', credentials: 'omit' });
        const result: unknown = await response.json();
        if (!response.ok || !object(result)) throw new Error(object(result) && object(result.error) && typeof result.error.message === 'string' ? result.error.message : `IntelX ${operation} failed (HTTP ${response.status}).`);
        return result;
    };
    try {
        const start = await request('start', { target, query, maxFiles });
        if (typeof start.searchId !== 'string' || !start.searchId) throw new Error('IntelX returned an invalid search identifier.');
        searchId = start.searchId;
        while (!controller.signal.aborted) {
            const result = await request('results', { searchId, limit: maxFiles });
            if (!Array.isArray(result.records) || !['pending', 'complete', 'expired'].includes(String(result.status))) throw new Error('IntelX returned invalid search status data.');
            const files = result.records.map((file: unknown): FileRecord => {
                if (!object(file) || typeof file.systemId !== 'string' || typeof file.bucket !== 'string' || typeof file.name !== 'string') throw new Error('IntelX returned malformed file metadata.');
                return { systemId: file.systemId, bucket: file.bucket, name: file.name };
            });
            truncated ||= result.truncated === true;
            for (const file of files) {
                if (seenFiles.has(file.systemId)) continue;
                if (seenFiles.size >= maxFiles) { truncated = true; break; }
                seenFiles.add(file.systemId);
                const read = await request('read', { systemId: file.systemId, bucket: file.bucket, name: file.name, target, query, hidePasswords: true });
                if (!Array.isArray(read.records) || !['found', 'not_found', 'error'].includes(String(read.status))) throw new Error('IntelX returned malformed file contents.');
                if (read.status === 'error') throw new Error(object(read.error) && typeof read.error.message === 'string' ? read.error.message : 'IntelX could not read a search result.');
                for (const record of read.records as unknown[]) {
                    if (!object(record) || typeof record.source !== 'string' || typeof record.field !== 'string' || typeof record.value !== 'string') throw new Error('IntelX returned malformed records.');
                    if (records.length < 1000) records.push({ source: record.source, field: record.field, value: record.value });
                    else truncated = true;
                }
                truncated ||= read.truncated === true;
            }
            if (result.status === 'expired') throw new Error('The IntelX search expired before it completed.');
            if (result.status === 'complete') { complete = true; break; }
            if (seenFiles.size >= maxFiles || records.length >= 1000) { truncated = true; warnings.push({ message: 'IntelX stopped at the configured file or record limit.' }); break; }
            await waitForNextPoll(controller.signal);
        }
        if (!complete && !truncated) throw new Error('IntelX exceeded the 60-second browser investigation limit.');
    } catch (error: unknown) {
        if (outerSignal.aborted) throw error;
        const message = controller.signal.aborted ? 'IntelX exceeded the 60-second investigation limit. This is an incomplete search.' : error instanceof Error ? error.message : 'IntelX search failed.';
        if (!records.length) return { target, provider: 'IntelX', status: 'error', records, count: 0, truncated: true, warnings, error: { code: 'INTELX_INCOMPLETE', message } };
        warnings.push({ message });
        truncated = true;
    } finally {
        window.clearTimeout(deadline);
        outerSignal.removeEventListener('abort', abort);
        if (searchId) {
            const cleanup = new AbortController();
            const cleanupDeadline = window.setTimeout(() => cleanup.abort(), 15000);
            try { await request('terminate', { searchId }, cleanup.signal); }
            catch { warnings.push({ message: 'IntelX search termination could not be confirmed. The provider may retain the search until it expires.' }); }
            finally { window.clearTimeout(cleanupDeadline); }
        }
    }
    return { target, provider: 'IntelX', status: records.length ? 'found' : complete ? 'not_found' : 'error', records, count: records.length, truncated, warnings, error: !complete && !records.length ? { code: 'INTELX_INCOMPLETE', message: 'The limited IntelX search did not complete; no absence of matches can be concluded.' } : undefined };
}

function waitForNextPoll(signal: AbortSignal): Promise<void> {
    return new Promise((resolve, reject) => {
        const onAbort = (): void => { window.clearTimeout(timer); signal.removeEventListener('abort', onAbort); reject(new DOMException('Search cancelled.', 'AbortError')); };
        const timer = window.setTimeout(() => { signal.removeEventListener('abort', onAbort); resolve(); }, 1000);
        signal.addEventListener('abort', onAbort, { once: true });
        if (signal.aborted) onAbort();
    });
}

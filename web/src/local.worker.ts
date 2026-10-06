import { isEmailAddress, MAX_TARGETS } from './domain';
import { TarTextReader } from './tar';

interface SearchRequest {
    type: 'search';
    id: number;
    files: File[];
    targets: string[];
    loose?: boolean;
}

interface CancelRequest {
    type: 'cancel';
    id: number;
}

interface LocalRecord {
    target: string;
    source: string;
    field: 'line';
    value: string;
}

const MAX_FILES = 200;
const MAX_BYTES = 100 * 1024 * 1024;
const MAX_LINE_LENGTH = 64 * 1024;
const MAX_RECORDS = 1000;
const scope = self as unknown as {
    onmessage: ((event: MessageEvent<SearchRequest | CancelRequest>) => void) | null;
    postMessage: (message: unknown) => void;
};
let currentId = 0;
let activeReader: ReadableStreamDefaultReader<Uint8Array> | null = null;

scope.onmessage = (event) => {
    const request = event.data;
    if (request.type === 'cancel') {
        if (currentId === request.id) {
            currentId = 0;
            void activeReader?.cancel().catch(() => undefined);
        }
        return;
    }
    currentId = request.id;
    void searchFiles(request).catch((error: unknown) => {
        if (currentId === request.id) {
            scope.postMessage({ type: 'error', id: request.id, message: error instanceof Error ? error.message : 'Local search failed.' });
        }
    });
};

async function searchFiles(request: SearchRequest): Promise<void> {
    if (!request.files.length || request.files.length > MAX_FILES) {
        throw new Error(`Choose between 1 and ${MAX_FILES} files.`);
    }
    if (!request.targets.length || request.targets.length > MAX_TARGETS || request.targets.some((target) => request.loose ? !target.trim() || target.length > 254 : !isEmailAddress(target))) {
        throw new Error(`Enter between 1 and ${MAX_TARGETS} valid email addresses.`);
    }
    const targets = [...new Set(request.targets.map((target) => target.toLowerCase()))];
    const records: LocalRecord[] = [];
    const warnings = new Set<string>();
    let bytesRead = 0;
    let filesProcessed = 0;
    let truncated = false;
    const matchLine = (line: string, source: string): void => {
        if (!line || records.length >= MAX_RECORDS) return;
        const normalized = line.toLowerCase();
        for (const target of targets) {
            let offset = normalized.indexOf(target);
            while (offset >= 0) {
                const before = normalized[offset - 1] ?? '';
                const after = normalized[offset + target.length] ?? '';
                if (request.loose || ((!before || !/[a-z0-9.!#$%&'*+/=?^_`{|}~-]/i.test(before)) && (!after || !/[a-z0-9.-]/i.test(after)))) {
                    records.push({ target, source, field: 'line', value: line });
                    break;
                }
                offset = normalized.indexOf(target, offset + 1);
            }
            if (records.length >= MAX_RECORDS) {
                truncated = true;
                return;
            }
        }
    };
    for (const file of request.files) {
        if (currentId !== request.id || truncated) break;
        const filename = file.webkitRelativePath || file.name;
        const tarArchive = /\.(?:tar(?:\.gz)?|tgz)$/i.test(filename);
        const basename = filename.split(/[\\/]/).pop() ?? filename;
        if (/\.(?:zip|7z|rar|bz2|xz)$/i.test(filename) || (!tarArchive && !/\.(?:txt|csv|log|gz)$/i.test(filename) && basename.includes('.'))) {
            warnings.add('Unsupported files were skipped. Use TXT, CSV, LOG, extensionless text, GZIP, or TAR.GZ files.');
            filesProcessed += 1;
            continue;
        }
        if (file.size > MAX_BYTES) {
            warnings.add('Files larger than 100 MB were skipped. Use the CLI for large datasets.');
            filesProcessed += 1;
            continue;
        }
        let stream = file.stream();
        if (/\.(?:gz|tgz)$/i.test(filename)) {
            if (typeof DecompressionStream === 'undefined') {
                warnings.add('This browser cannot decompress GZIP. Extract the text file first.');
                filesProcessed += 1;
                continue;
            }
            stream = stream.pipeThrough(new DecompressionStream('gzip'));
        }
        const reader = stream.getReader();
        activeReader = reader;
        let decoder = new TextDecoder('utf-8');
        let source = filename;
        let entryReadable = true;
        let pending = '';
        let discardingLongLine = false;
        let lastProgress = 0;
        const processText = (text: string): void => {
            const lines = (pending + text).split(/\r?\n/);
            pending = lines.pop() ?? '';
            for (const line of lines) {
                if (discardingLongLine) {
                    discardingLongLine = false;
                    continue;
                }
                if (line.length > MAX_LINE_LENGTH) {
                    warnings.add('Lines longer than 64 KB were skipped.');
                    continue;
                }
                matchLine(line, source);
                if (truncated) break;
            }
            if (pending.length > MAX_LINE_LENGTH) {
                warnings.add('Lines longer than 64 KB were skipped.');
                pending = '';
                discardingLongLine = true;
            }
        };
        const finalizeText = (): void => {
            processText(decoder.decode());
            if (!discardingLongLine) matchLine(pending, source);
            pending = '';
            discardingLongLine = false;
        };
        const tar = tarArchive ? new TarTextReader({
            onStart: (name) => {
                source = `${filename} :: ${name}`;
                const entryName = name.split('/').pop() ?? name;
                entryReadable = /\.(?:txt|csv|log)$/i.test(entryName) || !entryName.includes('.');
                decoder = new TextDecoder('utf-8');
                pending = '';
                discardingLongLine = false;
            },
            onData: (chunk) => { if (entryReadable && !truncated) processText(decoder.decode(chunk, { stream: true })); },
            onEnd: () => { if (entryReadable && !truncated) finalizeText(); },
        }) : null;
        try {
            while (currentId === request.id && !truncated) {
                const chunk = await reader.read();
                if (chunk.done) break;
                bytesRead += chunk.value.byteLength;
                if (bytesRead > MAX_BYTES) {
                    truncated = true;
                    warnings.add('Stopped at the 100 MB decompressed-data limit. Use the CLI to search the full dataset.');
                    break;
                }
                if (tar) tar.feed(chunk.value);
                else processText(decoder.decode(chunk.value, { stream: true }));
                const now = performance.now();
                if (now - lastProgress > 150) {
                    lastProgress = now;
                    scope.postMessage({ type: 'progress', id: request.id, filesProcessed, totalFiles: request.files.length, bytesRead, matches: records.length });
                }
            }
            if (!truncated && currentId === request.id) {
                if (tar) tar.finish();
                else finalizeText();
            }
        } catch {
            if (currentId === request.id) warnings.add('A file could not be read or decompressed. Other readable files were searched.');
        } finally {
            await reader.cancel().catch(() => undefined);
            reader.releaseLock();
            if (activeReader === reader) activeReader = null;
        }
        filesProcessed += 1;
        if (currentId === request.id) {
            scope.postMessage({ type: 'progress', id: request.id, filesProcessed, totalFiles: request.files.length, bytesRead, matches: records.length });
        }
    }
    if (records.length >= MAX_RECORDS) warnings.add('Stopped at 1,000 matches. Use the CLI for complete results.');
    if (currentId === request.id) {
        scope.postMessage({ type: 'complete', id: request.id, records, filesProcessed, bytesRead, truncated, warnings: [...warnings] });
    }
}

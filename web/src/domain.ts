export interface RecordEntry {
    source: string;
    field: string;
    value: string;
}

export interface ExportRecord extends RecordEntry {
    target: string;
    provider: string;
}

export const MAX_TARGETS = 10;
export const MAX_EXTRACTED_EMAILS = 1000;

/** Extract addresses locally; URLs and remote pages are never fetched. */
export function extractEmails(text: string): string[] {
    const matches = text.match(/[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+/gi) ?? [];
    return [...new Set(matches.map((email) => email.toLowerCase()))].filter((email) => email.length <= 254).slice(0, MAX_EXTRACTED_EMAILS);
}

export function parseEmailTargets(text: string): string[] {
    const entries = text.split(/[\s,;]+/).map((entry) => entry.trim()).filter(Boolean);
    return [...new Set(entries.map((entry) => entry.toLowerCase()))];
}

export function isEmailAddress(target: string): boolean {
    return target.length <= 254 && /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/i.test(target);
}

export function isSensitiveField(field: string): boolean {
    return /password|passwd|pwd|hash|salt|secret|token|credential|ssn|social.?security|credit.?card|(?:^|_)pass(?:$|_)|localsearch|intelx|^bc_|^line$/i.test(field);
}

/** Spreadsheet applications must not interpret untrusted values as formulas. */
export function neutralizeCsvValue(value: string): string {
    const safeValue = /^[\s\u0000-\u0020\uFEFF]*[=+\-@]/.test(value) || /^[\t\r\n]/.test(value) ? `'${value}` : value;
    return `"${safeValue.replaceAll('"', '""')}"`;
}

export function toCsv(records: ExportRecord[]): string {
    const columns = ['target', 'provider', 'source', 'field', 'value'] as const;
    return [columns.join(','), ...records.map((record) => columns.map((column) => neutralizeCsvValue(record[column])).join(','))].join('\r\n');
}

export function visibleValue(record: RecordEntry, showSensitive: boolean): string {
    return !showSensitive && isSensitiveField(record.field) ? '[hidden]' : record.value;
}

/** Append discovered email targets once and stop at the total investigation cap. */
export function appendChaseTargets(targets: string[], seen: Set<string>, records: RecordEntry[], limit: number, powerChase: boolean): boolean {
    const related = records.filter((record) => powerChase || /email|related/i.test(record.field)).flatMap((record) => extractEmails(record.value));
    let truncated = false;
    for (const target of related) {
        if (seen.has(target)) continue;
        if (targets.length >= limit) { truncated = true; continue; }
        seen.add(target);
        targets.push(target);
    }
    return truncated;
}

/** Preserve colons within upstream tagged values while flattening grouped JSON records. */
export function flattenEngineRecords(value: unknown, hideSensitive: boolean, passwordQuery = false): ExportRecord[] {
    if (!value || typeof value !== 'object' || !('targets' in value) || !Array.isArray(value.targets)) return [];
    return value.targets.flatMap((entry: unknown): ExportRecord[] => {
        if (!entry || typeof entry !== 'object' || !('target' in entry) || typeof entry.target !== 'string' || !('data' in entry) || !Array.isArray(entry.data)) return [];
        const record = (field: string, text: string): ExportRecord => ({ target: passwordQuery ? '[password query]' : entry.target as string, provider: 'Original engine', source: 'Original engine', field, value: visibleValue({ source: 'Original engine', field, value: text }, !hideSensitive) });
        return entry.data.flatMap((row: unknown): ExportRecord[] => {
            if (!Array.isArray(row)) return [];
            if (row.length === 2 && typeof row[0] === 'string' && !row[0].includes(':')) return [record(row[0], String(row[1]))];
            return row.filter((cell: unknown): cell is string => typeof cell === 'string').map((cell) => {
                const delimiter = cell.indexOf(':');
                return delimiter > 0 ? record(cell.slice(0, delimiter), cell.slice(delimiter + 1)) : record('record', cell);
            });
        });
    });
}

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { gzipSync } from 'node:zlib';

interface Completion { type: string; id: number; records?: { target: string; value: string; source: string }[]; warnings?: string[]; truncated?: boolean; message?: string }
const scope: { onmessage: ((event: { data: unknown }) => void) | null; postMessage: (value: Completion) => void } = { onmessage: null, postMessage: () => undefined };
Object.defineProperty(globalThis, 'self', { value: scope, configurable: true });
await import('../src/local.worker');
let nextId = 0;

function search(files: File[], targets: string[], loose = false): Promise<Completion> {
    const id = ++nextId;
    return new Promise((resolve, reject) => {
        const deadline = setTimeout(() => reject(new Error('The local worker did not finish within its test deadline.')), 4000);
        scope.postMessage = (result) => {
            if (result.id === id && result.type !== 'progress') { clearTimeout(deadline); resolve(result); }
        };
        scope.onmessage?.({ data: { type: 'search', id, files, targets, loose } });
    });
}

test('local text search matches full addresses and ignores larger address fragments', async () => {
    const result = await search([new File(['prefixuser@example.org:skip\nUSER@example.org:matched\nuser@example.org.evil:skip'], 'records.txt')], ['user@example.org']);
    assert.equal(result.type, 'complete');
    assert.equal(result.records?.length, 1);
    assert.equal(result.records?.[0]?.value, 'USER@example.org:matched');
});

test('local GZIP search decompresses streams without uploading files', async () => {
    const gzip = gzipSync(Buffer.from('target@example.org:private\n'));
    const result = await search([new File([gzip], 'records.txt.gz')], ['target@example.org']);
    assert.equal(result.type, 'complete');
    assert.equal(result.records?.length, 1);
    assert.equal(result.records?.[0]?.source, 'records.txt.gz');
});

test('loose mode supports literal strings and extensionless compilation files', async () => {
    const result = await search([new File(['John.Smith at EvilCorp\nother'], 'x')], ['john.smith'], true);
    assert.equal(result.records?.length, 1);
    assert.equal(result.records?.[0]?.target, 'john.smith');
});

test('overlong lines are skipped and subsequent valid lines are still searched', async () => {
    const result = await search([new File([`${'x'.repeat(70 * 1024)}target@example.org\ntarget@example.org:match`], 'records.log')], ['target@example.org']);
    assert.equal(result.records?.length, 1);
    assert.ok(result.warnings?.some((warning) => warning.includes('64 KB')));
});

test('corrupt compressed data reports an incomplete search rather than success', async () => {
    const result = await search([new File(['not gzip'], 'broken.gz')], ['target@example.org']);
    assert.equal(result.records?.length, 0);
    assert.ok(result.warnings?.length);
});

test('local results stop at the record cap and explicitly report truncation', async () => {
    const result = await search([new File([Array.from({ length: 1010 }, () => 'target@example.org:private').join('\n')], 'records.csv')], ['target@example.org']);
    assert.equal(result.records?.length, 1000);
    assert.equal(result.truncated, true);
});

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { lookupIntelX } from '../src/intelx';

Object.defineProperty(globalThis, 'window', { value: globalThis, configurable: true });

test('IntelX starts once, reads returned files, then terminates the search', async (context) => {
    const original = globalThis.fetch;
    context.after(() => { globalThis.fetch = original; });
    const operations: string[] = [];
    globalThis.fetch = async (_url, options) => {
        const payload = JSON.parse(String(options?.body)) as Record<string, unknown>;
        operations.push(String(payload.operation));
        const bodies: Record<string, unknown> = {
            start: { searchId: 'search-1', status: 'started' },
            results: { status: 'complete', records: [{ systemId: 'file-1', bucket: 'leaks.public', name: 'records.txt' }], truncated: false },
            read: { status: 'found', records: [{ source: 'records.txt', field: 'line', value: 'password:synthetic-secret' }] },
            terminate: { status: 'terminated' },
        };
        if (payload.operation === 'read') assert.equal(payload.hidePasswords, false);
        return new Response(JSON.stringify(bodies[String(payload.operation)]), { status: 200 });
    };
    const result = await lookupIntelX('person@example.org', 'email', new AbortController().signal);
    assert.equal(result.status, 'found');
    assert.equal(result.records.length, 1);
    assert.equal(result.records[0]?.value, 'password:synthetic-secret');
    assert.deepEqual(operations, ['start', 'results', 'read', 'terminate']);
});

test('IntelX only reports no matches after an explicitly completed search', async (context) => {
    const original = globalThis.fetch;
    context.after(() => { globalThis.fetch = original; });
    globalThis.fetch = async (_url, options) => {
        const payload = JSON.parse(String(options?.body)) as Record<string, unknown>;
        return new Response(JSON.stringify(payload.operation === 'start' ? { searchId: 'search-2' } : payload.operation === 'results' ? { status: 'complete', records: [] } : { status: 'terminated' }), { status: 200 });
    };
    const result = await lookupIntelX('person@example.org', 'email', new AbortController().signal);
    assert.equal(result.status, 'not_found');
    assert.equal(result.truncated, false);
});

test('IntelX expired searches remain errors and cleanup failures are visible', async (context) => {
    const original = globalThis.fetch;
    context.after(() => { globalThis.fetch = original; });
    globalThis.fetch = async (_url, options) => {
        const payload = JSON.parse(String(options?.body)) as Record<string, unknown>;
        if (payload.operation === 'terminate') return new Response(JSON.stringify({ error: { message: 'Termination failed.' } }), { status: 502 });
        return new Response(JSON.stringify(payload.operation === 'start' ? { searchId: 'search-3' } : { status: 'expired', records: [] }), { status: 200 });
    };
    const result = await lookupIntelX('person@example.org', 'email', new AbortController().signal);
    assert.equal(result.status, 'error');
    assert.ok(result.error?.message.includes('expired'));
    assert.ok(result.warnings.some((warning) => warning.message.includes('termination')));
});

test('IntelX cancellation terminates an identified search with a fresh request signal', async (context) => {
    const original = globalThis.fetch;
    context.after(() => { globalThis.fetch = original; });
    const controller = new AbortController();
    let terminated = false;
    globalThis.fetch = async (_url, options) => {
        const payload = JSON.parse(String(options?.body)) as Record<string, unknown>;
        if (payload.operation === 'start') return new Response(JSON.stringify({ searchId: 'search-4' }), { status: 200 });
        if (payload.operation === 'results') { controller.abort(); throw new DOMException('Cancelled.', 'AbortError'); }
        terminated = true;
        assert.equal(options?.signal?.aborted, false);
        return new Response(JSON.stringify({ status: 'terminated' }), { status: 200 });
    };
    await assert.rejects(lookupIntelX('person@example.org', 'email', controller.signal), { name: 'AbortError' });
    assert.equal(terminated, true);
});

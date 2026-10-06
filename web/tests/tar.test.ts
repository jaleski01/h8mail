import assert from 'node:assert/strict';
import { test } from 'node:test';
import { TarTextReader } from '../src/tar';

function archive(name: string, text: string, type = '0'): Uint8Array {
    const content = new TextEncoder().encode(text);
    const header = new Uint8Array(512);
    const write = (offset: number, value: string): void => header.set(new TextEncoder().encode(value), offset);
    write(0, name);
    write(124, `${content.length.toString(8).padStart(11, '0')}\0`);
    header.fill(32, 148, 156);
    write(156, type);
    const checksum = header.reduce((sum, byte) => sum + byte, 0);
    write(148, `${checksum.toString(8).padStart(6, '0')}\0 `);
    const result = new Uint8Array(512 + Math.ceil(content.length / 512) * 512 + 1024);
    result.set(header);
    result.set(content, 512);
    return result;
}

test('streams TAR headers and UTF-8 contents across arbitrary chunk boundaries', () => {
    const started: string[] = [];
    const chunks: Uint8Array[] = [];
    let ended = 0;
    const reader = new TarTextReader({ onStart: (name) => started.push(name), onData: (chunk) => chunks.push(chunk), onEnd: () => { ended += 1; } });
    const content = archive('folder/records.txt', 'user@example.org:private\nsecond@example.org');
    for (let offset = 0; offset < content.length; offset += 37) reader.feed(content.subarray(offset, offset + 37));
    reader.finish();
    assert.deepEqual(started, ['folder/records.txt']);
    assert.equal(ended, 1);
    assert.equal(new TextDecoder().decode(Buffer.concat(chunks)), 'user@example.org:private\nsecond@example.org');
});

test('does not follow TAR symlinks or expose their payload as records', () => {
    let started = false;
    const reader = new TarTextReader({ onStart: () => { started = true; }, onData: () => { throw new Error('Symlink content was read.'); }, onEnd: () => undefined });
    reader.feed(archive('../../outside.txt', 'target@example.org', '2'));
    reader.finish();
    assert.equal(started, false);
});

test('rejects corrupt headers and incomplete archive entries', () => {
    const reader = new TarTextReader({ onStart: () => undefined, onData: () => undefined, onEnd: () => undefined });
    const corrupt = archive('records.txt', 'target@example.org');
    corrupt[0] = 42;
    assert.throws(() => reader.feed(corrupt), /checksum/);
    const incomplete = new TarTextReader({ onStart: () => undefined, onData: () => undefined, onEnd: () => undefined });
    incomplete.feed(archive('records.txt', 'target@example.org').subarray(0, 517));
    assert.throws(() => incomplete.finish(), /incomplete/);
});

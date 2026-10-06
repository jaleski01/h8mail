import assert from 'node:assert/strict';
import { test } from 'node:test';
import { appendChaseTargets, extractEmails, flattenEngineRecords, isEmailAddress, neutralizeCsvValue, parseEmailTargets, toCsv, visibleValue } from '../src/domain';

test('extracts unique valid email addresses without fetching remote content', () => {
    assert.deepEqual(extractEmails('Contact USER@example.com or user@example.com. Invalid: no@domain. name+tag@example.org'), ['user@example.com', 'name+tag@example.org']);
});

test('rejects incomplete email domains and excessive address lengths', () => {
    assert.equal(isEmailAddress('person@example.org'), true);
    assert.equal(isEmailAddress('person@example'), false);
    assert.equal(isEmailAddress(`${'a'.repeat(250)}@example.org`), false);
});

test('normalizes and deduplicates pasted target lists', () => {
    assert.deepEqual(parseEmailTargets('Person@EXAMPLE.org; person@example.org\nother@example.org'), ['person@example.org', 'other@example.org']);
});

test('neutralizes formula injection including leading whitespace', () => {
    for (const cell of ['=HYPERLINK("https://example.org")', ' +123', '\tvalue', '\r=CMD()', '\uFEFF@SUM(1)']) {
        assert.ok(neutralizeCsvValue(cell).startsWith('"\''));
    }
    assert.equal(neutralizeCsvValue('safe "quoted" value'), '"safe ""quoted"" value"');
});

test('exports untrusted cells with quoted CSV fields', () => {
    const result = toCsv([{ target: 'user@example.org', provider: 'local', source: '=CMD()', field: 'line', value: 'a,b\n"c"' }]);
    assert.ok(result.includes('"\'=CMD()"'));
    assert.ok(result.includes('"a,b\n""c"""'));
});

test('hides passwords, hashes, and local breach lines by default', () => {
    for (const field of ['Password', 'passwordHash', 'line', 'access_token', 'SSN', 'BC_PASS', 'BREACHDR_PASS', 'LOCALSEARCH', 'INTELX']) {
        assert.equal(visibleValue({ source: 'test', field, value: 'sensitive' }, false), '[hidden]');
    }
    assert.equal(visibleValue({ source: 'test', field: 'Breach', value: 'Example' }, false), 'Example');
    assert.equal(visibleValue({ source: 'test', field: 'line', value: 'sensitive' }, true), 'sensitive');
});

test('chase deduplicates discovered addresses and stops at the total target cap', () => {
    const targets = ['first@example.org'];
    const seen = new Set(targets);
    const records = [{ source: 'Hunter', field: 'related_email', value: 'FIRST@example.org next@example.org third@example.org' }];
    assert.equal(appendChaseTargets(targets, seen, records, 2, false), true);
    assert.deepEqual(targets, ['first@example.org', 'next@example.org']);
    assert.equal(appendChaseTargets(targets, seen, records, 2, false), true);
    assert.deepEqual(targets, ['first@example.org', 'next@example.org']);
});

test('normal chase uses related email fields while power chase searches all returned fields', () => {
    const targets = ['first@example.org'];
    const seen = new Set(targets);
    const records = [{ source: 'Provider', field: 'notes', value: 'other@example.org' }];
    appendChaseTargets(targets, seen, records, 10, false);
    assert.equal(targets.length, 1);
    appendChaseTargets(targets, seen, records, 10, true);
    assert.deepEqual(targets, ['first@example.org', 'other@example.org']);
});

test('engine exports flatten grouped tagged records and preserve URL colons', () => {
    const result = flattenEngineRecords({ targets: [{ target: 'person@example.org', data: [['LOCALSEARCH:[hidden]'], ['HIBP:Example', 'PASTE_URL:https://example.org/id:123'], ['USERNAME', 'person']] }] }, true);
    assert.deepEqual(result.map(({ field, value }) => [field, value]), [['LOCALSEARCH', '[hidden]'], ['HIBP', 'Example'], ['PASTE_URL', 'https://example.org/id:123'], ['USERNAME', 'person']]);
    assert.ok(result.every((record) => record.source === 'Original engine'));
});

test('engine exports hide sensitive tagged values and password query targets', () => {
    const result = flattenEngineRecords({ targets: [{ target: 'query-password', data: [['BC_PASS:private', 'PASSWORD:private', 'LOCALSEARCH:person@example.org:private']] }] }, true, true);
    assert.ok(result.every((record) => record.target === '[password query]' && record.value === '[hidden]'));
});

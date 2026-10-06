import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { makeProviderSearchPlan } from '../src/provider-search';

const providers = [
    { id: 'hibp', name: 'Have I Been Pwned', available: true, queryTypes: ['email'] },
    { id: 'intelx', name: 'Intelligence X', available: true, queryTypes: ['email', 'selector'] },
    { id: 'snusbase', name: 'Snusbase', available: true, queryTypes: ['email', 'password'] },
    { id: 'scylla', name: 'Scylla', available: false, queryTypes: ['email'] },
];

describe('aggregate provider search plan', () => {
    it('includes every available provider supporting the query for each target', () => {
        const plan = makeProviderSearchPlan(['one@example.test', 'two@example.test'], providers, 'email');
        assert.deepEqual(plan.map(({ target, provider }) => [target, provider.id]), [
            ['one@example.test', 'hibp'], ['one@example.test', 'intelx'], ['one@example.test', 'snusbase'],
            ['two@example.test', 'hibp'], ['two@example.test', 'intelx'], ['two@example.test', 'snusbase'],
        ]);
    });

    it('limits non-email queries to providers that actually support them', () => {
        const plan = makeProviderSearchPlan(['example.test'], providers, 'selector');
        assert.deepEqual(plan.map(({ provider }) => provider.id), ['intelx']);
    });
});

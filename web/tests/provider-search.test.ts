import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { makeProviderSearchPlan } from '../src/provider-search';

const providers = [
    { id: 'hibp', name: 'Have I Been Pwned', available: true, queryTypes: ['email'], credentialFields: [{ key: 'apiKey', required: true, configured: true }] },
    { id: 'intelx', name: 'Intelligence X', available: true, queryTypes: ['email', 'selector'], credentialFields: [{ key: 'apiKey', required: true, configured: true }] },
    { id: 'snusbase', name: 'Snusbase', available: true, queryTypes: ['email', 'password'], credentialFields: [{ key: 'apiKey', required: true, configured: false }] },
    { id: 'hunter', name: 'Hunter', available: true, queryTypes: ['email'], freeQueryTypes: ['email'], credentialFields: [{ key: 'apiKey', required: true, configured: false }] },
    { id: 'pwnedpasswords', name: 'HIBP Pwned Passwords', available: true, queryTypes: ['password'], freeQueryTypes: ['password'] },
    { id: 'scylla', name: 'Scylla', available: false, queryTypes: ['email'] },
];

describe('aggregate provider search plan', () => {
    it('includes configured providers and free modes, while skipping unconfigured keys', () => {
        const plan = makeProviderSearchPlan(['one@example.test', 'two@example.test'], providers, 'email');
        assert.deepEqual(plan.map(({ target, provider }) => [target, provider.id]), [
            ['one@example.test', 'hibp'], ['one@example.test', 'intelx'], ['one@example.test', 'hunter'],
            ['two@example.test', 'hibp'], ['two@example.test', 'intelx'], ['two@example.test', 'hunter'],
        ]);
    });

    it('limits non-email queries to providers that actually support them', () => {
        const plan = makeProviderSearchPlan(['example.test'], providers, 'selector');
        assert.deepEqual(plan.map(({ provider }) => provider.id), ['intelx']);
    });

    it('keeps password checking available without a provider key', () => {
        const plan = makeProviderSearchPlan(['synthetic-candidate'], providers, 'password');
        assert.deepEqual(plan.map(({ provider }) => provider.id), ['pwnedpasswords']);
    });
});

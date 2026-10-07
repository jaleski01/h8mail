import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { makeProviderSearchPlan, providerSearchAvailability } from '../src/provider-search';

const providers = [
    { id: 'hibp', name: 'Have I Been Pwned', available: true, queryTypes: ['email'], credentialFields: [{ key: 'apiKey', required: true, configured: true }] },
    { id: 'intelx', name: 'Intelligence X', available: true, queryTypes: ['email', 'selector'], credentialFields: [{ key: 'apiKey', required: true, configured: true }] },
    { id: 'snusbase', name: 'Snusbase', available: true, queryTypes: ['email', 'password'], credentialFields: [{ key: 'apiKey', required: true, configured: false }] },
    { id: 'hunter', name: 'Hunter', available: true, queryTypes: ['email', 'domain'], freeQueryTypes: ['email'], credentialFields: [{ key: 'apiKey', required: true, configured: false }] },
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

    it('requires the Hunter key for direct domain searches', () => {
        assert.deepEqual(makeProviderSearchPlan(['example.test'], providers, 'domain'), []);
        const configured = providers.map((provider) => provider.id === 'hunter'
            ? { ...provider, credentialFields: [{ key: 'apiKey', required: true, configured: true }] }
            : provider);
        assert.deepEqual(makeProviderSearchPlan(['example.test'], configured, 'domain').map(({ provider }) => provider.id), ['hunter']);
    });

    it('includes every compatible provider when all required keys are configured', () => {
        const configured = providers.map((provider) => ({
            ...provider,
            credentialFields: provider.credentialFields?.map((field) => ({ ...field, configured: true })),
        }));
        assert.deepEqual(makeProviderSearchPlan(['one@example.test'], configured, 'email').map(({ provider }) => provider.id), ['hibp', 'intelx', 'snusbase', 'hunter']);
    });

    it('keeps free email lookup active when all provider keys are absent', () => {
        const unconfigured = providers.map((provider) => ({
            ...provider,
            credentialFields: provider.credentialFields?.map((field) => ({ ...field, configured: false })),
        }));
        assert.deepEqual(makeProviderSearchPlan(['one@example.test'], unconfigured, 'email').map(({ provider }) => provider.id), ['hunter']);
        assert.equal(providerSearchAvailability(unconfigured[4]!, 'email').status, 'unsupported_query');
    });

    it('explains why each excluded provider was not queried', () => {
        assert.equal(providerSearchAvailability(providers[2]!, 'email').status, 'missing_key');
        assert.equal(providerSearchAvailability(providers[4]!, 'email').status, 'unsupported_query');
        assert.equal(providerSearchAvailability(providers[5]!, 'email').status, 'unavailable');
        const access = providerSearchAvailability({
            id: 'emailrep', name: 'EmailRep', available: true, queryTypes: ['email'],
            credentialFields: [{ key: 'apiKey', required: true, configured: false, environmentVariable: 'EMAILREP_API_KEY' }],
            accessDescription: 'Anonymous access is disabled.',
        }, 'email');
        assert.equal(access.status, 'missing_key');
        assert.match(access.message, /EMAILREP_API_KEY/);
        assert.match(access.message, /Anonymous access is disabled/);
    });

    it('requires all mandatory credentials while preserving an explicit free mode', () => {
        const multiCredentialProvider = {
            id: 'multi', name: 'Multi', available: true, queryTypes: ['email', 'domain'], freeQueryTypes: ['email'],
            credentialFields: [{ key: 'apiKey', required: true, configured: true }, { key: 'account', required: true, configured: false }],
        };
        assert.equal(providerSearchAvailability(multiCredentialProvider, 'domain').status, 'missing_key');
        assert.equal(providerSearchAvailability(multiCredentialProvider, 'email').status, 'ready');
    });
});

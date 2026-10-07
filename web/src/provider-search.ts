export interface SearchProvider {
    id: string;
    name: string;
    available: boolean;
    queryTypes: string[];
    freeQueryTypes?: string[];
    credentialFields?: { key: string; required?: boolean; configured?: boolean; environmentVariable?: string }[];
    accessDescription?: string;
    unavailableReason?: string;
}

export interface ProviderSearchJob {
    target: string;
    provider: SearchProvider;
}

export interface ProviderSearchAvailability {
    status: 'ready' | 'missing_key' | 'unsupported_query' | 'unavailable';
    message: string;
}

/** Use the same access rules for scheduling and explaining search coverage. */
export function providerSearchAvailability(provider: SearchProvider, query: string): ProviderSearchAvailability {
    if (!provider.available) return { status: 'unavailable', message: provider.unavailableReason || 'This provider has no supported hosted API.' };
    if (!provider.queryTypes.includes(query)) return { status: 'unsupported_query', message: `Does not support this query. Supported types: ${provider.queryTypes.join(', ')}.` };
    if (provider.freeQueryTypes?.includes(query)) return { status: 'ready', message: 'The free mode is included automatically; no key is needed.' };
    const missing = (provider.credentialFields ?? []).filter((field) => field.required && field.configured !== true);
    if (missing.length) {
        const variables = missing.map((field) => field.environmentVariable || field.key).join(', ');
        return { status: 'missing_key', message: `Not queried: ${variables} is not configured. ${provider.accessDescription || 'This API requires a provider credential.'}` };
    }
    return { status: 'ready', message: 'Included automatically with the configured provider credentials.' };
}

export function canRunProviderSearch(provider: SearchProvider, query: string): boolean {
    return providerSearchAvailability(provider, query).status === 'ready';
}

/** Plan all configured providers and key-free query modes that support the request. */
export function makeProviderSearchPlan(
    targets: readonly string[],
    providers: readonly SearchProvider[],
    query: string,
): ProviderSearchJob[] {
    const compatible = providers.filter((provider) => canRunProviderSearch(provider, query));
    return targets.flatMap((target) => compatible.map((provider) => ({ target, provider })));
}

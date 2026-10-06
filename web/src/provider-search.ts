export interface SearchProvider {
    id: string;
    name: string;
    available: boolean;
    queryTypes: string[];
    freeQueryTypes?: string[];
    credentialFields?: { key: string; required?: boolean; configured?: boolean }[];
}

export interface ProviderSearchJob {
    target: string;
    provider: SearchProvider;
}

export function canRunProviderSearch(provider: SearchProvider, query: string): boolean {
    if (!provider.available || !provider.queryTypes.includes(query)) return false;
    const apiKey = provider.credentialFields?.find((field) => field.key === 'apiKey');
    return !apiKey || !apiKey.required || apiKey.configured === true || provider.freeQueryTypes?.includes(query) === true;
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

export interface SearchProvider {
    id: string;
    name: string;
    available: boolean;
    queryTypes: string[];
}

export interface ProviderSearchJob {
    target: string;
    provider: SearchProvider;
}

/** Plan one lookup for every hosted provider that supports the requested query. */
export function makeProviderSearchPlan(
    targets: readonly string[],
    providers: readonly SearchProvider[],
    query: string,
): ProviderSearchJob[] {
    const compatible = providers.filter((provider) => provider.available && provider.queryTypes.includes(query));
    return targets.flatMap((target) => compatible.map((provider) => ({ target, provider })));
}

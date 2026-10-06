import './styles.css';
import { mountEngine } from './engine';
import { lookupIntelX } from './intelx';
import { appendChaseTargets, extractEmails, isEmailAddress, MAX_TARGETS, parseEmailTargets, toCsv, visibleValue, type ExportRecord, type RecordEntry } from './domain';
import { canRunProviderSearch, makeProviderSearchPlan, type ProviderSearchJob, type SearchProvider } from './provider-search';

type ClientErrorEvent =
    | { type: 'uncaught_exception' | 'unhandled_rejection'; route: 'app' | 'local' }
    | { type: 'provider_lookup_error'; route: 'app'; provider: string };

function reportClientError(event: ClientErrorEvent): void {
    const body = new Blob([JSON.stringify(event)], { type: 'application/json' });
    try {
        if (navigator.sendBeacon('/api/client-error', body)) return;
    } catch {
        // Fall through to fetch; the reporter must not interrupt the user action.
    }
    void fetch('/api/client-error', { method: 'POST', body, keepalive: true, credentials: 'omit', cache: 'no-store' })
        .catch(() => undefined);
}

window.addEventListener('error', () => reportClientError({ type: 'uncaught_exception', route: 'app' }));
window.addEventListener('unhandledrejection', () => reportClientError({ type: 'unhandled_rejection', route: 'app' }));

type QueryType = 'email' | 'username' | 'domain' | 'ip' | 'hash' | 'password' | 'selector';
type Mode = 'online' | 'local' | 'extract' | 'engine';
interface CredentialField { key: string; label: string; type: 'password' | 'text'; required?: boolean; environmentVariable?: string; configured?: boolean; default?: string; options?: string[] }
interface Provider extends SearchProvider { credentialFields: CredentialField[]; description: string; accessDescription?: string; unavailableReason?: string; apiDocumentationUrl?: string }
interface Health { version: string; remoteEnabled: boolean; providers: Provider[]; localCompanion?: boolean; localAccessToken?: string; capabilities?: { maxTargets?: number; maxConcurrent?: number; urlExtraction?: boolean } }
interface SearchResult { target: string; query?: QueryType; provider: string; status: 'found' | 'not_found' | 'error'; records: RecordEntry[]; count?: number; page?: number; total?: number; hasMore?: boolean; error?: { code: string; message: string }; notice?: string; truncated?: boolean; warnings?: { message: string }[] }
interface LocalResponse { type: 'progress' | 'complete' | 'error'; id: number; records?: { target: string; source: string; field: string; value: string }[]; filesProcessed?: number; totalFiles?: number; bytesRead?: number; matches?: number; truncated?: boolean; warnings?: string[]; message?: string }

function element<T extends HTMLElement>(id: string): T {
    const found = document.getElementById(id);
    if (!found) throw new Error(`Missing interface element: ${id}`);
    return found as T;
}
const onlineTargets = element<HTMLTextAreaElement>('online-targets');
const localTargets = element<HTMLTextAreaElement>('local-targets');
const querySelect = element<HTMLSelectElement>('query-type');
const showSensitive = element<HTMLInputElement>('show-sensitive');
const resultContent = element('result-content');
const queryTypes: QueryType[] = ['email', 'username', 'domain', 'ip', 'hash', 'password', 'selector'];
const queryLabels: Record<QueryType, string> = { email: 'Email', username: 'Username', domain: 'Domain', ip: 'IP address', hash: 'Hash', password: 'Password', selector: 'Identifier' };
let health: Health | null = null;
let activeMode: Mode = 'online';
let localAccessToken = '';
let selectedFiles: File[] = [];
let extracted: string[] = [];
let results: SearchResult[] = [];
let runWarnings: string[] = [];
let running = false;
let engineBusy = false;
let runId = 0;
let controller: AbortController | null = null;
let localWorker: Worker | null = null;
let fileReadGeneration = 0;
const engine = mountEngine({ getAccessKey: () => localAccessToken, isBusy: () => running, onBusy: (busy) => { engineBusy = busy; running = busy; updateControls(); }, download });
mountExtendedInputs();

function setMessage(id: string, message: string, tone: 'normal' | 'error' | 'success' = 'normal'): void {
    const node = element(id);
    node.textContent = message;
    node.className = `form-message ${tone === 'normal' ? '' : tone}`;
}

function setMode(mode: Mode, focus = false): void {
    activeMode = mode;
    for (const tab of document.querySelectorAll<HTMLButtonElement>('.tab')) {
        const selected = tab.dataset.mode === mode;
        tab.classList.toggle('active', selected);
        tab.setAttribute('aria-selected', String(selected));
        tab.tabIndex = selected ? 0 : -1;
        if (selected && focus) tab.focus();
    }
    for (const panel of document.querySelectorAll<HTMLElement>('.mode-panel')) panel.hidden = panel.id !== `panel-${mode}`;
}

function updateTargetCount(): void {
    const count = querySelect.value === 'email' ? parseEmailTargets(onlineTargets.value).length : Number(Boolean(onlineTargets.value.trim()));
    element('target-count').textContent = `${count} / ${querySelect.value === 'email' ? MAX_TARGETS : 1}`;
}

function providersForQuery(query = querySelect.value): Provider[] {
    return (health?.providers ?? []).filter((provider) => provider.available && provider.queryTypes.includes(query as QueryType));
}

function runnableProvidersForQuery(query = querySelect.value): Provider[] {
    return providersForQuery(query).filter((provider) => canRunProviderSearch(provider, query));
}

function hasConfiguredApiKey(provider: Provider): boolean {
    return provider.credentialFields.some((field) => field.key === 'apiKey' && field.configured);
}

function renderProviderSummary(): void {
    const compatible = providersForQuery();
    const runnable = compatible.filter((provider) => canRunProviderSearch(provider, querySelect.value));
    const free = runnable.filter((provider) => !hasConfiguredApiKey(provider));
    const missingKeys = compatible.length - runnable.length;
    const names = runnable.map((provider) => provider.name).join(', ');
    const emailFreeMode = querySelect.value === 'email' && free.some((provider) => provider.id === 'hunter');
    element('provider-description').textContent = compatible.length
        ? emailFreeMode
            ? 'Without Vercel keys, email lookup uses Hunter Email Insight for deliverability signals. It does not search breach records.'
            : runnable.length
                ? `${runnable.length} source${runnable.length === 1 ? '' : 's'} can run for ${queryLabels[querySelect.value as QueryType] ?? 'this query'}; key-required sources are skipped automatically.`
                : 'No key-free source is available for this query. Local file and text tools still work without deployment keys.'
        : 'No hosted provider supports this query type.';
    element('provider-summary').textContent = runnable.length
        ? `${names}${free.length ? ` · ${free.length} free without key` : ' · configured'}${missingKeys ? ` · ${missingKeys} key-required source${missingKeys === 1 ? '' : 's'} skipped` : ''}`
        : compatible.length ? `${missingKeys} provider${missingKeys === 1 ? '' : 's'} require${missingKeys === 1 ? 's' : ''} an API key.`
        : 'Choose another query type or use the original local engine.';
}

function renderProviderGuide(): void {
    const list = element('provider-guide-list');
    list.replaceChildren();
    if (!health) {
        list.textContent = 'Reconnect to load provider setup information.';
        return;
    }
    for (const provider of health.providers) {
        const entry = document.createElement('article');
        entry.className = 'provider-guide-entry';
        const summary = document.createElement('div');
        const state = document.createElement('span');
        const apiKeyField = provider.credentialFields.find((field) => field.key === 'apiKey');
        const keyConfigured = hasConfiguredApiKey(provider);
        const freeWithoutKey = Boolean(provider.freeQueryTypes?.length && !apiKeyField?.required);
        const stateLabel = !provider.available ? 'WEB UNAVAILABLE'
            : keyConfigured ? 'KEY CONFIGURED'
                : freeWithoutKey ? 'FREE · NO KEY REQUIRED'
                    : provider.freeQueryTypes?.length ? 'KEY NOT SET · FREE MODE ACTIVE'
                        : apiKeyField?.required ? 'KEY NOT CONFIGURED' : 'NO KEY REQUIRED';
        const heading = document.createElement('div');
        heading.className = 'provider-guide-heading';
        const dot = document.createElement('span');
        dot.className = `provider-status-dot${!provider.available ? ' unavailable' : keyConfigured || freeWithoutKey || !apiKeyField?.required ? ' configured' : ' missing'}`;
        dot.setAttribute('aria-hidden', 'true');
        const name = document.createElement('a');
        name.className = 'provider-guide-name';
        name.textContent = provider.name;
        if (provider.apiDocumentationUrl) {
            name.href = provider.apiDocumentationUrl;
            name.target = '_blank';
            name.rel = 'noopener noreferrer';
            name.setAttribute('aria-label', `${provider.name} API documentation, opens in a new tab`);
        }
        state.className = `provider-guide-state${!provider.available ? ' unavailable' : keyConfigured || freeWithoutKey || !apiKeyField?.required ? '' : ' missing'}`;
        state.textContent = stateLabel;
        heading.append(dot, name, state);
        const description = document.createElement('p');
        description.textContent = provider.available ? (provider.accessDescription || provider.description) : provider.unavailableReason || 'Unavailable in the hosted adapter.';
        summary.append(heading, description);
        const keys = document.createElement('div');
        keys.className = 'provider-guide-keys';
        for (const field of provider.credentialFields) {
            if (!field.environmentVariable) continue;
            const row = document.createElement('div');
            row.className = 'provider-guide-key';
            const variable = document.createElement('code');
            variable.textContent = field.environmentVariable;
            const copy = document.createElement('button');
            copy.type = 'button';
            copy.className = 'provider-copy-button';
            copy.textContent = 'Copy name';
            copy.setAttribute('aria-label', `Copy Vercel variable name ${field.environmentVariable}`);
            copy.addEventListener('click', () => { void copyEnvironmentVariable(field.environmentVariable ?? ''); });
            row.append(variable, copy);
            keys.append(row);
        }
        if (!provider.credentialFields.length) {
            const note = document.createElement('span');
            note.className = 'provider-guide-empty';
            note.textContent = provider.available ? 'No key required for this source.' : 'No hosted key is supported.';
            keys.append(note);
        }
        entry.append(summary, keys);
        list.append(entry);
    }
}

async function copyEnvironmentVariable(variable: string): Promise<void> {
    try {
        await navigator.clipboard.writeText(variable);
        setMessage('provider-guide-status', `${variable} copied. Add it as a Vercel environment variable name.`, 'success');
    } catch {
        setMessage('provider-guide-status', `Clipboard access failed. Copy the variable name manually: ${variable}`, 'error');
    }
}

function updateQuery(): void {
    const query = querySelect.value as QueryType;
    querySelect.dataset.current = query;
    element('target-label').textContent = query === 'email' ? 'Email addresses' : queryLabels[query] ?? 'Target';
    element('target-hint').textContent = query === 'email' ? 'Separate email addresses with a new line, comma, or space.' : 'Custom queries use one target per lookup. Provider support varies.';
    onlineTargets.placeholder = query === 'email' ? 'name@example.com\nOne address per line, up to 10.' : `Enter one ${queryLabels[query]?.toLowerCase() ?? 'target'}`;
    updateTargetCount();
    renderProviderSummary();
}

function updateControls(): void {
    element<HTMLButtonElement>('online-submit').disabled = running || !health?.remoteEnabled || !runnableProvidersForQuery().length;
    element<HTMLButtonElement>('local-submit').disabled = running;
    element<HTMLButtonElement>('extract-submit').disabled = running;
    querySelect.disabled = running || !health;
    for (const button of document.querySelectorAll<HTMLButtonElement>('.cancel-button')) button.hidden = !running;
    for (const button of document.querySelectorAll<HTMLButtonElement>('.pagination-button')) button.disabled = running;
    showSensitive.disabled = running;
    const extractUrlsButton = document.getElementById('extract-urls-button') as HTMLButtonElement | null;
    if (extractUrlsButton) extractUrlsButton.disabled = running || !health?.remoteEnabled || !health.capabilities?.urlExtraction;
    const chase = document.getElementById('chase-enabled') as HTMLInputElement | null;
    if (chase) chase.disabled = running || querySelect.value !== 'email';
}

function isObject(value: unknown): value is Record<string, unknown> { return Boolean(value) && typeof value === 'object' && !Array.isArray(value); }
function parseHealth(value: unknown): Health {
    if (!isObject(value) || typeof value.version !== 'string' || typeof value.remoteEnabled !== 'boolean' || !Array.isArray(value.providers)) throw new Error('The server returned invalid provider metadata.');
    const providers = value.providers.map((entry: unknown): Provider => {
        if (!isObject(entry) || typeof entry.id !== 'string' || typeof entry.name !== 'string' || typeof entry.description !== 'string' || !Array.isArray(entry.queryTypes) || !Array.isArray(entry.credentialFields)) throw new Error('The server returned invalid provider metadata.');
        const supportedQueries = entry.queryTypes.filter((query: unknown): query is QueryType => typeof query === 'string' && queryTypes.includes(query as QueryType));
        const fields = entry.credentialFields.map((field: unknown): CredentialField => {
            if (!isObject(field) || typeof field.key !== 'string' || typeof field.label !== 'string' || (field.type !== 'password' && field.type !== 'text')) throw new Error('The server returned invalid credential fields.');
            if (field.environmentVariable !== undefined && (typeof field.environmentVariable !== 'string' || !/^[A-Z][A-Z0-9_]*$/.test(field.environmentVariable))) throw new Error('The server returned invalid provider setup metadata.');
            const options = Array.isArray(field.options) ? field.options.filter((option: unknown): option is string => typeof option === 'string') : undefined;
            return { key: field.key, label: field.label, type: field.type, required: field.required === true, environmentVariable: typeof field.environmentVariable === 'string' ? field.environmentVariable : undefined, configured: field.configured === true, default: typeof field.default === 'string' ? field.default : undefined, options };
        });
        const freeQueryTypes = Array.isArray(entry.freeQueryTypes) ? entry.freeQueryTypes.filter((query: unknown): query is QueryType => typeof query === 'string' && supportedQueries.includes(query as QueryType)) : [];
        let apiDocumentationUrl: string | undefined;
        if (typeof entry.apiDocumentationUrl === 'string') {
            try {
                const url = new URL(entry.apiDocumentationUrl);
                if (url.protocol === 'https:' && !url.username && !url.password) apiDocumentationUrl = url.toString();
            } catch { /* Invalid provider links are omitted. */ }
        }
        return { id: entry.id, name: entry.name, description: entry.description, accessDescription: typeof entry.accessDescription === 'string' ? entry.accessDescription : undefined, available: entry.available !== false, queryTypes: supportedQueries, freeQueryTypes, apiDocumentationUrl, credentialFields: fields, unavailableReason: typeof entry.unavailableReason === 'string' ? entry.unavailableReason : undefined };
    });
    return { version: value.version, remoteEnabled: value.remoteEnabled, providers, localCompanion: value.localCompanion === true, localAccessToken: typeof value.localAccessToken === 'string' ? value.localAccessToken : undefined, capabilities: isObject(value.capabilities) ? { urlExtraction: value.capabilities.urlExtraction === true } : undefined };
}

async function loadHealth(): Promise<void> {
    element('service-status').textContent = 'Connecting';
    const healthController = new AbortController();
    const timer = window.setTimeout(() => healthController.abort(), 15000);
    try {
        const response = await fetch('/api/health', { signal: healthController.signal, cache: 'no-store', credentials: 'omit' });
        if (!response.ok) throw new Error('The deployment could not load provider information.');
        health = parseHealth(await response.json());
        engine.configure(Boolean(health.localCompanion));
        localAccessToken = health.localCompanion ? health.localAccessToken ?? '' : '';
        element('engine-version').textContent = `ENGINE ${health.version} / WEB`;
        element('service-status').textContent = health.remoteEnabled ? 'Search API online' : 'Local tools ready';
        element('service-status').className = `service-status ${health.remoteEnabled ? 'ready' : 'offline'}`;
        const previousQuery = querySelect.dataset.current ?? querySelect.value ?? 'email';
        const supportedQueries = queryTypes.filter((query) => health?.providers.some((provider) => provider.available && provider.queryTypes.includes(query)));
        querySelect.replaceChildren();
        for (const query of supportedQueries) {
            const option = document.createElement('option');
            option.value = query;
            option.textContent = queryLabels[query];
            querySelect.append(option);
        }
        querySelect.value = supportedQueries.includes(previousQuery as QueryType) ? previousQuery : supportedQueries[0] ?? 'email';
        element('remote-notice').hidden = true;
        element('retry-connection').hidden = true;
        renderProviderGuide();
        updateQuery();
    } catch (error: unknown) {
        health = null;
        element('service-status').textContent = 'Server unavailable';
        element('service-status').className = 'service-status offline';
        element('remote-notice').hidden = false;
        element('remote-notice').textContent = error instanceof Error && error.name !== 'AbortError' ? error.message : 'The server connection timed out. Local tools remain available.';
        element('retry-connection').hidden = false;
        element('provider-description').textContent = 'Reconnect to load provider status. Local files and pasted-text extraction remain available.';
    } finally {
        window.clearTimeout(timer);
        updateControls();
    }
}

function parseSearchResult(value: unknown, target: string, provider: string): SearchResult {
    if (!isObject(value) || !['found', 'not_found', 'error'].includes(String(value.status)) || !Array.isArray(value.records)) throw new Error('The provider returned a malformed result.');
    const records = value.records.map((record: unknown): RecordEntry => {
        if (!isObject(record) || typeof record.source !== 'string' || typeof record.field !== 'string' || typeof record.value !== 'string') throw new Error('The provider returned malformed records.');
        return { source: record.source, field: record.field, value: record.value };
    });
    const error = isObject(value.error) && typeof value.error.code === 'string' && typeof value.error.message === 'string' ? { code: value.error.code, message: value.error.message } : undefined;
    const warnings = Array.isArray(value.warnings) ? value.warnings.filter((warning: unknown): warning is { message: string } => isObject(warning) && typeof warning.message === 'string').map((warning) => ({ message: warning.message })) : [];
    return { target, provider, query: typeof value.query === 'string' && queryTypes.includes(value.query as QueryType) ? value.query as QueryType : undefined, status: value.status as SearchResult['status'], records, count: typeof value.count === 'number' ? value.count : records.length, page: typeof value.page === 'number' ? value.page : 1, total: typeof value.total === 'number' ? value.total : undefined, hasMore: value.hasMore === true, error, notice: typeof value.notice === 'string' ? value.notice : undefined, truncated: value.truncated === true, warnings };
}

function errorMessage(payload: unknown, fallback: string): string {
    return isObject(payload) && isObject(payload.error) && typeof payload.error.message === 'string' ? payload.error.message : fallback;
}

function beginRun(): number {
    cancelRun(false);
    running = true;
    results = [];
    runWarnings = [];
    showSensitive.checked = false;
    controller = new AbortController();
    const id = ++runId;
    updateControls();
    element('export-controls').hidden = true;
    element('results-title').textContent = 'Investigation in progress.';
    resultContent.replaceChildren();
    const progress = document.createElement('div');
    progress.className = 'run-progress';
    const spinner = document.createElement('span');
    spinner.className = 'spinner';
    spinner.setAttribute('aria-hidden', 'true');
    const text = document.createElement('span');
    text.id = 'run-progress-text';
    text.textContent = 'Preparing search…';
    progress.append(spinner, text);
    resultContent.append(progress);
    return id;
}

function finishRun(id: number): void {
    if (id !== runId) return;
    running = false;
    controller = null;
    localWorker?.terminate();
    localWorker = null;
    updateControls();
    renderResults();
}

function cancelRun(announce = true): void {
    if (engineBusy) { void engine.cancel(); return; }
    if (!running) return;
    runId += 1;
    controller?.abort();
    controller = null;
    localWorker?.terminate();
    localWorker = null;
    running = false;
    runWarnings.push('Search cancelled. Completed results are retained; unsearched targets are not marked as no matches.');
    updateControls();
    if (announce) {
        renderResults();
        setMessage(activeMode === 'local' ? 'local-message' : activeMode === 'extract' ? 'extract-message' : 'online-message', 'Search cancelled. Completed results are retained.');
    }
}

function validateTargets(text: string, query: QueryType): string[] {
    const targets = query === 'email' ? parseEmailTargets(text) : [text.trim()].filter(Boolean);
    if (!targets.length) throw new Error('Enter a target to search.');
    if (targets.length > MAX_TARGETS) throw new Error(`Use at most ${MAX_TARGETS} email addresses per lookup.`);
    if (query === 'email' && targets.some((target) => !isEmailAddress(target))) throw new Error('Enter complete email addresses, such as name@example.com.');
    const first = targets[0];
    if (query !== 'email' && first && (first.length > 1024 || /[\r\n]/.test(first))) throw new Error('Enter a single target of at most 1,024 characters.');
    return targets;
}

async function runOnline(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    if (running) return;
    if (!health?.remoteEnabled) return;
    let targets: string[];
    const query = querySelect.value as QueryType;
    const compatible = providersForQuery(query);
    const runnable = runnableProvidersForQuery(query);
    try {
        targets = validateTargets(onlineTargets.value, query);
        if (!compatible.length) throw new Error('No hosted provider supports this query type.');
        if (!runnable.length) throw new Error('No key-free source supports this lookup. Configure an API key to use these providers, or use local tools.');
    } catch (error: unknown) {
        setMessage('online-message', error instanceof Error ? error.message : 'Check the search input.', 'error');
        return;
    }
    const chaseEnabled = query === 'email' && element<HTMLInputElement>('chase-enabled').checked;
    const powerChase = element<HTMLInputElement>('power-chase').checked;
    const chaseLimit = Math.min(25, Math.max(targets.length, Number(element<HTMLInputElement>('chase-limit').value) || 10));
    const seen = new Set(targets);
    const id = beginRun();
    const signal = controller?.signal;
    setMessage('online-message', `Searching ${targets.length} target${targets.length === 1 ? '' : 's'} with ${runnable.length} available source${runnable.length === 1 ? '' : 's'}…`);
    let nextIndex = 0;
    let completed = 0;
    const ordered: (SearchResult | undefined)[] = [];
    const queue: Array<ProviderSearchJob & { resultIndex: number }> = [];
    const enqueue = (jobs: readonly ProviderSearchJob[]): void => {
        for (const job of jobs) {
            queue.push({ ...job, resultIndex: ordered.length });
            ordered.push(undefined);
        }
    };
    enqueue(makeProviderSearchPlan(targets, runnable, query));
    const searchNext = async (): Promise<void> => {
        while (id === runId && nextIndex < queue.length) {
            const job = queue[nextIndex++];
            if (!job) return;
            let result: SearchResult;
            try {
                if (job.provider.id === 'intelx' && signal) {
                    const fileLimit = Number(element<HTMLInputElement>('intelx-file-limit').value);
                    result = { ...await lookupIntelX(job.target, query, signal, Math.min(25, Math.max(1, Number.isInteger(fileLimit) ? fileLimit : 10))), query };
                } else {
                    const response = await fetch('/api/search', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ target: job.target, query, provider: job.provider.id, hidePasswords: true, page: 1 }), signal, credentials: 'omit', cache: 'no-store' });
                    const payload: unknown = await response.json();
                    if (!response.ok) throw new Error(errorMessage(payload, `Lookup failed (HTTP ${response.status}).`));
                    result = parseSearchResult(payload, job.target, job.provider.name);
                }
            } catch (error: unknown) {
                if (id !== runId || signal?.aborted) return;
                if (error instanceof TypeError) {
                    reportClientError({ type: 'provider_lookup_error', route: 'app', provider: job.provider.id });
                }
                result = { target: job.target, query, provider: job.provider.name, status: 'error', records: [], error: { code: 'REQUEST_FAILED', message: error instanceof Error ? error.message : 'The server could not complete this lookup.' } };
            }
            if (id !== runId) return;
            ordered[job.resultIndex] = result;
            if (chaseEnabled && result.status === 'found' && (powerChase || job.provider.id === 'hunter')) {
                const previousTargetCount = targets.length;
                const truncated = appendChaseTargets(targets, seen, result.records, chaseLimit, powerChase);
                if (targets.length > previousTargetCount) {
                    const discovered = targets.slice(previousTargetCount);
                    enqueue(makeProviderSearchPlan(discovered, runnable, query));
                }
                if (truncated && !runWarnings.includes('Chase stopped at the configured target limit. Some related addresses were not queried.')) runWarnings.push('Chase stopped at the configured target limit. Some related addresses were not queried.');
            }
            completed += 1;
            results = ordered.filter((entry): entry is SearchResult => Boolean(entry));
            const progress = document.getElementById('run-progress-text');
            if (progress) progress.textContent = `${completed} / ${queue.length} provider lookups completed${chaseEnabled ? ' · bounded chase enabled' : ''}.`;
            element('results-announcement').textContent = `${completed} of ${queue.length} provider lookups completed.`;
        }
    };
    await Promise.all(Array.from({ length: Math.min(3, queue.length) }, () => searchNext()));
    if (id === runId) {
        const errors = results.filter((result) => result.status === 'error').length;
        setMessage('online-message', `${completed} provider lookups completed${errors ? `; ${errors} failed. See each provider's result below.` : '.'}`, errors ? 'error' : 'success');
        finishRun(id);
    }
}

function selectFiles(files: File[]): void {
    if (running) return;
    if (files.length > 200) {
        setMessage('local-message', 'Choose at most 200 files. Use the CLI for larger datasets.', 'error');
        return;
    }
    selectedFiles = files;
    const bytes = files.reduce((total, file) => total + file.size, 0);
    element('file-summary').textContent = files.length ? `${files.length} file${files.length === 1 ? '' : 's'} selected · ${formatBytes(bytes)} on disk. Nothing uploaded.` : 'No files selected.';
    setMessage('local-message', '');
}

function formatBytes(bytes: number): string { return bytes >= 1024 * 1024 ? `${(bytes / (1024 * 1024)).toFixed(1)} MB` : `${Math.ceil(bytes / 1024)} KB`; }

function runLocal(event: SubmitEvent): void {
    event.preventDefault();
    if (running) return;
    let targets: string[];
    const loose = element<HTMLInputElement>('local-loose').checked;
    try {
        targets = loose ? [...new Set(localTargets.value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean))] : validateTargets(localTargets.value, 'email');
        if (!targets.length || targets.length > MAX_TARGETS || targets.some((target) => target.length > 254)) throw new Error('Enter between 1 and 10 targets, at most 254 characters each.');
        if (!selectedFiles.length) throw new Error('Choose at least one local file.');
    } catch (error: unknown) {
        setMessage('local-message', error instanceof Error ? error.message : 'Check the local search input.', 'error');
        return;
    }
    const id = beginRun();
    setMessage('local-message', 'Searching in this browser. Files are not uploaded.');
    try {
        localWorker = new Worker(new URL('./local.worker.ts', import.meta.url), { type: 'module' });
        localWorker.onerror = () => {
            if (id !== runId) return;
            runWarnings.push('Local processing failed. No complete search result is available.');
            setMessage('local-message', 'The browser could not process these files. Use readable text files or the original CLI.', 'error');
            finishRun(id);
        };
        localWorker.onmessage = (event: MessageEvent<LocalResponse>) => {
            const message = event.data;
            if (id !== runId || message.id !== id) return;
            if (message.type === 'progress') {
                const text = `${message.filesProcessed ?? 0} / ${selectedFiles.length} files · ${formatBytes(message.bytesRead ?? 0)} read · ${message.matches ?? 0} matches`;
                const progress = document.getElementById('run-progress-text');
                if (progress) progress.textContent = text;
                setMessage('local-message', text);
            } else if (message.type === 'error') {
                runWarnings.push(message.message ?? 'Local search failed.');
                setMessage('local-message', message.message ?? 'Local search failed.', 'error');
                finishRun(id);
            } else {
                runWarnings = message.warnings ?? [];
                results = targets.map((target) => {
                    const records = (message.records ?? []).filter((record) => record.target === target).map(({ source, field, value }) => ({ source, field, value }));
                    const incomplete = Boolean(message.truncated || runWarnings.length);
                    return { target, provider: 'Local files', status: records.length ? 'found' : incomplete ? 'error' : 'not_found', records, error: !records.length && incomplete ? { code: 'INCOMPLETE_SEARCH', message: 'No match in the processed portion. This search was incomplete; review the warnings.' } : undefined };
                });
                setMessage('local-message', `Searched ${message.filesProcessed ?? 0} files. ${message.records?.length ?? 0} matches${message.truncated ? ' · limit reached' : ''}.`, runWarnings.length ? 'normal' : 'success');
                finishRun(id);
            }
        };
        localWorker.postMessage({ type: 'search', id, files: selectedFiles, targets, loose });
    } catch {
        runWarnings.push('The browser could not start the local processing worker.');
        setMessage('local-message', 'Local processing is unavailable in this browser. Use the original CLI.', 'error');
        finishRun(id);
    }
}

async function loadNextPage(index: number, expected: SearchResult, button: HTMLButtonElement): Promise<void> {
    if (running || results[index] !== expected || !expected.hasMore) return;
    const provider = health?.providers.find((entry) => entry.name === expected.provider);
    if (!provider || !expected.query) {
        expected.warnings = [{ message: 'Provider setup information is unavailable. Reconnect before loading another page.' }, ...(expected.warnings ?? [])];
        renderResults();
        return;
    }
    const id = ++runId;
    running = true;
    controller = new AbortController();
    updateControls();
    button.textContent = 'Loading…';
    setMessage('online-message', `Loading page ${(expected.page ?? 1) + 1} from ${expected.provider}…`);
    try {
        const response = await fetch('/api/search', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target: expected.target, query: expected.query, provider: provider.id,
                hidePasswords: true, page: (expected.page ?? 1) + 1 }),
            signal: controller.signal, credentials: 'omit', cache: 'no-store',
        });
        const payload: unknown = await response.json();
        if (!response.ok) throw new Error(errorMessage(payload, `Lookup failed (HTTP ${response.status}).`));
        const next = parseSearchResult(payload, expected.target, provider.name);
        if (next.status === 'error') throw new Error(next.error?.message ?? 'The provider could not return this page.');
        if (id !== runId || results[index] !== expected) return;
        results[index] = {
            ...next,
            records: [...expected.records, ...next.records],
            count: next.count,
            warnings: next.warnings,
        };
        setMessage('online-message', `Loaded page ${next.page ?? 1} from ${provider.name}.`, 'success');
    } catch (error: unknown) {
        if (id !== runId || controller?.signal.aborted || results[index] !== expected) return;
        expected.warnings = [{ message: error instanceof Error ? `Could not load the next page: ${error.message}` : 'Could not load the next page.' }, ...(expected.warnings ?? [])];
        setMessage('online-message', 'The next page could not be loaded. Your existing results remain available.', 'error');
    } finally {
        if (id === runId) {
            running = false;
            controller = null;
            updateControls();
            renderResults();
        }
    }
}

function renderResults(): void {
    resultContent.replaceChildren();
    const recordCount = results.reduce((total, result) => total + result.records.length, 0);
    const targetCount = new Set(results.map((result) => result.target)).size;
    const errors = results.filter((result) => result.status === 'error').length;
    element('results-title').textContent = results.length
        ? `${recordCount} record${recordCount === 1 ? '' : 's'} / ${targetCount} target${targetCount === 1 ? '' : 's'} / ${results.length} provider lookup${results.length === 1 ? '' : 's'}`
        : runWarnings.length ? 'Search stopped.' : 'Your results appear here.';
    element('export-controls').hidden = !recordCount;
    element('results-announcement').textContent = `${recordCount} records across ${targetCount} targets and ${results.length} provider lookups. ${errors} errors.`;
    if (!results.length) {
        const empty = document.createElement('div');
        empty.className = 'empty-state';
        const message = document.createElement('p');
        message.textContent = runWarnings.length ? 'No complete target results are available.' : 'Choose a provider or search a local file to begin.';
        empty.append(message);
        resultContent.append(empty);
    }
    for (const result of results) {
        const group = document.createElement('article');
        group.className = 'result-group';
        const heading = document.createElement('div');
        heading.className = 'result-group-heading';
        const target = document.createElement('h3');
        target.className = 'result-target';
        target.textContent = result.query === 'password' ? '[password query]' : result.target;
        const provider = document.createElement('span');
        provider.className = 'result-provider';
        provider.textContent = result.provider;
        const status = document.createElement('span');
        status.className = `result-status ${result.status}`;
        status.textContent = result.status === 'found' ? `${result.records.length} RECORD${result.records.length === 1 ? '' : 'S'} FOUND` : result.status === 'not_found' ? 'NO MATCHES REPORTED' : 'LOOKUP FAILED';
        heading.append(target, provider, status);
        group.append(heading);
        if (result.notice) {
            const notice = document.createElement('p');
            notice.className = 'run-warning';
            notice.textContent = result.notice;
            group.append(notice);
        }
        if (result.records.length) {
            const wrapper = document.createElement('div');
            wrapper.className = 'table-scroll';
            const table = document.createElement('table');
            table.className = 'results-table';
            const caption = document.createElement('caption');
            caption.className = 'sr-only';
            caption.textContent = `Records from ${result.provider}`;
            const head = document.createElement('thead');
            const headerRow = document.createElement('tr');
            for (const title of ['SOURCE', 'FIELD', 'VALUE']) {
                const cell = document.createElement('th');
                cell.scope = 'col';
                cell.textContent = title;
                headerRow.append(cell);
            }
            head.append(headerRow);
            const body = document.createElement('tbody');
            for (const record of result.records) {
                const row = document.createElement('tr');
                const displayed = visibleValue(record, showSensitive.checked);
                for (const value of [record.source, record.field, displayed]) {
                    const cell = document.createElement('td');
                    cell.textContent = value;
                    if (displayed === '[hidden]' && value === displayed) cell.className = 'masked';
                    row.append(cell);
                }
                body.append(row);
            }
            table.append(caption, head, body);
            wrapper.append(table);
            group.append(wrapper);
        } else {
            const message = document.createElement('p');
            message.className = result.status === 'error' ? 'result-error' : 'result-empty';
            message.textContent = result.error?.message ?? 'The selected source reported no matches. This does not guarantee that the target has never appeared in a breach.';
            group.append(message);
        }
        resultContent.append(group);
        if (result.hasMore) {
            const pagination = document.createElement('div');
            pagination.className = 'pagination-action';
            const nextPage = document.createElement('button');
            nextPage.type = 'button';
            nextPage.className = 'button secondary pagination-button';
            nextPage.textContent = `Load next page${result.total ? ` · ${Math.max(0, result.total - result.records.length)} remaining` : ''}`;
            nextPage.setAttribute('aria-label', `Load the next page of ${result.provider} results for ${result.query === 'password' ? 'password query' : result.target}`);
            nextPage.addEventListener('click', () => { void loadNextPage(results.indexOf(result), result, nextPage); });
            pagination.append(nextPage);
            group.append(pagination);
        } else if (result.truncated) {
            const notice = document.createElement('p');
            notice.className = 'run-warning';
            notice.textContent = 'The provider limited this result. It may not contain every reported record.';
            group.append(notice);
        }
        for (const warning of result.warnings ?? []) {
            const notice = document.createElement('p');
            notice.className = 'run-warning';
            notice.textContent = warning.message;
            group.append(notice);
        }
    }
    for (const warning of runWarnings) {
        const message = document.createElement('p');
        message.className = 'run-warning';
        message.textContent = warning;
        resultContent.append(message);
    }
}

function exportRecords(): ExportRecord[] {
    return results.flatMap((result) => result.records.map((record) => ({ target: result.query === 'password' ? '[password query]' : result.target, provider: result.provider, source: record.source, field: record.field, value: visibleValue(record, showSensitive.checked) })));
}

function download(content: string, filename: string, contentType: string): void {
    const url = URL.createObjectURL(new Blob([content], { type: contentType }));
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.append(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function renderExtraction(emails: string[]): void {
    extracted = [...new Set(emails)].filter(isEmailAddress).slice(0, 1000);
    element('extraction-output').hidden = !extracted.length;
    element('extraction-title').textContent = `${extracted.length} unique address${extracted.length === 1 ? '' : 'es'}`;
    element('extracted-addresses').textContent = extracted.join('\n');
    setMessage('extract-message', extracted.length ? `${extracted.length} unique address${extracted.length === 1 ? '' : 'es'} extracted${extracted.length === 1000 ? ' · 1,000-address limit reached' : ''}.` : 'No complete email addresses found in this text.', extracted.length ? 'success' : 'normal');
}

element<HTMLFormElement>('online-form').addEventListener('submit', (event) => { void runOnline(event); });
element<HTMLFormElement>('local-form').addEventListener('submit', runLocal);
element<HTMLFormElement>('extract-form').addEventListener('submit', (event) => {
    event.preventDefault();
    const text = element<HTMLTextAreaElement>('extract-text').value;
    if (new Blob([text]).size > 2 * 1024 * 1024) { setMessage('extract-message', 'Use at most 2 MB of text.', 'error'); return; }
    renderExtraction(extractEmails(text));
});
for (const tab of document.querySelectorAll<HTMLButtonElement>('.tab')) {
    tab.addEventListener('click', () => setMode(tab.dataset.mode as Mode));
    tab.addEventListener('keydown', (event) => {
        const tabs = [...document.querySelectorAll<HTMLButtonElement>('.tab')];
        const index = tabs.indexOf(tab);
        let next: HTMLButtonElement | undefined;
        if (event.key === 'ArrowRight') next = tabs[(index + 1) % tabs.length];
        if (event.key === 'ArrowLeft') next = tabs[(index - 1 + tabs.length) % tabs.length];
        if (event.key === 'Home') next = tabs[0];
        if (event.key === 'End') next = tabs[tabs.length - 1];
        if (next) { event.preventDefault(); setMode(next.dataset.mode as Mode, true); }
    });
}
querySelect.addEventListener('change', updateQuery);
querySelect.addEventListener('change', updateControls);
onlineTargets.addEventListener('input', updateTargetCount);
element('retry-connection').addEventListener('click', () => { void loadHealth(); });
for (const button of document.querySelectorAll<HTMLButtonElement>('.cancel-button')) button.addEventListener('click', () => cancelRun());
element('online-clear').addEventListener('click', () => {
    cancelRun(false);
    fileReadGeneration += 1;
    engine.clear();
    onlineTargets.value = '';
    localTargets.value = '';
    element<HTMLTextAreaElement>('extract-text').value = '';
    extracted = [];
    selectedFiles = [];
    results = [];
    runWarnings = [];
    showSensitive.checked = false;
    element('extraction-output').hidden = true;
    element<HTMLInputElement>('local-files').value = '';
    element<HTMLInputElement>('local-folder').value = '';
    element('file-summary').textContent = 'No files selected.';
    renderProviderGuide();
    renderResults();
    setMessage('online-message', 'Session cleared. Targets, files, and results were discarded.');
});
element('local-clear').addEventListener('click', () => {
    cancelRun();
    selectedFiles = [];
    element<HTMLInputElement>('local-files').value = '';
    element<HTMLInputElement>('local-folder').value = '';
    element('file-summary').textContent = 'No files selected.';
    setMessage('local-message', 'File selection cleared.');
});
for (const id of ['local-files', 'local-folder']) element<HTMLInputElement>(id).addEventListener('change', (event) => selectFiles(Array.from((event.target as HTMLInputElement).files ?? [])));
if (!('webkitdirectory' in document.createElement('input'))) element('folder-label').hidden = true;
const drop = element('file-drop');
drop.addEventListener('dragover', (event) => { event.preventDefault(); if (!running) drop.classList.add('dragging'); });
drop.addEventListener('dragleave', () => drop.classList.remove('dragging'));
drop.addEventListener('drop', (event) => { event.preventDefault(); drop.classList.remove('dragging'); selectFiles(Array.from(event.dataTransfer?.files ?? [])); });
element<HTMLInputElement>('extract-file').addEventListener('change', async (event) => {
    const input = event.target as HTMLInputElement;
    const file = input.files?.[0];
    if (!file) return;
    const generation = ++fileReadGeneration;
    if (file.size > 2 * 1024 * 1024) { setMessage('extract-message', 'Choose a text file smaller than 2 MB.', 'error'); input.value = ''; return; }
    try {
        const text = await file.text();
        if (generation !== fileReadGeneration) return;
        element<HTMLTextAreaElement>('extract-text').value = text;
        setMessage('extract-message', `Read ${file.name} locally. Select Extract addresses to continue.`);
    }
    catch { setMessage('extract-message', 'This file could not be read. Choose a readable UTF-8 text file.', 'error'); }
    input.value = '';
});
element('extract-clear').addEventListener('click', () => { fileReadGeneration += 1; element<HTMLTextAreaElement>('extract-text').value = ''; element<HTMLTextAreaElement>('extract-urls').value = ''; extracted = []; element('extraction-output').hidden = true; setMessage('extract-message', ''); });
element('use-extracted').addEventListener('click', () => {
    onlineTargets.value = extracted.slice(0, MAX_TARGETS).join('\n');
    if (runnableProvidersForQuery('email').length) { querySelect.value = 'email'; updateQuery(); }
    updateTargetCount();
    setMode('online');
    onlineTargets.focus();
    setMessage('online-message', `${Math.min(extracted.length, MAX_TARGETS)} extracted addresses ready for lookup.`);
});
element('download-extracted').addEventListener('click', () => download(extracted.join('\n'), 'h8mail-addresses.txt', 'text/plain;charset=utf-8'));
showSensitive.addEventListener('change', renderResults);
element('export-json').addEventListener('click', () => download(JSON.stringify(exportRecords(), null, 2), 'h8mail-results.json', 'application/json'));
element('export-csv').addEventListener('click', () => download(toCsv(exportRecords()), 'h8mail-results.csv', 'text/csv;charset=utf-8'));
window.addEventListener('pagehide', () => { cancelRun(false); localAccessToken = ''; });
void loadHealth();

function mountExtendedInputs(): void {
    const privacy = document.querySelector<HTMLElement>('.privacy-line');
    if (privacy) privacy.textContent = '↳ Local files stay on your device.';
    const fileDescription = element('file-drop').querySelector('p');
    if (fileDescription) fileDescription.textContent = 'Text, GZIP, TAR, and TAR.GZ archives.';
    element<HTMLInputElement>('local-files').accept = '.txt,.csv,.log,.gz,.tar,.tgz';
    const browserScope = element('panel-local').querySelector('.limit-note p:last-child');
    if (browserScope) browserScope.textContent = 'Breach Compilation folders and text archives are searched within these bounds. For IntelX, ZIP, and larger datasets, use Full engine.';
    const extractLabel = element('panel-extract').querySelector('.provider-column .section-label .mono');
    if (extractLabel) extractLabel.textContent = 'TEXT STAYS LOCAL';
    const extractScope = element('panel-extract').querySelector('.limit-note p');
    if (extractScope) extractScope.textContent = 'Up to 1,000 unique addresses. Pasted text and files are processed locally. Public HTTPS pages are fetched through the server.';
    const onlineExtras = document.createElement('div');
    onlineExtras.className = 'query-extras';
    onlineExtras.innerHTML = `<label class="text-button file-picker" for="online-target-file">Read targets from a file ↑<input id="online-target-file" type="file" accept=".txt,.csv,.log" /></label><details class="chase-settings"><summary>Follow related targets</summary><div class="chase-fields"><label class="checkbox-label"><input id="chase-enabled" type="checkbox" />Enable bounded chase</label><label class="checkbox-label"><input id="power-chase" type="checkbox" />Use every returned email field (power chase)</label><label class="field-label" for="chase-limit">Maximum total targets, including the initial list</label><input id="chase-limit" type="number" min="1" max="25" value="10" /><p class="field-hint">Hunter related emails by default. Power chase searches addresses returned by any provider. Every discovered address is checked across all compatible providers, up to 25 targets.</p></div></details>`;
    element('target-hint').after(onlineExtras);
    const localExtras = document.createElement('label');
    localExtras.className = 'checkbox-label local-loose';
    const loose = document.createElement('input');
    loose.id = 'local-loose';
    loose.type = 'checkbox';
    const text = document.createElement('span');
    text.textContent = 'Loose search: match literal strings instead of email addresses';
    localExtras.append(loose, text);
    element('local-target-hint').after(localExtras);
    loose.addEventListener('change', () => {
        element('local-target-hint').textContent = loose.checked ? 'Up to 10 literal strings, one per line. Matches ignore case.' : 'Up to 10 email addresses. Searches match complete addresses, ignoring case.';
    });
    const urls = document.createElement('div');
    urls.className = 'url-extraction';
    urls.innerHTML = `<label class="field-label" for="extract-urls">Or extract from public HTTPS pages</label><textarea id="extract-urls" rows="3" placeholder="https://example.com/contact&#10;Up to 10 URLs, one per line." spellcheck="false"></textarea><button id="extract-urls-button" class="button secondary" type="button" disabled>Fetch page addresses <span aria-hidden="true">↗</span></button><button id="extract-urls-cancel" class="text-button" type="button" hidden>Cancel extraction</button><p class="field-hint">The server fetches only public HTTPS pages and rejects private or local network addresses. Pasted text stays on your device.</p>`;
    element('panel-extract').querySelector('.provider-column')?.append(urls);
    element<HTMLInputElement>('online-target-file').addEventListener('change', async (event) => {
        const input = event.target as HTMLInputElement;
        const file = input.files?.[0];
        if (!file) return;
        const generation = ++fileReadGeneration;
        if (file.size > 2 * 1024 * 1024) { setMessage('online-message', 'Choose a target file smaller than 2 MB.', 'error'); input.value = ''; return; }
        try {
            const text = await file.text();
            if (generation !== fileReadGeneration) return;
            const targets = querySelect.value === 'email' ? extractEmails(text) : [text.trim()];
            onlineTargets.value = targets.slice(0, MAX_TARGETS).join('\n');
            updateTargetCount();
            setMessage('online-message', `Read ${Math.min(targets.length, MAX_TARGETS)} targets locally${targets.length > MAX_TARGETS ? '; only the first 10 are loaded' : ''}.`);
        } catch { setMessage('online-message', 'The target file could not be read.', 'error'); }
        input.value = '';
    });
    element('extract-urls-button').addEventListener('click', () => { void extractUrls(); });
    element('extract-urls-cancel').addEventListener('click', () => cancelRun());
}

async function extractUrls(): Promise<void> {
    if (running || !health?.remoteEnabled || !health.capabilities?.urlExtraction) return;
    const urls = [...new Set(element<HTMLTextAreaElement>('extract-urls').value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean))];
    if (!urls.length || urls.length > 10 || urls.some((url) => { try { return new URL(url).protocol !== 'https:'; } catch { return true; } })) { setMessage('extract-message', 'Enter between 1 and 10 complete public HTTPS URLs, one per line.', 'error'); return; }
    const id = ++runId;
    running = true;
    controller = new AbortController();
    updateControls();
    element('extract-urls-cancel').hidden = false;
    const emails = new Set(extracted);
    const failures: string[] = [];
    for (const [index, url] of urls.entries()) {
        if (id !== runId) break;
        setMessage('extract-message', `Fetching page ${index + 1} / ${urls.length}…`);
        try {
            const response = await fetch('/api/extract', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url }), signal: controller.signal, credentials: 'omit', cache: 'no-store' });
            const payload: unknown = await response.json();
            if (!response.ok) throw new Error(errorMessage(payload, `Page ${index + 1} failed (HTTP ${response.status}).`));
            if (!isObject(payload) || !Array.isArray(payload.emails) || payload.emails.some((email: unknown) => typeof email !== 'string')) throw new Error(`Page ${index + 1} returned malformed extraction data.`);
            for (const email of payload.emails as string[]) if (isEmailAddress(email) && emails.size < 1000) emails.add(email.toLowerCase());
        } catch (error: unknown) {
            if (id !== runId) break;
            failures.push(error instanceof Error ? error.message : `Page ${index + 1} could not be fetched.`);
        }
    }
    element('extract-urls-cancel').hidden = true;
    if (id !== runId) return;
    running = false;
    controller = null;
    updateControls();
    renderExtraction([...emails]);
    if (failures.length) setMessage('extract-message', `${emails.size} addresses retained. ${failures.join(' ')}`, 'error');
}

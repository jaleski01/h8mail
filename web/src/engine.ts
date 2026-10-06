import { flattenEngineRecords, toCsv, visibleValue, type ExportRecord } from './domain';

interface EngineOptions {
    getAccessKey: () => string;
    isBusy: () => boolean;
    onBusy: (busy: boolean) => void;
    download: (content: string, filename: string, type: string) => void;
}
interface EngineJob { id: string; status: 'running' | 'completed' | 'error' | 'cancelled'; results?: unknown; error?: { message?: string }; warnings?: { message?: string }[] }

export function mountEngine(options: EngineOptions): { configure: (available: boolean) => void; cancel: () => Promise<void>; clear: () => void } {
    const tab = document.createElement('button');
    tab.id = 'tab-engine';
    tab.type = 'button';
    tab.className = 'tab';
    tab.setAttribute('role', 'tab');
    tab.setAttribute('aria-selected', 'false');
    tab.setAttribute('aria-controls', 'panel-engine');
    tab.tabIndex = -1;
    tab.dataset.mode = 'engine';
    tab.textContent = 'Full engine';
    document.querySelector('.tabs')?.append(tab);
    const panel = document.createElement('div');
    panel.id = 'panel-engine';
    panel.className = 'mode-panel';
    panel.hidden = true;
    panel.setAttribute('role', 'tabpanel');
    panel.setAttribute('aria-labelledby', 'tab-engine');
    // This template is static; all upstream output is inserted as text below.
    panel.innerHTML = `<div id="engine-setup" class="engine-setup"><p class="eyebrow">ORIGINAL CLI / LOCAL COMPANION</p><h2>Every upstream feature.<br />On your own machine.</h2><p>The full Python engine needs your local filesystem and long-running processes. Start the local companion to use Breach Compilation, archives, configuration files, all CLI providers, chase, and power chase through this interface.</p><pre tabindex="0">python scripts/local_app.py</pre><p>Then open <a href="http://127.0.0.1:5330">http://127.0.0.1:5330</a>. Vercel's online lookup and browser file tools work independently.</p></div>
        <form id="engine-form" class="engine-form" hidden novalidate><div class="section-label"><span>ORIGINAL H8MAIL ENGINE</span><span>LOCAL COMPANION</span></div><h2>Run the full investigation.</h2><p class="field-hint">Paths refer to files on the machine running the companion. API keys and configuration are used only for this job.</p><div class="engine-fields"><div><label class="field-label" for="engine-targets">Targets or absolute paths to target files</label><textarea id="engine-targets" rows="3" placeholder="name@example.com&#10;C:\\Data\\targets.txt" spellcheck="false"></textarea></div><div><label class="field-label" for="engine-urls">URLs to extract targets from</label><textarea id="engine-urls" rows="3" placeholder="https://example.com/contact" spellcheck="false"></textarea></div><div><label class="field-label" for="engine-query">Query type</label><select id="engine-query"><option value="email">Email</option><option value="domain">Domain</option><option value="username">Username</option><option value="ip">IP address</option><option value="hash">Hash</option><option value="password">Password</option></select></div><div><label class="field-label" for="engine-chase-limit">Chase limit (0 disables chase)</label><input id="engine-chase-limit" type="number" min="0" max="25" value="0" /></div><div><label class="field-label" for="engine-local-paths">Local text files or directories (one absolute path per line)</label><textarea id="engine-local-paths" rows="3" spellcheck="false"></textarea></div><div><label class="field-label" for="engine-gzip-paths">GZIP / TAR.GZ files or directories (one absolute path per line)</label><textarea id="engine-gzip-paths" rows="3" spellcheck="false"></textarea></div><div><label class="field-label" for="engine-breach-path">Breach Compilation directory</label><input id="engine-breach-path" type="text" autocomplete="off" spellcheck="false" /></div><div><label class="field-label" for="engine-config-paths">Configuration files (one absolute path per line)</label><textarea id="engine-config-paths" rows="2" spellcheck="false"></textarea></div><div class="engine-wide"><label class="field-label" for="engine-api-keys">CLI API keys (space-separated name=value entries)</label><input id="engine-api-keys" type="password" autocomplete="off" spellcheck="false" placeholder="hunterio=your-key snusbase_token=your-key" /></div></div><div class="engine-options"><label class="checkbox-label"><input id="engine-loose" type="checkbox" />Loose targets (for local string searches)</label><label class="checkbox-label"><input id="engine-power-chase" type="checkbox" />Power chase</label><label class="checkbox-label"><input id="engine-single-file" type="checkbox" />Scan files sequentially (disable multiprocessing)</label><label class="checkbox-label"><input id="engine-skip-defaults" type="checkbox" checked />Skip legacy default sources</label><label class="checkbox-label"><input id="engine-hide-passwords" type="checkbox" checked />Hide passwords</label></div><div class="action-row"><button id="engine-submit" class="button primary" type="submit">Run original engine <span aria-hidden="true">↗</span></button><button id="engine-cancel" class="button secondary" type="button" hidden>Cancel job</button><button id="engine-clear" class="text-button" type="button">Clear inputs</button></div><p id="engine-message" class="form-message" role="status"></p><p class="scope-note">Legacy default services may have old transport or provider behavior. Keep Skip legacy default sources enabled and configure only trusted providers. The companion runs the original CLI; remote extraction can contact the URLs you enter.</p></form><div id="engine-output" class="engine-output" hidden><div class="results-heading"><div><p class="eyebrow">ORIGINAL ENGINE OUTPUT</p><h2 id="engine-output-title">Job results</h2></div><div class="export-actions"><button id="engine-export-json" class="text-button" type="button">Export JSON ↓</button><button id="engine-export-csv" class="text-button" type="button">Export CSV ↓</button></div></div><pre id="engine-output-json" tabindex="0" aria-label="Original engine JSON result"></pre></div>`;
    document.getElementById('workspace')?.append(panel);
    const node = <T extends HTMLElement>(id: string): T => {
        const found = document.getElementById(id);
        if (!found) throw new Error(`Missing engine field: ${id}`);
        return found as T;
    };
    let enabled = false;
    let jobId: string | null = null;
    let starting = false;
    let cancelAfterStart = false;
    let jobAccessKey = '';
    let jobQuery = 'email';
    let jobHidePasswords = true;
    let generation = 0;
    let timer: number | undefined;
    let requestController: AbortController | null = null;
    let exported: unknown = null;
    let csvRecords: ExportRecord[] = [];
    const message = (text: string, error = false): void => {
        node('engine-message').textContent = text;
        node('engine-message').className = `form-message ${error ? 'error' : ''}`;
    };
    const inputValue = (id: string): string => node<HTMLInputElement | HTMLTextAreaElement>(id).value.trim();
    const lines = (id: string): string[] => inputValue(id).split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
    const checked = (id: string): boolean => node<HTMLInputElement>(id).checked;
    const setBusy = (busy: boolean): void => {
        options.onBusy(busy);
        node<HTMLButtonElement>('engine-submit').disabled = busy || !enabled;
        node<HTMLButtonElement>('engine-cancel').hidden = !busy;
        node<HTMLButtonElement>('engine-clear').disabled = busy;
        for (const field of panel.querySelectorAll<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>('input, select, textarea')) field.disabled = busy;
    };
    const headers = (): Record<string, string> => ({ 'Content-Type': 'application/json', Authorization: `Bearer ${jobAccessKey || options.getAccessKey()}` });
    const readJob = (value: unknown): EngineJob => {
        if (!value || typeof value !== 'object') throw new Error('The companion returned an invalid job response.');
        const job = value as Record<string, unknown>;
        if (typeof job.id !== 'string' || !['running', 'completed', 'error', 'cancelled'].includes(String(job.status))) {
            const error = job.error as { message?: unknown } | undefined;
            throw new Error(typeof error?.message === 'string' ? error.message : 'The companion returned an invalid job response.');
        }
        return job as unknown as EngineJob;
    };
    const finish = (job: EngineJob): void => {
        jobId = null;
        setBusy(false);
        const warnings = (job.warnings ?? []).map((warning) => warning.message).filter(Boolean).join(' ');
        message(`${job.status === 'completed' ? 'Job completed.' : job.status === 'cancelled' ? 'Job cancelled.' : job.error?.message ?? 'The original engine failed.'}${warnings ? ` ${warnings}` : ''}`, job.status === 'error');
        if (job.results) {
            exported = sanitizeResults(job.results, jobHidePasswords, jobQuery === 'password');
            csvRecords = flattenEngineRecords(exported, jobHidePasswords, jobQuery === 'password');
            node('engine-output').hidden = false;
            node('engine-output-title').textContent = `Original engine / ${job.status}`;
            node('engine-output-json').textContent = JSON.stringify(exported, null, 2);
        }
        jobAccessKey = '';
    };
    const poll = async (id: string, current: number): Promise<void> => {
        if (current !== generation) return;
        try {
            requestController = new AbortController();
            const response = await fetch(`/api/local/jobs/${encodeURIComponent(id)}`, { headers: headers(), signal: requestController.signal, cache: 'no-store', credentials: 'omit' });
            const payload: unknown = await response.json();
            if (!response.ok) throw new Error(response.status === 401 ? 'The local access key was rejected.' : 'The companion could not retrieve this job.');
            if (current !== generation) return;
            const job = readJob(payload);
            if (job.status === 'running') timer = window.setTimeout(() => { void poll(id, current); }, 1000);
            else finish(job);
        } catch (error: unknown) {
            if (current !== generation) return;
            setBusy(Boolean(jobId));
            message(`${error instanceof Error ? error.message : 'Job status could not be retrieved.'} The job may still be running; use Cancel job.`, true);
            node<HTMLButtonElement>('engine-cancel').hidden = !jobId;
        }
    };
    const cancel = async (): Promise<void> => {
        if (starting) { cancelAfterStart = true; message('Cancellation requested. Waiting for the companion to identify the starting job.'); return; }
        generation += 1;
        window.clearTimeout(timer);
        requestController?.abort();
        if (!jobId) { setBusy(false); return; }
        const id = jobId;
        try {
            const response = await fetch('/api/local/cancel', { method: 'POST', headers: headers(), body: JSON.stringify({ id }), credentials: 'omit' });
            if (!response.ok) throw new Error('The companion could not confirm cancellation.');
            jobId = null;
            jobAccessKey = '';
            message('Cancellation confirmed. The job processes were stopped.');
        } catch (error: unknown) {
            message(error instanceof Error ? error.message : 'Cancellation failed. Check the companion terminal.', true);
        } finally { setBusy(false); node<HTMLButtonElement>('engine-cancel').hidden = !jobId; }
    };
    const clear = (): void => {
        for (const field of panel.querySelectorAll<HTMLInputElement | HTMLTextAreaElement>('textarea, input:not([type="checkbox"]):not([type="number"])')) field.value = '';
        exported = null;
        csvRecords = [];
        node('engine-output').hidden = true;
    };
    node<HTMLFormElement>('engine-form').addEventListener('submit', async (event) => {
        event.preventDefault();
        if (!enabled || options.isBusy() || jobId) return;
        if (!inputValue('engine-targets') && !inputValue('engine-urls')) { message('Enter targets, target files, or extraction URLs.', true); return; }
        const chaseLimit = Number(inputValue('engine-chase-limit'));
        if (!Number.isInteger(chaseLimit) || chaseLimit < 0 || chaseLimit > 25) { message('Use a chase limit between 0 and 25.', true); return; }
        const current = ++generation;
        const payload = { targets: inputValue('engine-targets'), urls: inputValue('engine-urls'), query: inputValue('engine-query'), loose: checked('engine-loose'), localPaths: lines('engine-local-paths'), gzipPaths: lines('engine-gzip-paths'), breachCompilationPath: inputValue('engine-breach-path'), chaseLimit, powerChase: checked('engine-power-chase'), singleFile: checked('engine-single-file'), skipDefaults: checked('engine-skip-defaults'), hidePasswords: checked('engine-hide-passwords'), configPaths: lines('engine-config-paths'), apiKeys: inputValue('engine-api-keys').split(/\s+/).filter(Boolean) };
        setBusy(true);
        starting = true;
        cancelAfterStart = false;
        jobAccessKey = options.getAccessKey();
        jobQuery = payload.query;
        jobHidePasswords = payload.hidePasswords;
        message('Starting the original h8mail engine…');
        node('engine-output').hidden = true;
        try {
            requestController = new AbortController();
            const response = await fetch('/api/local/run', { method: 'POST', headers: headers(), body: JSON.stringify(payload), signal: requestController.signal, credentials: 'omit' });
            const raw: unknown = await response.json();
            if (current !== generation) return;
            const job = readJob(raw);
            if (!response.ok) throw new Error(job.error?.message ?? 'The companion could not start this job.');
            jobId = job.id;
            starting = false;
            if (cancelAfterStart) { await cancel(); return; }
            if (job.status === 'running') { message(`Original engine is running. Job ${job.id.slice(0, 8)}. One job runs at a time; you can cancel at any time.`); void poll(job.id, current); }
            else finish(job);
        } catch (error: unknown) {
            if (current !== generation) return;
            starting = false;
            setBusy(false);
            message(error instanceof Error ? error.message : 'The original engine could not start.', true);
        }
    });
    node('engine-cancel').addEventListener('click', () => { void cancel(); });
    node('engine-clear').addEventListener('click', () => { clear(); message('Inputs and results cleared.'); });
    node('engine-export-json').addEventListener('click', () => options.download(JSON.stringify(exported, null, 2), 'h8mail-engine-results.json', 'application/json'));
    node('engine-export-csv').addEventListener('click', () => options.download(toCsv(csvRecords), 'h8mail-engine-results.csv', 'text/csv;charset=utf-8'));
    window.addEventListener('pagehide', () => { generation += 1; window.clearTimeout(timer); requestController?.abort(); clear(); });
    return { configure: (available) => { enabled = available; node('engine-setup').hidden = available; node('engine-form').hidden = !available; node<HTMLButtonElement>('engine-submit').disabled = !available; }, cancel, clear };
}

function sanitizeResults(value: unknown, hidePasswords: boolean, passwordQuery = false): unknown {
    if (!value || typeof value !== 'object') return value;
    if (Array.isArray(value)) return value.map((entry) => sanitizeResults(entry, hidePasswords, passwordQuery));
    return Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, (passwordQuery && key === 'target') || (hidePasswords && /password|passwd|pwd|hash|secret|token/i.test(key)) ? '[hidden]' : key === 'data' && Array.isArray(entry) ? entry.map((row: unknown) => {
        if (!Array.isArray(row)) return sanitizeResults(row, hidePasswords, passwordQuery);
        if (row.length === 2 && typeof row[0] === 'string' && !row[0].includes(':')) return [row[0], visibleValue({ source: 'engine', field: row[0], value: String(row[1]) }, !hidePasswords)];
        return row.map((cell: unknown) => {
            if (typeof cell !== 'string') return sanitizeResults(cell, hidePasswords, passwordQuery);
            const delimiter = cell.indexOf(':');
            return delimiter > 0 ? `${cell.slice(0, delimiter)}:${visibleValue({ source: 'engine', field: cell.slice(0, delimiter), value: cell.slice(delimiter + 1) }, !hidePasswords)}` : cell;
        });
    }) : sanitizeResults(entry, hidePasswords, passwordQuery)]));
}

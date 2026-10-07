# H8MAIL web adaptation

This repository preserves the original `h8mail` package and adds a black,
minimal interface, a private Python API for Vercel, browser-local file search,
and an optional local companion for workflows that require the original CLI
engine and access to your computer's files. No analytics, remote fonts or
tracking SDKs are added.

The repository includes the web interface, Python API, Vercel service routing,
and an upstream synchronization workflow. A local checkout alone does not
confirm that a Vercel deployment or scheduled upstream workflow is active.

## Run locally

Use Node.js 22.12 or newer and a Python installation with `pip`:

```bash
npm ci --prefix web
python -m pip install -r requirements.txt
npm --prefix web run build
python scripts/local_app.py
```

Open the loopback URL printed by the local companion. It serves the same built
interface and creates a temporary access token automatically; no environment
variable is required for this mode. Keep it bound to your own computer.

For interface development, run these in separate terminals:

```bash
npm --prefix web run dev:api
npm --prefix web run dev
```

The Vite development server proxies `/api` to the local Python API. Set any
provider API keys you want to test in the Python server's process environment.
Remote lookup reads them on the server; the browser does not accept or store
provider credentials. Browser-local file search does not need provider keys.

The original terminal entry point remains available:

```bash
python -m h8mail --help
```

## Optional Vercel setup

Import this repository with its root as the Vercel project root. `vercel.json`
defines two services: the Vite app builds from `web/` and serves `/`; the Python
API runs from the repository root and receives `/api` and `/api/*`. The API path
must remain public because the browser calls it on the same origin. Provider API
keys belong in Vercel Project Settings → Environment Variables and are read only
by server functions. Do not add them as `VITE_` variables. The interface's
collapsed **Provider access and Vercel key setup** section lists the server
variable names and reports whether each API key is configured; it never exposes
the values.

All online lookups that have a public no-key API work without Vercel
environment variables. With no keys, email lookups run Hunter Email Insight,
which checks address and domain deliverability signals but does not search
breach records. Password lookups run HIBP Pwned Passwords using k-anonymity and
response padding; only the first five characters of a SHA-1 hash are sent to
HIBP. Providers requiring keys are skipped automatically and do not appear as
lookup failures. Configured providers join the same aggregate search.

Every email lookup keeps Hunter Email Insight active, even when
`HUNTER_API_KEY` is configured. The key adds its separate Domain Search for
business-domain contacts and enables direct domain queries. When Email Insight
identifies a public webmail provider, Domain Search is skipped; searching a
domain such as `gmail.com` is not an individual inbox search. A failed or empty
Domain Search does not erase successful free signals. Partial provider failures
are shown as warnings and logged without targets or credentials. HIBP email-breach and paste
searches require an API subscription key; its documented integration-test
email is the only no-subscription exception. EmailRep anonymous access is
disabled and new keys are not currently issued. IntelX's public instance is
available to non-registered users on its site, but third-party API integration
requires an API license; this adapter therefore uses an account-assigned API
instance and key. IntelX defaults to the paid instance; set
`INTELX_API_TIER=free` only if IntelX assigned that instance to your key.

| Variable | Purpose |
| --- | --- |
| `HIBP_API_KEY` | Have I Been Pwned account breach and paste searches. |
| `EMAILREP_API_KEY` | EmailRep reputation lookup. |
| `HUNTER_API_KEY` | Optional. Enables Hunter related-domain email search; Email Insight works without it. |
| `LEAKLOOKUP_API_KEY` | Leak-Lookup search. |
| `SNUSBASE_API_KEY` | Snusbase activation code. |
| `DEHASHED_API_KEY` | DeHashed API v2. |
| `INTELX_API_KEY` | Intelligence X API key. |
| `INTELX_API_TIER` | Optional `paid` or `free`; defaults to `paid`. |
| `BREACHDIRECTORY_API_KEY` | BreachDirectory subscription key from RapidAPI. |

Do not point the adaptation's deployment repository at the original author's
repository. It must contain both the upstream package and the adapters/interface.
See [upstream updates](UPDATES.md) for the prepared automatic update pipeline.

## Original capabilities and where they run

The original source remains intact. Serverless hosting cannot provide persistent
background processes, access your computer's folders or remove provider limits.
The local companion and terminal engine preserve the workflows that need those
capabilities.

| Original capability | Vercel/browser interface | Local companion / original CLI |
| --- | --- | --- |
| Email pattern matching and text/file targeting | Extract addresses from text or a target file of up to 2 MiB; first 10 targets per batch | Original regex, file paths, globbing and multiple target arguments |
| URLs as target sources | Authenticated extraction from up to 10 bounded public HTTPS pages; local text extraction | Original URL targeting also available through the CLI |
| Loose patterns such as usernames or domain fragments | Browser-local substring matching where selected | Original `--loose` engine search |
| Bulk target inputs | Small bounded provider batches and browser file inputs | Original file-reading and large batches |
| CSV and JSON output | Download displayed normalized results | Original output flags and engine output |
| Breach Compilation data | Browser can search readable text selected by the user | Original indexed-directory engine; use local paths |
| Cleartext and GZIP local datasets | Files stay in the browser; bounded streaming worker | Original filesystem and multiprocessing search for large datasets |
| TAR/GZIP archives and directories | Selected folders and regular text members of TAR, TAR.GZ and TGZ archives, within browser limits; archive links are skipped | Original archive/directory engine on your computer |
| Related email discovery | Hunter domain search with an API key; bounded results | Original provider methods |
| Chasing related addresses | Interface chase/power-chase controls, at most 25 addresses total | Original `--chase` and `--power-chase` |
| Premium provider lookups | Curated HTTPS adapters with explicit service status | Original provider integrations and configuration files |
| Username, password, IP, hash and domain queries | Supported query types depend on the selected provider | Original `--custom-query` and local loose queries |
| Regrouping results for targets/methods | Results table and exports | Original summaries and output |
| Password hiding | Sensitive fields hidden by default; reveal explicitly | Original `--hide` and companion masking |
| Terminal colors and progress | Interface status, progress and cancellation | Original terminal formatting |
| Single-file scanning and multiprocessing | Browser worker avoids blocking the interface | Original `--single-file` and multiprocessing modes |
| INI keys and `--gen-config` | Enter provider keys in memory | Config-file paths in the local engine; original `--gen-config` through CLI |
| Debug mode | Safe error codes instead of provider payloads | Original CLI `--debug`; treat its output as sensitive |

Vercel adapters cover HIBP breaches/pastes, HIBP Pwned Passwords, EmailRep,
Hunter, Leak-Lookup, Snusbase, DeHashed and BreachDirectory through its RapidAPI
endpoint. IntelX uses its incremental API workflow. A query is sent to every
compatible provider whose key is configured, plus compatible public no-key
endpoints. Providers control their own access, quota and response coverage; a
successful integration cannot guarantee a particular result. Legacy Scylla
and WeLeakInfo methods remain in the original package, but the hosted interface
marks them unavailable because their current secure API contracts are not
verified. Retaining legacy source does not mean those external services
currently work.

Every aggregated lookup displays a **Search coverage** list beside its results.
All catalog providers appear with their actual access or completion status:
results, no matches, partial/failed lookup, missing key, unsupported query, or
unavailable hosted API. Skipped providers are never counted as completed
lookups or marked as no matches. A cancelled lookup retains completed results
and marks remaining work as not completed. Hunter Email Insight is currently
the only no-key email lookup in this catalog; free HIBP Pwned Passwords accepts
a password candidate, not an email. EmailRep's anonymous API is disabled.

Remote searches are bounded by target, response-size, record and execution limits.
Hunter and DeHashed expose one provider page at a time; use **Load next page** to
continue within the limits of the active subscription. DeHashed is capped at
10,000 results per query. Other providers may return domain-related evidence
rather than breach evidence; the interface identifies the source and warns about
truncation. A `not_found` result means that the selected service returned no
matching result, not proof that an address has never appeared in a breach. An
external error is reported as `error` and is not converted into a clean result.

The local companion permits one active job, up to 100 initial target lines and
10 URLs, a 15-minute execution deadline, and a 2 MiB result limit. Use the CLI
directly when a complete dataset or long investigation exceeds these interface
limits. The direct CLI retains its original behavior and does not inherit the
companion's job limits.

Browser searches are bounded to 200 selected files, 100 MiB of decompressed
content, 1,000 matches and 64 KiB per text line. They stream readable TXT, CSV,
LOG, GZIP and regular text members from supported TAR archives. Extensionless
text leaves, including readable Breach Compilation folders, are accepted within
the same bounds. No archive contents are extracted onto the computer. Warnings
identify skipped files or incomplete searches rather than claiming a clean result.

## Privacy and safety boundaries

Local browser searches do not upload file contents. Remote searches send your
query and the relevant provider credential to this application's server and to
the selected provider over HTTPS. URL extraction makes a bounded server-side
request to the URL you explicitly submit; private, loopback and reserved
destinations are rejected. These are explicit user-requested third-party
transfers, not background telemetry.

Provider credentials are held only in server environment variables and the
server-side worker input pipe. Session queries and results are not intentionally
retained in browser storage, database tables or application error logs. API
failures are written as structured Vercel runtime logs with route, provider,
status and safe error code only; search targets, API keys, provider response
payloads, JavaScript messages and stack traces are excluded. Uncaught browser
exceptions are reported with only an event category and coarse page route. This
minimal error reporting is enabled to meet the deployment's error-log requirement.
The local companion exchanges worker results through a
temporary local job directory and removes it after completion; CLI output files
that you explicitly request follow the original CLI behavior. Hosting providers
and queried services have their own infrastructure and retention policies. Exported CSV/JSON files can
contain sensitive records and are saved only when you request a download. CSV
formula-like cells are neutralized to prevent spreadsheet formula execution.

Keep the local companion bound to loopback,
and use the original engine only with data and queries you are authorized to
process. It preserves the upstream behavior and its external-service limitations.

## Validation

```bash
python -m unittest discover -s tests_web
npm --prefix web run check
npm --prefix web test
npm --prefix web run build
```

The automated provider tests use offline fixtures. They verify contracts,
validation, credential isolation, error handling and upstream compatibility
without sending private targets or using paid credentials. The live Vercel test
can use Hunter Email Insight and HIBP Pwned Passwords without configured keys.
HIBP email breach lookup should only be live-tested against its documented
reserved test addresses unless a real subscription key is configured.

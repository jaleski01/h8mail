"""Run the preserved CLI in a disposable local process, never a Vercel function."""

import contextlib
import io
import json
import sys
from pathlib import Path
from urllib.parse import urlsplit

import requests


class QuietOutput(io.TextIOBase):
    def write(self, text):
        return len(text)


def serialize_targets(targets, hide_passwords):
    """Include local three-field records and mask complete sensitive dump lines."""
    from h8mail.utils.print_json import generate_source_arrays

    captured = []
    for target in targets:
        rows = generate_source_arrays([tuple(entry[:2]) for entry in target.data if len(entry) >= 2])
        if hide_passwords:
            rows = [[record.split(":", 1)[0] + ":[hidden]" if any(term in record.split(":", 1)[0].upper() for term in ("PASS", "HASH", "SALT", "LOCALSEARCH", "BC_", "INTELX")) else record for record in row] for row in rows]
        captured.append({"target": target.target, "pwn_num": target.pwned, "data": rows})
    return captured


def run_engine(settings):
    """Capture results without making the terminal output a public API contract."""
    from h8mail.utils import run
    from h8mail.utils.colors import colors

    results = {"targets": []}
    warnings = []
    attempted_sources = 0

    def engine_warning(*args, **kwargs):
        if not warnings:
            warnings.append({"code": "engine_warning", "message": "The original engine reported a failure. Some sources or files may be incomplete."})

    def capture_results(destination, targets):
        results["targets"] = serialize_targets(targets, settings["hidePasswords"])

    # The compatibility engine keeps its providers, with verified transport enforced.
    original_request = requests.sessions.Session.request
    allowed_hosts = {"api.hunter.io", "haveibeenpwned.com", "emailrep.io", "api.snusbase.com", "leak-lookup.com", "api.dehashed.com", "2.intelx.io", "free.intelx.io", "public.intelx.io", "breachdirectory.org", "api.weleakinfo.com", "scylla.so"}

    def guarded_request(session, method, url, **kwargs):
        nonlocal attempted_sources
        attempted_sources += 1
        parsed = urlsplit(url)
        if parsed.scheme != "https" or parsed.hostname not in allowed_hosts or parsed.port not in (None, 443) or parsed.username or parsed.password:
            engine_warning()
            raise requests.RequestException("The legacy provider endpoint is not permitted.")
        kwargs.update(timeout=(5, 20), verify=True, allow_redirects=False, stream=True)
        session.trust_env = False
        response = original_request(session, method, url, **kwargs)
        try:
            content = bytearray()
            for chunk in response.iter_content(65536):
                content.extend(chunk)
                if len(content) > 8 * 1024 * 1024:
                    raise requests.RequestException("The legacy provider response exceeded the local safety limit.")
            response._content = bytes(content)
            response._content_consumed = True
        finally:
            response.close()
        if response.status_code >= 400 and response.status_code != 404:
            engine_warning()
        return response

    requests.sessions.Session.request = guarded_request
    colors.bad_news = engine_warning
    run.save_results_json = capture_results
    from .local_scan import scan_files
    from h8mail.utils import localsearch, breachcompilation

    def scan_source(files, targets, gzip_mode=False, single_file=False):
        nonlocal attempted_sources
        if not files:
            raise ValueError("The selected source did not contain readable files.")
        attempted_sources += len(files)
        return scan_files(files, targets, gzip_mode=gzip_mode, single_file=single_file)

    run.local_search = lambda files, targets: scan_source(files, targets)
    run.local_search_single = lambda files, targets: scan_source(files, targets, single_file=True)
    run.local_gzip_search = lambda files, targets: scan_source(files, targets, gzip_mode=True)
    run.local_search_single_gzip = lambda files, targets: scan_source(files, targets, gzip_mode=True, single_file=True)
    localsearch.local_search = run.local_search
    breachcompilation.local_search = run.local_search
    original_breachcomp_check = run.breachcomp_check

    def isolated_breachcomp_check(targets, path):
        from h8mail.utils.classes import target as Target

        # Upstream mutates its shared path and replaces .data; isolate each account.
        for target in targets:
            local_target = Target(target.target)
            original_breachcomp_check([local_target], path)
            target.data.extend(local_target.data)
            target.pwned += local_target.pwned
        return targets

    run.breachcomp_check = isolated_breachcomp_check
    targets = settings["targets"].splitlines()
    targets = [target.strip() for target in targets if target.strip()]
    if settings["urls"].strip():
        from .url_extract import extract_url

        for url in settings["urls"].splitlines():
            if url.strip():
                targets.extend(extract_url(url.strip())["emails"])
    if not targets:
        raise ValueError("No targets were found in the input or URLs.")
    arguments = ["-t", *targets, "-j", "captured-in-memory.json"]
    if settings["query"] != "email":
        arguments.extend(["-q", settings["query"]])
    for key, flag in (("localPaths", "-lb"), ("gzipPaths", "-gz"), ("configPaths", "-c"), ("apiKeys", "-k")):
        if settings[key]:
            arguments.extend([flag, *settings[key]])
    if settings["breachCompilationPath"]:
        arguments.extend(["-bc", settings["breachCompilationPath"]])
    for key, flag in (("loose", "--loose"), ("singleFile", "-sf"), ("skipDefaults", "-sk"), ("hidePasswords", "--hide"), ("powerChase", "--power-chase")):
        if settings[key]:
            arguments.append(flag)
    if settings["chaseLimit"]:
        arguments.extend(["-ch", str(settings["chaseLimit"])])
    with contextlib.redirect_stdout(QuietOutput()), contextlib.redirect_stderr(QuietOutput()):
        run.h8mail(run.parse_args(arguments))
    outcome = {"results": results, "warnings": warnings, "partial": bool(warnings)}
    if not attempted_sources:
        outcome["error"] = {"code": "no_sources", "message": "No source was searched. Select local files, a dataset directory or valid provider configuration."}
    elif warnings and not any(target["data"] for target in results["targets"]):
        outcome["error"] = {"code": "incomplete_search", "message": "Some sources failed. A clean result cannot be confirmed."}
    return outcome


def main():
    destination = Path(sys.argv[1])
    try:
        settings = json.loads(sys.stdin.read(65537))
        outcome = run_engine(settings)
    except (Exception, SystemExit):
        # Upstream CLI exits and provider errors never expose secrets or stack traces.
        outcome = {"error": {"code": "local_engine_failed", "message": "The original engine could not complete this search. Check paths, query type and provider configuration."}}
    encoded = json.dumps(outcome, ensure_ascii=True).encode("utf-8")
    if len(encoded) > 2 * 1024 * 1024:
        encoded = json.dumps({"error": {"code": "results_too_large", "message": "The engine results exceed 2 MiB. Narrow the search or use the CLI directly."}}).encode()
    destination.write_bytes(encoded)


if __name__ == "__main__":
    main()

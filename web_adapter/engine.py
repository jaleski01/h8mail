"""Run upstream methods in isolation and normalize validated provider responses."""

import contextlib
import hashlib
import re
from urllib.parse import quote

import requests

from h8mail.utils.classes import target as UpstreamTarget

from .contracts import MAX_RECORDS, MAX_VALUE_LENGTH, SearchRequest, result
from .errors import AdapterError, public_error
from .transport import Transport


class DiscardOutput:
    """Discard CLI output without retaining secrets, even within the child process."""

    def write(self, text: str) -> int:
        return len(text)

    def flush(self) -> None:
        pass


@contextlib.contextmanager
def protect_session_boundary(transport: Transport):
    """Fail closed if an upstream update bypasses WebTarget.make_request()."""
    original_class_request = requests.Session.request
    authorized_request = transport.session.request

    def guarded_request(session, method, url, **options):
        if session is not transport.session:
            transport.failure = "transport_blocked"
            raise AdapterError("transport_blocked")
        return authorized_request(method, url, **options)

    requests.Session.request = guarded_request
    try:
        yield
    finally:
        requests.Session.request = original_class_request


class WebTarget(UpstreamTarget):
    def __init__(self, request: SearchRequest, transport: Transport):
        super().__init__(request.target, debug=False)
        self.transport = transport

    def make_request(self, url, meth="GET", timeout=20, redirs=True,
                     data=None, params=None, verify=True, auth=None):
        # The legacy method cannot opt out of transport protections.
        return self.transport.request(url, meth, self.headers, data, params, auth=auth)


def require(condition: bool) -> None:
    if not condition:
        raise AdapterError("protocol_error")


def nonnegative_integer(value: object) -> int:
    require(type(value) is int and value >= 0)
    return value


def hibp_password_hash(password: str) -> str:
    """Use HIBP's SHA-1 lookup protocol without treating it as cryptography."""
    return hashlib.sha1(password.encode("utf-8"), usedforsecurity=False).hexdigest().upper()


def request_pwned_passwords(request: SearchRequest, transport: Transport) -> None:
    digest = hibp_password_hash(request.target)
    transport.request(
        f"https://api.pwnedpasswords.com/range/{digest[:5]}", "GET",
        {"User-Agent": "h8mail-web-adapter", "Add-Padding": "true"}, raw=True,
    )


def record(source: str, field: str, value: object, request: SearchRequest) -> dict[str, str]:
    require(isinstance(source, str) and isinstance(field, str)
            and isinstance(value, (str, int, float, bool)))
    sensitive = any(marker in field.lower() for marker in
                    ("password", "pass", "hash", "salt", "dehash"))
    rendered = "[hidden]" if request.hidePasswords and sensitive else str(value)
    if len(rendered) > MAX_VALUE_LENGTH:
        rendered = rendered[:MAX_VALUE_LENGTH - 14] + "… [truncated]"
    return {"source": source[:256], "field": field[:128], "value": rendered}


def flatten_entries(entries: list, source: str, request: SearchRequest,
                    records: list[dict[str, str]]) -> None:
    for entry in entries:
        require(isinstance(entry, dict))
        for field, value in entry.items():
            require(isinstance(field, str))
            if value is None or value == "" or field in ("id", "database_name", "obtained_from"):
                continue
            if isinstance(value, list):
                require(all(isinstance(part, (str, int, float, bool)) for part in value))
                values = value
            else:
                require(isinstance(value, (str, int, float, bool)))
                values = [value]
            for part in values:
                if len(records) < MAX_RECORDS:
                    records.append(record(source, field, part, request))


def invoke(request: SearchRequest, target: WebTarget, transport: Transport) -> None:
    api_key = request.credentials["apiKey"]
    if request.provider == "hibp":
        # Upstream interpolates path input; encode it before invoking the original method.
        target.target = quote(request.target, safe="")
        target.get_hibp3(api_key)
        if len(transport.responses) == 1 and transport.responses[0][1] == 404:
            target.headers["hibp-api-key"] = api_key
            target.get_hibp3_pastes()
    elif request.provider == "hibp_pastes":
        target.target = quote(request.target, safe="")
        target.headers["hibp-api-key"] = api_key
        target.get_hibp3_pastes()
    elif request.provider == "emailrep":
        target.target = quote(request.target, safe="")
        target.get_emailrepio(api_key)
    elif request.provider == "leaklookup":
        # Use the public method for email to avoid legacy private-field parsing bugs.
        if request.query == "email":
            target.get_leaklookup_pub(api_key)
        else:
            query = {"ip": "ipaddress", "domain": "domain", "username": "username",
                     "password": "password"}[request.query]
            transport.request("https://leak-lookup.com/api/search", "POST", target.headers,
                              {"key": api_key, "type": query, "query": request.target})
    elif request.provider == "snusbase":
        # Current Snusbase JSON/Auth contract differs from the upstream 2022 form API.
        query = {"ip": "lastip", "domain": "_domain"}.get(request.query, request.query)
        transport.request("https://api.snusbase.com/data/search", "POST",
                          {**target.headers, "Auth": api_key},
                          json_body={"terms": [request.target], "types": [query], "wildcard": False})
    elif request.provider == "dehashed":
        field = {"ip": "ip_address", "hash": "hashed_password"}.get(request.query, request.query)
        term = request.target.replace("\\", "\\\\").replace('"', '\\"')
        transport.request("https://api.dehashed.com/v2/search", "POST",
                          {**target.headers, "Dehashed-Api-Key": api_key},
                          json_body={"query": f'{field}:"{term}"', "page": request.page, "size": 100,
                                     "regex": False, "wildcard": False, "de_dupe": False})
    elif request.provider == "breachdirectory":
        function = {"email": "auto", "username": "auto", "domain": "domain",
                    "hash": "dehash", "password": "password"}[request.query]
        transport.request("https://breachdirectory.p.rapidapi.com/", "GET",
                          {**target.headers, "X-RapidAPI-Key": api_key,
                           "X-RapidAPI-Host": "breachdirectory.p.rapidapi.com"},
                          params={"func": function, "term": request.target})


def normalize(request: SearchRequest, transport: Transport) -> dict:
    records: list[dict[str, str]] = []
    count = 0
    truncated = False
    metadata: dict[str, object] = {}
    if not transport.responses:
        raise AdapterError(transport.failure or "engine_error")
    _, status, payload = transport.responses[0]
    if status == 404 and request.provider in ("hibp_pastes", "emailrep"):
        return result(request, [], 0)
    if status == 404 and request.provider == "hibp":
        payload = []
    else:
        require(status == 200)
    if request.provider == "hibp":
        require(isinstance(payload, list))
        names = set()
        for breach in payload:
            require(isinstance(breach, dict) and isinstance(breach.get("Name"), str))
            names.add(breach["Name"])
        count = len(names)
        records.extend(record("HIBP", "breach", name, request) for name in sorted(names)[:MAX_RECORDS])
        for path, paste_status, pastes in transport.responses[1:]:
            try:
                require("/pasteaccount/" in path)
                if paste_status == 404:
                    continue
                require(paste_status == 200 and isinstance(pastes, list))
                require(all(isinstance(paste, dict) and isinstance(paste.get("Id"), str)
                            and isinstance(paste.get("Source"), str) for paste in pastes))
            except AdapterError:
                transport.failure = "protocol_error"
                continue
            for paste in pastes:
                if len(records) < MAX_RECORDS:
                    records.append(record("HIBP", "paste", paste["Source"] + ":" + paste["Id"], request))
            count += len(pastes)
    elif request.provider == "hibp_pastes":
        require(isinstance(payload, list))
        for paste in payload:
            require(isinstance(paste, dict) and isinstance(paste.get("Id"), str)
                    and isinstance(paste.get("Source"), str))
            if len(records) < MAX_RECORDS:
                records.append(record("HIBP", "paste", paste["Source"] + ":" + paste["Id"], request))
        count = len(payload)
    elif request.provider == "emailrep":
        require(isinstance(payload, dict) and isinstance(payload.get("details"), dict)
                and isinstance(payload.get("reputation"), str))
        details = payload["details"]
        require(type(details.get("credentials_leaked")) is bool
                and type(details.get("deliverable")) is bool
                and isinstance(details.get("profiles"), list)
                and all(isinstance(profile, str) for profile in details["profiles"]))
        references = nonnegative_integer(payload.get("references"))
        records.append(record("EMAILREP", "reputation", payload["reputation"], request))
        for field in ("deliverable", "credentials_leaked", "data_breach", "first_seen", "last_seen"):
            if field in details:
                records.append(record("EMAILREP", field, details[field], request))
        records.extend(record("EMAILREP", "profile", profile, request) for profile in details["profiles"][:100])
        records.append(record("EMAILREP", "references", references, request))
        # References include non-breach evidence; never label this number as a breach count.
        count = 1
    elif request.provider == "pwnedpasswords":
        require(isinstance(payload, bytes))
        digest = hibp_password_hash(request.target)
        suffix_to_find = digest[5:]
        try:
            lines = payload.decode("ascii").splitlines()
        except UnicodeDecodeError as exc:
            raise AdapterError("protocol_error") from exc
        require(bool(lines))
        prevalence = None
        for line in lines:
            suffix, separator, raw_count = line.partition(":")
            require(bool(separator) and bool(re.fullmatch(r"[A-F0-9]{35}", suffix))
                    and bool(re.fullmatch(r"[0-9]{1,12}", raw_count)))
            if suffix == suffix_to_find:
                prevalence = int(raw_count)
        if prevalence:
            records.append(record("HIBP Pwned Passwords", "occurrence_count", prevalence, request))
            count = 1
        metadata["notice"] = "The full password was compared on this server; only a padded SHA-1 prefix was sent to HIBP."
    elif request.provider == "leaklookup":
        require(isinstance(payload, dict) and (payload.get("error") is False or payload.get("error") == "false"))
        messages = payload.get("message")
        require(isinstance(messages, (dict, list)))
        if isinstance(messages, list):
            require(all(isinstance(source, str) for source in messages))
            count = len(messages)
            records.extend(record("LEAKLOOKUP", "breach", source, request) for source in messages[:MAX_RECORDS])
        else:
            for source, entries in messages.items():
                require(isinstance(source, str))
                if isinstance(entries, list):
                    count += len(entries) if entries else 1
                    if entries and all(isinstance(entry, dict) for entry in entries):
                        flatten_entries(entries, source, request, records)
                    else:
                        require(all(isinstance(entry, (str, int, float, bool)) for entry in entries))
                        if len(records) < MAX_RECORDS:
                            records.append(record("LEAKLOOKUP", "breach", source, request))
                elif isinstance(entries, (str, int, bool)):
                    count += 1
                    if len(records) < MAX_RECORDS:
                        records.append(record("LEAKLOOKUP", "breach", source, request))
                else:
                    raise AdapterError("protocol_error")
    elif request.provider == "snusbase":
        require(isinstance(payload, dict) and isinstance(payload.get("results"), dict))
        count = nonnegative_integer(payload.get("size"))
        actual = 0
        for source, entries in payload["results"].items():
            require(isinstance(source, str) and isinstance(entries, list))
            actual += len(entries)
            flatten_entries(entries, source, request, records)
        require(count >= actual and (count == 0 or actual > 0))
        truncated = count > actual
    elif request.provider == "dehashed":
        require(isinstance(payload, dict))
        count = nonnegative_integer(payload.get("total"))
        entries = payload.get("entries")
        require(isinstance(entries, list) or (entries is None and count == 0))
        for entry in entries or []:
            require(isinstance(entry, dict))
            source = entry.get("database_name", entry.get("obtained_from", "DEHASHED"))
            if isinstance(source, list):
                require(all(isinstance(part, str) for part in source))
                source = ", ".join(source)
            require(isinstance(source, str))
            flatten_entries([entry], source, request, records)
        require(count >= len(entries or []) and (count == 0 or bool(entries)))
        has_more = bool(entries) and request.page * 100 < min(count, 10_000)
        truncated = count > 10_000
        metadata.update({"total": count, "hasMore": has_more, "truncated": truncated})
    elif request.provider == "breachdirectory":
        require(isinstance(payload, dict) and payload.get("success") is True)
        count = nonnegative_integer(payload.get("found"))
        entries = payload.get("result")
        require(isinstance(entries, (list, dict, str)) or entries is None)
        if isinstance(entries, list):
            flatten_entries(entries, "BREACHDIRECTORY", request, records)
            require(count >= len(entries) or count == 0 and not entries)
        elif isinstance(entries, dict):
            if all(isinstance(values, list) for values in entries.values()):
                for source, values in entries.items():
                    require(isinstance(source, str))
                    flatten_entries(values, source, request, records)
            else:
                flatten_entries([entries], "BREACHDIRECTORY", request, records)
        elif isinstance(entries, str) and entries:
            records.append(record("BREACHDIRECTORY", "dehash_result", entries, request))
        truncated = count > len(entries) if isinstance(entries, list) else False
    truncated = truncated or len(records) >= MAX_RECORDS or any(
        entry["value"].endswith("… [truncated]") for entry in records
    )
    metadata.setdefault("truncated", truncated)
    if transport.failure:
        # Optional HIBP paste failures must not erase confirmed breach findings.
        if request.provider == "hibp" and count:
            metadata["warnings"] = [public_error(transport.failure)]
        else:
            raise AdapterError(transport.failure)
    return result(request, records, count, **metadata)


def hunter_insight(payload: object, request: SearchRequest) -> tuple[list[dict[str, str]], bool]:
    """Validate the free endpoint before using its webmail flag to skip domain search."""
    require(isinstance(payload, dict) and isinstance(payload.get("data"), dict))
    insight = payload["data"]
    returned_email = insight.get("email")
    require(isinstance(returned_email, str)
            and returned_email.casefold() == request.target.casefold())
    fields = ("gibberish", "pattern", "mx_records", "disposable", "webmail")
    require(all(type(insight.get(field)) is bool for field in fields))
    webmail_allowed = insight.get("webmail_allowed")
    require(webmail_allowed is None or type(webmail_allowed) is bool)
    records = [record("HUNTER_EMAIL_INSIGHT", field, insight[field], request) for field in fields]
    if webmail_allowed is not None:
        records.append(record("HUNTER_EMAIL_INSIGHT", "webmail_allowed", webmail_allowed, request))
    return records, insight["webmail"]


def run_hunter_search(request: SearchRequest, connection: Transport) -> dict:
    """Always retain free email signals; key-based domain results are supplementary."""
    records = []
    warnings = []
    notices = []
    count = 0
    webmail = False
    completed = False
    metadata = {}
    headers = {"User-Agent": "h8mail-web-adapter"}
    if request.query == "email" and request.page == 1:
        try:
            response = connection.request("https://api.hunter.io/v2/email-insight", headers=headers,
                                          params={"email": request.target})
            require(response.status_code == 200)
            insight_records, webmail = hunter_insight(connection.responses[-1][2], request)
            records.extend(insight_records)
            count = 1
            completed = True
            notices.append("Free Email Insight completed. These are address and domain signals, not mailbox verification or breach records.")
        except AdapterError as error:
            warnings.append({**public_error(error.code),
                             "message": "Hunter Email Insight: " + str(error)})
    api_key = request.credentials["apiKey"]
    if api_key and webmail:
        notices.append("This address uses a public webmail provider. Domain Search was skipped because it searches business-domain contacts, not individual Gmail or Outlook inboxes.")
    elif api_key:
        try:
            domain = request.target.rsplit("@", 1)[-1]
            response = connection.request("https://api.hunter.io/v2/domain-search", headers=headers,
                                          params={"domain": domain, "api_key": api_key, "limit": 10,
                                                  "offset": (request.page - 1) * 10})
            require(response.status_code == 200)
            payload = connection.responses[-1][2]
            require(isinstance(payload, dict) and isinstance(payload.get("data"), dict)
                    and isinstance(payload.get("meta"), dict))
            emails = payload["data"].get("emails")
            require(isinstance(emails, list) and all(isinstance(email, dict)
                    and isinstance(email.get("value"), str) for email in emails))
            total = nonnegative_integer(payload["meta"].get("results"))
            require(total >= len(emails))
            records.extend(record("HUNTER_DOMAIN_SEARCH", "related_email", email["value"], request)
                           for email in emails[:MAX_RECORDS - len(records)])
            count += total
            completed = True
            metadata.update(total=total, hasMore=bool(emails) and request.page * 10 < total,
                            truncated=total > 10_000 or len(records) >= MAX_RECORDS)
            notices.append(f"Domain Search reports {total} related business-domain email addresses. This does not search breach records or leaked passwords.")
        except AdapterError as error:
            warnings.append({**public_error(error.code),
                             "message": "Hunter Domain Search: " + str(error)})
    if not completed:
        failure = warnings.pop(0) if warnings else public_error("provider_error")
        response = result(request, [], 0, failure["code"], warnings=warnings)
        response["error"] = failure
        return response
    return result(request, records, count, warnings=warnings, notice=" ".join(notices), **metadata)


def run_search(request: SearchRequest, transport: Transport | None = None) -> dict:
    """Use only within a dedicated child process; CLI stdout is process-local."""
    if request.provider == "pwnedpasswords":
        return run_pwned_password_search(request, transport)
    connection = transport or Transport(request.provider)
    try:
        if request.provider == "hunter":
            return run_hunter_search(request, connection)
        with contextlib.redirect_stdout(DiscardOutput()), contextlib.redirect_stderr(DiscardOutput()), \
                protect_session_boundary(connection):
            target = WebTarget(request, connection)
            try:
                invoke(request, target, connection)
            except AdapterError:
                if not connection.responses:
                    raise
            return normalize(request, connection)
    except AdapterError as exc:
        return result(request, [], 0, exc.code)
    except (Exception, SystemExit):
        # The original CLI uses broad catches and exit(); neither may escape the worker boundary.
        return result(request, [], 0, "engine_error")
    finally:
        connection.close()


def run_pwned_password_search(request: SearchRequest, transport: Transport | None = None) -> dict:
    """Run the self-contained HIBP range API path without invoking the legacy CLI."""
    connection = transport or Transport(request.provider)
    try:
        request_pwned_passwords(request, connection)
        return normalize(request, connection)
    except AdapterError as exc:
        return result(request, [], 0, exc.code)
    finally:
        connection.close()

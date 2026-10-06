"""Incremental IntelX operations based on the official SDK, without dataset files."""

import re

from .contracts import MAX_RECORDS, SearchRequest, result, validate_request
from .engine import record, require
from .errors import AdapterError, public_error
from .transport import MAX_RESPONSE_BYTES, Transport

ROOTS = {"paid": "2.intelx.io", "free": "free.intelx.io"}
UUID_PATTERN = re.compile(r"[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}")
BUCKET_PATTERN = re.compile(r"(?:leaks|pastes|darknet|whois|usenet|dns|documents|dumpster|web)(?:\.[a-z0-9_-]+)*")
OPERATIONS = {
    "start": {"target", "query", "maxFiles"},
    "results": {"searchId", "limit"},
    "read": {"systemId", "bucket", "target", "query", "hidePasswords", "name"},
    "terminate": {"searchId"},
}


def identifier(value: object, error_code: str = "invalid_request") -> str:
    if not isinstance(value, str) or not UUID_PATTERN.fullmatch(value):
        raise AdapterError(error_code)
    return value.lower()


def bucket_name(value: object, error_code: str = "invalid_request") -> str:
    if not isinstance(value, str) or len(value) > 128 or not BUCKET_PATTERN.fullmatch(value):
        raise AdapterError(error_code)
    return value


def bounded_integer(value: object, minimum: int = 1, maximum: int = 10) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise AdapterError("invalid_request")
    return value


def validate_operation(payload: object, server_credentials: dict[str, str] | None = None) -> dict:
    if not isinstance(payload, dict):
        raise AdapterError("invalid_request")
    operation = payload.get("operation")
    if not isinstance(operation, str) or operation not in OPERATIONS or set(payload) - (
        OPERATIONS[operation] | {"operation"}
    ):
        raise AdapterError("invalid_request")
    credentials = server_credentials or {}
    if not isinstance(credentials, dict) or set(credentials) - {"apiKey", "apiTier"}:
        raise AdapterError("invalid_request")
    api_key = credentials.get("apiKey")
    api_tier = credentials.get("apiTier") or "paid"
    if not isinstance(api_key, str) or len(api_key) > 512 or any(
        not 33 <= ord(character) <= 126 for character in api_key
    ):
        raise AdapterError("invalid_credentials")
    if not api_key:
        raise AdapterError("provider_not_configured")
    if not isinstance(api_tier, str) or api_tier not in ROOTS:
        raise AdapterError("invalid_request")
    normalized = {"operation": operation, "credentials": {"apiKey": api_key, "apiTier": api_tier}}
    if operation in ("results", "terminate"):
        normalized["searchId"] = identifier(payload.get("searchId"))
    if operation == "results":
        normalized["limit"] = bounded_integer(payload.get("limit", 10))
    if operation in ("start", "read"):
        target = payload.get("target")
        query = payload.get("query", "email")
        hide_passwords = payload.get("hidePasswords", True)
        if query == "selector":
            if not isinstance(target, str) or not 1 <= len(target) <= 320 or any(
                ord(character) < 32 or ord(character) == 127 for character in target
            ) or type(hide_passwords) is not bool:
                raise AdapterError("invalid_request")
            target = target.strip()
            if not target:
                raise AdapterError("invalid_request")
        else:
            checked = validate_request({"provider": "snusbase", "target": target, "query": query,
                                        "hidePasswords": hide_passwords}, {"apiKey": api_key})
            target = checked.target
        normalized.update(target=target, query=query, hidePasswords=hide_passwords)
    if operation == "start":
        normalized["maxFiles"] = bounded_integer(payload.get("maxFiles", 10))
    if operation == "read":
        normalized["systemId"] = identifier(payload.get("systemId"))
        normalized["bucket"] = bucket_name(payload.get("bucket"))
        name = payload.get("name", "IntelX record")
        if not isinstance(name, str) or len(name) > 256 or any(ord(character) < 32 for character in name):
            raise AdapterError("invalid_request")
        normalized["name"] = name
    return normalized


class IntelXTransport(Transport):
    def __init__(self, api_tier: str, api_key: str):
        super().__init__("intelx")
        self.host = ROOTS[api_tier]
        self.headers = {"x-key": api_key, "User-Agent": "h8mail-web/1.0", "Accept": "application/json"}

    def call(self, path: str, method: str = "GET", params: dict | None = None,
             payload: dict | None = None, raw: bool = False):
        if path not in ("/authenticate/info", "/intelligent/search", "/intelligent/search/result",
                        "/intelligent/search/terminate", "/file/read"):
            raise AdapterError("transport_blocked")
        return self.request("https://" + self.host + path, method, self.headers,
                            params=params, json_body=payload, raw=raw, allow_truncate=raw)


def start_search(settings: dict, connection: IntelXTransport) -> dict:
    capabilities = connection.call("/authenticate/info")
    require(capabilities.status_code == 200)
    capabilities = capabilities.json()
    require(isinstance(capabilities, dict) and isinstance(capabilities.get("buckets"), list)
            and all(isinstance(bucket, str) for bucket in capabilities["buckets"]))
    buckets = [bucket for bucket in capabilities["buckets"] if BUCKET_PATTERN.fullmatch(bucket)]
    if not buckets:
        raise AdapterError("provider_denied")
    response = connection.call("/intelligent/search", "POST", payload={
        "term": settings["target"], "buckets": buckets, "lookuplevel": 0,
        "maxresults": settings["maxFiles"], "timeout": 5, "datefrom": "", "dateto": "",
        "sort": 4, "media": 24, "terminate": [],
    })
    require(response.status_code == 200)
    payload = response.json()
    require(isinstance(payload, dict))
    if payload.get("status") == 1:
        raise AdapterError("invalid_selector")
    if "status" in payload:
        require(type(payload["status"]) is int and payload["status"] == 0)
    return {"operation": "start", "searchId": identifier(payload.get("id"), "protocol_error"), "status": "started"}


def search_results(settings: dict, connection: IntelXTransport) -> dict:
    response = connection.call("/intelligent/search/result", params={
        "id": settings["searchId"], "limit": settings["limit"],
    })
    require(response.status_code == 200)
    payload = response.json()
    require(isinstance(payload, dict) and type(payload.get("status")) is int
            and payload["status"] in (0, 1, 2, 3) and isinstance(payload.get("records"), list))
    records = []
    skipped = 0
    for entry in payload["records"]:
        require(isinstance(entry, dict) and type(entry.get("media")) is int
                and type(entry.get("size")) is int and entry["size"] >= 0
                and isinstance(entry.get("name"), str))
        system_id = identifier(entry.get("systemid"), "protocol_error")
        bucket = bucket_name(entry.get("bucket"), "protocol_error")
        storage_id = entry.get("storageid", "")
        require(isinstance(storage_id, str) and (storage_id == "" or bool(re.fullmatch(r"[a-fA-F0-9]{128}", storage_id))))
        if entry["media"] != 24:
            skipped += 1
            continue
        if len(records) < settings["limit"]:
            name = " ".join(entry["name"].split())[:256]
            records.append({"systemId": system_id, "storageId": storage_id, "bucket": bucket,
                            "name": name, "size": entry["size"], "media": entry["media"]})
    status = {0: "pending", 1: "complete", 2: "expired", 3: "pending"}[payload["status"]]
    return {"operation": "results", "searchId": settings["searchId"], "status": status,
            "providerStatus": payload["status"], "records": records, "count": len(records),
            "truncated": len(payload["records"]) > settings["limit"] or skipped > 0}


def read_matches(settings: dict, connection: IntelXTransport) -> dict:
    response = connection.call("/file/read", params={
        "type": 0, "systemid": settings["systemId"], "bucket": settings["bucket"],
    }, raw=True)
    if response.status_code == 404:
        raise AdapterError("record_unavailable")
    require(response.status_code == 200)
    content = response.content
    if b"\x00" in content:
        raise AdapterError("protocol_error")
    text = content.decode("utf-8", errors="replace")
    truncated = response.web_truncated or len(content) == MAX_RESPONSE_BYTES
    lines = text.splitlines()
    if truncated and content and not content.endswith((b"\n", b"\r")):
        lines = lines[:-1]
    request = SearchRequest(settings["target"], settings["query"], "intelx",
                            {"apiKey": settings["credentials"]["apiKey"]}, settings["hidePasswords"])
    records = []
    needle = request.target.casefold() if request.query == "email" else request.target
    for line_number, line in enumerate(lines, 1):
        searchable = line.casefold() if request.query == "email" else line
        if needle in searchable:
            if len(records) >= MAX_RECORDS:
                truncated = True
                break
            value = "[hidden]" if request.hidePasswords else line
            records.append(record(settings["name"], "matching_line_" + str(line_number), value, request))
    metadata = {"truncated": truncated, "bytesRead": len(content)}
    if truncated:
        metadata["warnings"] = [public_error("incomplete_search")]
    return result(request, records, len(records), "incomplete_search" if truncated and not records else None, **metadata)


def terminate_search(settings: dict, connection: IntelXTransport) -> dict:
    response = connection.call("/intelligent/search/terminate", params={"id": settings["searchId"]})
    require(response.status_code in (200, 204))
    return {"operation": "terminate", "searchId": settings["searchId"], "status": "terminated"}


def execute_operation(settings: dict, connection: IntelXTransport | None = None) -> dict:
    """Perform exactly one bounded operation; all polling is owned by the browser."""
    connection = connection or IntelXTransport(settings["credentials"]["apiTier"], settings["credentials"]["apiKey"])
    operations = {"start": start_search, "results": search_results,
                  "read": read_matches, "terminate": terminate_search}
    try:
        return operations[settings["operation"]](settings, connection)
    finally:
        connection.close()

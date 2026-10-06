"""WSGI entry point for the private h8mail web adapter."""

from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
import json
import logging
from typing import Callable
from urllib.parse import parse_qs, urlsplit

from h8mail.utils.version import __version__
from web_adapter.contracts import MAX_REQUEST_BYTES, validate_request
from web_adapter.errors import AdapterError, MESSAGES, public_error
from web_adapter.executor import execute_search
from web_adapter.providers import PROVIDERS, PROVIDER_BY_ID, get_provider_credentials

LOGGER = logging.getLogger("h8mail.api")
API_ROUTES = {"health", "search", "extract", "intelx", "client-error"}
CLIENT_ERROR_TYPES = {"uncaught_exception", "unhandled_rejection"}
CLIENT_ERROR_ROUTES = {"app"}
URL_ERROR_CODES = {
    "invalid_url", "dns_error", "blocked_address", "redirect_error", "website_error",
    "unsupported_content", "page_too_large", "too_many_emails", "website_unavailable",
    "timeout", "extraction_failed",
}
ERROR_CODES = set(MESSAGES) | URL_ERROR_CODES


def provider_metadata() -> list[dict]:
    providers = []
    for provider in PROVIDERS:
        entry = {**provider}
        fields = []
        for field in provider["credentialFields"]:
            configured = bool(get_provider_credentials(provider["id"]).get(field["key"]))
            fields.append({**field, "configured": configured})
        entry["credentialFields"] = fields
        providers.append(entry)
    return providers


def health() -> dict:
    return {
        "engine": {"name": "h8mail", "version": __version__}, "version": __version__,
        "remoteEnabled": True, "providers": provider_metadata(),
        "capabilities": {"maxTargets": 10, "maxConcurrent": 4, "maxRecords": 500,
                         "localSearch": "browser", "urlExtraction": True},
    }


def route_for(path: str, query_string: str) -> str:
    route = parse_qs(query_string).get("route", [""])[0]
    return route.strip("/") if route else path.removeprefix("/api").strip("/")


def log_api_error(route: str, status: int, payload: dict, exception: Exception | None = None) -> None:
    error = payload.get("error")
    errors = [error] if isinstance(error, dict) else []
    warnings = payload.get("warnings")
    if isinstance(warnings, list):
        errors.extend(warning for warning in warnings if isinstance(warning, dict))
    provider_id = payload.get("provider")
    event = {
        "level": "error", "event": "api_error",
        "route": route if route in API_ROUTES else "unknown",
        "status": status,
    }
    if isinstance(provider_id, str) and provider_id in PROVIDER_BY_ID:
        event["provider"] = provider_id
    if exception is not None:
        event["exception"] = type(exception).__name__[:64]
    for error in errors:
        code = error.get("code")
        event["code"] = code if isinstance(code, str) and code in ERROR_CODES else "provider_error"
        LOGGER.error(json.dumps(event, separators=(",", ":"), sort_keys=True))


def _dispatch_request(
    method: str,
    path: str,
    query_string: str,
    content_type: str,
    content_length_values: list[str],
    has_transfer_encoding: bool,
    read_body: Callable[[int], bytes],
) -> tuple[int, dict]:
    route = route_for(path, query_string)
    if method == "GET":
        if route in ("", "health"):
            return 200, health()
        code = "method_not_allowed" if route in ("search", "extract", "intelx") else "not_found"
        return (405 if code == "method_not_allowed" else 404), {"error": public_error(code)}
    if method == "OPTIONS":
        return 405, {"error": public_error("method_not_allowed")}
    if method != "POST":
        return 405, {"error": public_error("method_not_allowed")}
    if route not in ("search", "extract", "intelx", "client-error"):
        code = "method_not_allowed" if route in ("", "health") else "not_found"
        return (405 if code == "method_not_allowed" else 404), {"error": public_error(code)}

    try:
        if (content_type.split(";", 1)[0].strip().lower() != "application/json"
                or len(content_length_values) != 1 or not content_length_values[0].isdigit()
                or has_transfer_encoding):
            raise AdapterError("invalid_request")
        length = int(content_length_values[0])
        if length > MAX_REQUEST_BYTES:
            raise AdapterError("payload_too_large")
        payload = json.loads(read_body(length))
        if route == "extract":
            if not isinstance(payload, dict) or set(payload) != {"url"} or not isinstance(payload["url"], str):
                raise AdapterError("invalid_request")
        elif route == "client-error":
            if (not isinstance(payload, dict) or set(payload) != {"type", "route"}
                    or not isinstance(payload["type"], str) or payload["type"] not in CLIENT_ERROR_TYPES
                    or not isinstance(payload["route"], str) or payload["route"] not in CLIENT_ERROR_ROUTES):
                raise AdapterError("invalid_request")
            LOGGER.error(json.dumps({
                "level": "error", "event": "client_error", "code": "client_error",
                "type": payload["type"], "route": payload["route"],
            }, separators=(",", ":"), sort_keys=True))
            return 202, {"accepted": True}
        elif route == "intelx":
            from web_adapter.intelx import validate_operation

            request = validate_operation(payload, get_provider_credentials("intelx"))
        else:
            provider_id = payload.get("provider") if isinstance(payload, dict) else ""
            request = validate_request(payload, get_provider_credentials(provider_id))
    except (AdapterError, ValueError, UnicodeError) as error:
        code = error.code if isinstance(error, AdapterError) else "invalid_request"
        return (413 if code == "payload_too_large" else 400), {"error": public_error(code)}

    if route == "extract":
        from web_adapter.url_extract import UrlExtractionError, extract_url

        try:
            return 200, extract_url(payload["url"])
        except UrlExtractionError as error:
            status = 400 if error.code in ("invalid_url", "blocked_address") else 502
            return status, {"error": {"code": error.code, "message": str(error)}}
    if route == "intelx":
        from web_adapter.intelx import execute_operation

        try:
            return 200, execute_operation(request)
        except AdapterError as error:
            status = 400 if error.code in ("invalid_selector", "invalid_request") else 502
            return status, {"error": public_error(error.code)}
    return 200, execute_search(request)


def dispatch_request(
    method: str,
    path: str,
    query_string: str,
    content_type: str,
    content_length_values: list[str],
    has_transfer_encoding: bool,
    read_body: Callable[[int], bytes],
) -> tuple[int, dict]:
    route = route_for(path, query_string)
    try:
        status, payload = _dispatch_request(
            method, path, query_string, content_type, content_length_values,
            has_transfer_encoding, read_body,
        )
    except Exception as error:
        status, payload = 500, {"error": public_error("internal_error")}
        log_api_error(route, status, payload, error)
        return status, payload
    if status >= 400 or payload.get("status") == "error" or payload.get("error"):
        log_api_error(route, status, payload)
    return status, payload


def encode_response(payload: dict) -> tuple[bytes, list[tuple[str, str]]]:
    encoded = json.dumps(payload, ensure_ascii=True, allow_nan=False).encode("utf-8")
    return encoded, [
        ("Content-Type", "application/json; charset=utf-8"),
        ("Content-Length", str(len(encoded))),
        ("Cache-Control", "no-store, private"),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "no-referrer"),
    ]


def app(environ: dict, start_response: Callable) -> list[bytes]:
    """Serve the API through Vercel's Python WSGI entry point."""
    transfer_encoding = environ.get("HTTP_TRANSFER_ENCODING", "")
    length = environ.get("CONTENT_LENGTH", "")
    status, payload = dispatch_request(
        environ.get("REQUEST_METHOD", ""),
        environ.get("PATH_INFO", "/"),
        environ.get("QUERY_STRING", ""),
        environ.get("CONTENT_TYPE", ""),
        [length] if length else [],
        bool(transfer_encoding),
        environ["wsgi.input"].read,
    )
    encoded, headers = encode_response(payload)
    start_response(f"{status} {HTTPStatus(status).phrase}", headers)
    return [encoded]


class handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # HTTP logs must not contain request targets, provider keys, or private records.
        pass

    def _route(self) -> str:
        parsed = urlsplit(self.path)
        return route_for(parsed.path, parsed.query)

    def _send(self, status: int, payload: dict) -> None:
        encoded, headers = encode_response(payload)
        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        try:
            self.wfile.write(encoded)
        except (BrokenPipeError, ConnectionResetError):
            return

    def _dispatch(self) -> None:
        parsed = urlsplit(self.path)
        lengths = self.headers.get_all("Content-Length", []) or []
        status, payload = dispatch_request(
            self.command,
            parsed.path,
            parsed.query,
            self.headers.get("Content-Type", ""),
            lengths,
            bool(self.headers.get("Transfer-Encoding")),
            self.rfile.read,
        )
        self._send(status, payload)

    def do_GET(self):
        self._dispatch()

    def do_POST(self):
        self._dispatch()

    def do_OPTIONS(self):
        self._dispatch()

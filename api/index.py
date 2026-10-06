"""WSGI entry point for the private h8mail web adapter."""

from hmac import compare_digest
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
import json
import os
from typing import Callable
from urllib.parse import parse_qs, urlsplit

from h8mail.utils.version import __version__
from web_adapter.contracts import MAX_REQUEST_BYTES, validate_request
from web_adapter.errors import AdapterError, public_error
from web_adapter.executor import execute_search
from web_adapter.providers import PROVIDERS


def configured_token() -> str | None:
    token = os.environ.get("H8MAIL_ACCESS_TOKEN", "")
    return token if 16 <= len(token) <= 512 and all(33 <= ord(char) <= 126 for char in token) else None


def health() -> dict:
    return {
        "engine": {"name": "h8mail", "version": __version__}, "version": __version__,
        "remoteEnabled": configured_token() is not None, "providers": PROVIDERS,
        "capabilities": {"maxTargets": 10, "maxConcurrent": 4, "maxRecords": 500,
                         "localSearch": "browser", "urlExtraction": True},
    }


def route_for(path: str, query_string: str) -> str:
    route = parse_qs(query_string).get("route", [""])[0]
    return route.strip("/") if route else path.removeprefix("/api").strip("/")


def dispatch_request(
    method: str,
    path: str,
    query_string: str,
    authorization_values: list[str],
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
    if route not in ("search", "extract", "intelx"):
        code = "method_not_allowed" if route in ("", "health") else "not_found"
        return (405 if code == "method_not_allowed" else 404), {"error": public_error(code)}

    token = configured_token()
    if token is None:
        return 503, {"error": public_error("not_configured")}
    authorization = authorization_values[0] if len(authorization_values) == 1 else ""
    supplied = authorization.removeprefix("Bearer ") if authorization.startswith("Bearer ") else ""
    if len(supplied) > 512 or not compare_digest(supplied.encode("utf-8"), token.encode("utf-8")):
        return 401, {"error": public_error("access_required")}

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
        elif route == "intelx":
            from web_adapter.intelx import validate_operation

            request = validate_operation(payload)
        else:
            request = validate_request(payload)
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
    authorization = environ.get("HTTP_AUTHORIZATION")
    transfer_encoding = environ.get("HTTP_TRANSFER_ENCODING", "")
    length = environ.get("CONTENT_LENGTH", "")
    status, payload = dispatch_request(
        environ.get("REQUEST_METHOD", ""),
        environ.get("PATH_INFO", "/"),
        environ.get("QUERY_STRING", ""),
        [authorization] if authorization is not None else [],
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
        # HTTP logs must not contain Authorization headers, query targets, or private records.
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
        authorization = self.headers.get_all("Authorization", []) or []
        lengths = self.headers.get_all("Content-Length", []) or []
        status, payload = dispatch_request(
            self.command,
            parsed.path,
            parsed.query,
            authorization,
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

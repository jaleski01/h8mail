"""Vercel Python HTTP entry point for the private h8mail web adapter."""

from hmac import compare_digest
from http.server import BaseHTTPRequestHandler
import json
import os
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


class handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # HTTP logs must not contain Authorization headers, query targets, or private records.
        pass

    def _route(self) -> str:
        parsed = urlsplit(self.path)
        route = parse_qs(parsed.query).get("route", [""])[0]
        return route.strip("/") if route else parsed.path.removeprefix("/api").strip("/")

    def _send(self, status: int, payload: dict) -> None:
        encoded = json.dumps(payload, ensure_ascii=True, allow_nan=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store, private")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        try:
            self.wfile.write(encoded)
        except (BrokenPipeError, ConnectionResetError):
            # A disconnected browser no longer receives the completed response.
            return

    def do_GET(self):
        route = self._route()
        if route in ("", "health"):
            self._send(200, health())
        else:
            code = "method_not_allowed" if route in ("search", "extract", "intelx") else "not_found"
            self._send(405 if code == "method_not_allowed" else 404, {"error": public_error(code)})

    def do_POST(self):
        route = self._route()
        if route not in ("search", "extract", "intelx"):
            code = "method_not_allowed" if route in ("", "health") else "not_found"
            self._send(405 if code == "method_not_allowed" else 404, {"error": public_error(code)})
            return
        token = configured_token()
        if token is None:
            self._send(503, {"error": public_error("not_configured")})
            return
        authorizations = self.headers.get_all("Authorization", [])
        authorization = authorizations[0] if len(authorizations) == 1 else ""
        supplied = authorization.removeprefix("Bearer ") if authorization.startswith("Bearer ") else ""
        if len(supplied) > 512 or not compare_digest(supplied.encode("utf-8"), token.encode("utf-8")):
            self._send(401, {"error": public_error("access_required")})
            return
        try:
            content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
            lengths = self.headers.get_all("Content-Length", [])
            if (content_type != "application/json" or len(lengths) != 1
                    or not lengths[0].isdigit() or self.headers.get("Transfer-Encoding")):
                raise AdapterError("invalid_request")
            length = int(lengths[0])
            if length > MAX_REQUEST_BYTES:
                raise AdapterError("payload_too_large")
            payload = json.loads(self.rfile.read(length))
            if route == "extract":
                if not isinstance(payload, dict) or set(payload) != {"url"} or not isinstance(payload["url"], str):
                    raise AdapterError("invalid_request")
            elif route == "intelx":
                from web_adapter.intelx import validate_operation

                request = validate_operation(payload)
            else:
                request = validate_request(payload)
        except (AdapterError, ValueError, UnicodeError) as exc:
            code = exc.code if isinstance(exc, AdapterError) else "invalid_request"
            self._send(413 if code == "payload_too_large" else 400, {"error": public_error(code)})
            return
        if route == "extract":
            from web_adapter.url_extract import UrlExtractionError, extract_url

            try:
                self._send(200, extract_url(payload["url"]))
            except UrlExtractionError as exc:
                self._send(400 if exc.code in ("invalid_url", "blocked_address") else 502,
                           {"error": {"code": exc.code, "message": str(exc)}})
        elif route == "intelx":
            from web_adapter.intelx import execute_operation

            try:
                self._send(200, execute_operation(request))
            except AdapterError as exc:
                self._send(400 if exc.code in ("invalid_selector", "invalid_request") else 502,
                           {"error": public_error(exc.code)})
        else:
            self._send(200, execute_search(request))

    def do_OPTIONS(self):
        self._send(405, {"error": public_error("method_not_allowed")})

"""Fetch public HTTPS pages without exposing a server-side request forgery proxy."""

import html
import http.client
import ipaddress
import json
import re
import socket
import ssl
import subprocess
import sys
from urllib.parse import quote, urljoin, urlsplit

MAX_PAGE_BYTES = 2 * 1024 * 1024
MAX_EMAILS = 500
EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,63}")


class UrlExtractionError(Exception):
    """A safe failure description that excludes page content and credentials."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


def validate_url(url):
    if not isinstance(url, str) or not url or len(url) > 2048:
        raise UrlExtractionError("invalid_url", "Enter an HTTPS URL of at most 2048 characters.")
    if any(ord(character) < 33 or ord(character) == 127 for character in url):
        raise UrlExtractionError("invalid_url", "The URL contains invalid characters.")
    try:
        parsed = urlsplit(url)
        hostname = (parsed.hostname or "").encode("idna").decode("ascii")
        port = parsed.port
    except (UnicodeError, ValueError):
        raise UrlExtractionError("invalid_url", "The URL is malformed.") from None
    if parsed.scheme != "https" or not hostname or port not in (None, 443) or parsed.username is not None or parsed.password is not None:
        raise UrlExtractionError("invalid_url", "Only public HTTPS URLs on port 443 without credentials are supported.")
    return parsed, hostname


def public_addresses(hostname):
    try:
        addresses = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise UrlExtractionError("dns_error", "The website address could not be resolved.") from None
    unique_addresses = list(dict.fromkeys(address[4][0] for address in addresses))
    if not unique_addresses:
        raise UrlExtractionError("dns_error", "The website address could not be resolved.")
    for address in unique_addresses:
        ip = ipaddress.ip_address(address)
        if not ip.is_global or ip.is_multicast or ip.is_reserved or getattr(ip, "ipv4_mapped", None) is not None:
            raise UrlExtractionError("blocked_address", "Private, reserved and local network addresses are blocked.")
    return unique_addresses


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Keep TLS hostname verification while connecting to the validated IP."""

    def __init__(self, hostname, address):
        super().__init__(hostname, timeout=5, context=ssl.create_default_context())
        self.address = address

    def connect(self):
        raw_socket = socket.create_connection((self.address, 443), timeout=self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw_socket, server_hostname=self.host)
        except Exception:
            raw_socket.close()
            raise


def extract_page(url):
    """Resolve and pin every redirect independently; never follow private redirects."""
    current_url = url
    for redirect_count in range(4):
        parsed, hostname = validate_url(current_url)
        addresses = public_addresses(hostname)
        connection = PinnedHTTPSConnection(hostname, addresses[0])
        try:
            path = quote(parsed.path or "/", safe="/%:@!$&'()*+,;=-._~")
            if parsed.query:
                path += "?" + quote(parsed.query, safe="/%?:@!$&'()*+,;=-._~")
            connection.request("GET", path, headers={"Host": hostname, "User-Agent": "h8mail-web/1.0", "Accept": "text/html,text/plain,application/xhtml+xml", "Accept-Encoding": "identity"})
            response = connection.getresponse()
            if response.status in (301, 302, 303, 307, 308):
                location = response.getheader("Location")
                if not location or redirect_count == 3:
                    raise UrlExtractionError("redirect_error", "The website returned too many or invalid redirects.")
                current_url = urljoin(current_url, location)
                continue
            if response.status != 200:
                raise UrlExtractionError("website_error", "The website did not return a readable page.")
            content_type = response.getheader("Content-Type", "").split(";", 1)[0].lower().strip()
            if content_type not in ("text/html", "text/plain", "application/xhtml+xml"):
                raise UrlExtractionError("unsupported_content", "Only HTML and plain text pages are supported.")
            if response.getheader("Content-Encoding", "identity").lower() not in ("identity", ""):
                raise UrlExtractionError("unsupported_content", "The website ignored the uncompressed content request.")
            page = response.read(MAX_PAGE_BYTES + 1)
            if len(page) > MAX_PAGE_BYTES:
                raise UrlExtractionError("page_too_large", "The page exceeds the 2 MiB extraction limit.")
            text = html.unescape(page.decode("utf-8", errors="replace"))
            emails = list(dict.fromkeys(match.group(0).lower() for match in EMAIL_PATTERN.finditer(text)))
            if len(emails) > MAX_EMAILS:
                raise UrlExtractionError("too_many_emails", "The page exceeds the 500 email extraction limit.")
            return {"url": url, "emails": emails}
        except (OSError, http.client.HTTPException):
            raise UrlExtractionError("website_unavailable", "The website could not be reached securely within the time limit.") from None
        finally:
            connection.close()
    raise UrlExtractionError("redirect_error", "The website returned too many redirects.")


def extract_url(url):
    """Bound DNS, TLS and reading together in a disposable child process."""
    validate_url(url)
    try:
        completed = subprocess.run([sys.executable, "-m", "web_adapter.url_extract"], input=json.dumps({"url": url}), capture_output=True, text=True, timeout=18, check=False)
    except subprocess.TimeoutExpired:
        raise UrlExtractionError("timeout", "The website exceeded the extraction time limit.") from None
    except OSError:
        raise UrlExtractionError("extraction_failed", "The website extraction could not be started.") from None
    if completed.returncode != 0:
        raise UrlExtractionError("extraction_failed", "The website extraction could not be completed.")
    try:
        outcome = json.loads(completed.stdout)
    except (json.JSONDecodeError, TypeError):
        raise UrlExtractionError("extraction_failed", "The website extraction could not be completed.") from None
    if not isinstance(outcome, dict):
        raise UrlExtractionError("extraction_failed", "The website extraction returned an invalid result.")
    if "error" in outcome:
        error = outcome["error"]
        if not isinstance(error, dict) or not isinstance(error.get("code"), str) or not isinstance(error.get("message"), str) or len(error["code"]) > 64 or len(error["message"]) > 256:
            raise UrlExtractionError("extraction_failed", "The website extraction returned an invalid result.")
        raise UrlExtractionError(error["code"], error["message"])
    if set(outcome) != {"url", "emails"} or outcome["url"] != url or not isinstance(outcome["emails"], list) or len(outcome["emails"]) > MAX_EMAILS or any(not isinstance(email, str) or len(email) > 254 or EMAIL_PATTERN.fullmatch(email) is None for email in outcome["emails"]):
        raise UrlExtractionError("extraction_failed", "The website extraction returned an invalid result.")
    return outcome


if __name__ == "__main__":
    try:
        result = extract_page(json.loads(sys.stdin.read())["url"])
    except UrlExtractionError as error:
        result = {"error": {"code": error.code, "message": error.message}}
    print(json.dumps(result))

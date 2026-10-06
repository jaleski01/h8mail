"""Bounded HTTPS transport; an upstream update cannot choose arbitrary hosts."""

import json
import time
from urllib.parse import urlsplit

import requests

from .errors import AdapterError
from .providers import HOSTS

MAX_RESPONSE_BYTES = 2 * 1024 * 1024


class Transport:
    def __init__(self, provider_id: str):
        self.host = HOSTS[provider_id]
        self.deadline = time.monotonic() + 20
        self.session = requests.Session()
        # Provider traffic must not inherit proxy credentials or netrc authentication.
        self.session.trust_env = False
        self.responses: list[tuple[str, int, object]] = []
        self.failure: str | None = None

    def close(self) -> None:
        self.session.close()

    def request(self, url: str, method: str = "GET", headers: dict | None = None,
                data: object = None, params: object = None, json_body: object = None,
                auth: object = None, raw: bool = False, allow_truncate: bool = False) -> requests.Response:
        try:
            parsed = urlsplit(url)
            if (parsed.scheme != "https" or parsed.hostname != self.host
                    or parsed.username or parsed.password or parsed.port not in (None, 443)
                    or parsed.fragment or method not in ("GET", "POST")):
                raise AdapterError("transport_blocked")
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise AdapterError("timeout")
            with self.session.request(
                method, url, headers=headers, data=data, params=params, json=json_body,
                auth=auth, timeout=(min(4, remaining), min(8, remaining)),
                allow_redirects=False, verify=True, stream=True,
            ) as response:
                content = bytearray()
                truncated = False
                for chunk in response.iter_content(16_384):
                    if time.monotonic() > self.deadline:
                        raise AdapterError("timeout")
                    content.extend(chunk)
                    if len(content) > MAX_RESPONSE_BYTES:
                        if not allow_truncate:
                            raise AdapterError("response_too_large")
                        content = content[:MAX_RESPONSE_BYTES]
                        truncated = True
                        break
                response._content = bytes(content)
                response._content_consumed = True
                response.web_truncated = truncated
            status = response.status_code
            if status in (401, 403, 402, 429) or status >= 500 or 300 <= status < 400:
                code = {401: "invalid_credentials", 402: "provider_denied", 403: "provider_denied",
                        429: "rate_limited"}.get(status, "provider_error")
                raise AdapterError(code)
            try:
                payload = response.content if status == 200 and raw else response.json() if status == 200 else None
            except (ValueError, json.JSONDecodeError) as exc:
                raise AdapterError("protocol_error") from exc
            self.responses.append((parsed.path, status, payload))
            return response
        except AdapterError as exc:
            self.failure = exc.code
            raise
        except requests.Timeout as exc:
            self.failure = "timeout"
            raise AdapterError("timeout") from exc
        except (requests.RequestException, ValueError) as exc:
            self.failure = "provider_error"
            raise AdapterError("provider_error") from exc

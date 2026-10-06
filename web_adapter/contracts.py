"""Validate untrusted requests before any provider request or process starts."""

from dataclasses import asdict, dataclass
import ipaddress
import re

from .errors import AdapterError
from .providers import PROVIDER_BY_ID

MAX_REQUEST_BYTES = 16_384
MAX_RECORDS = 500
MAX_VALUE_LENGTH = 2048


@dataclass(frozen=True)
class SearchRequest:
    target: str
    query: str
    provider: str
    credentials: dict[str, str]
    hidePasswords: bool = True
    page: int = 1

    def to_dict(self) -> dict:
        return asdict(self)


def normalize_domain(domain: str) -> str:
    try:
        normalized = domain.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise AdapterError("invalid_request") from exc
    labels = normalized.split(".")
    if len(normalized) > 253 or len(labels) < 2 or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in labels
    ):
        raise AdapterError("invalid_request")
    return normalized


def validate_request(payload: object) -> SearchRequest:
    if not isinstance(payload, dict) or set(payload) - {
        "target", "query", "provider", "credentials", "hidePasswords", "page"
    }:
        raise AdapterError("invalid_request")
    target = payload.get("target")
    query = payload.get("query", "email")
    provider_id = payload.get("provider")
    credentials = payload.get("credentials", {})
    hide_passwords = payload.get("hidePasswords", True)
    page = payload.get("page", 1)
    if not isinstance(provider_id, str) or provider_id not in PROVIDER_BY_ID:
        raise AdapterError("invalid_request")
    provider = PROVIDER_BY_ID[provider_id]
    if not provider["available"]:
        raise AdapterError("provider_unavailable")
    if provider.get("apiRoute"):
        raise AdapterError("invalid_request")
    if type(page) is not int or not 1 <= page <= 1000:
        raise AdapterError("invalid_request")
    if provider_id == "dehashed" and page > 100:
        raise AdapterError("invalid_request")
    if provider_id not in ("hunter", "dehashed") and page != 1:
        raise AdapterError("invalid_request")
    if not isinstance(query, str) or query not in provider["queryTypes"]:
        raise AdapterError("invalid_request")
    if not isinstance(target, str) or not 1 <= len(target) <= 320 or any(
        ord(character) < 32 or ord(character) == 127 for character in target
    ) or type(hide_passwords) is not bool:
        raise AdapterError("invalid_request")
    if query != "password":
        target = target.strip()
    if query == "email":
        if target.count("@") != 1:
            raise AdapterError("invalid_request")
        local, domain = target.rsplit("@", 1)
        if not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}", local):
            raise AdapterError("invalid_request")
        target = local + "@" + normalize_domain(domain)
    elif query == "domain":
        target = normalize_domain(target)
    elif query == "ip":
        try:
            target = str(ipaddress.ip_address(target))
        except ValueError as exc:
            raise AdapterError("invalid_request") from exc
    elif not target or len(target) > 256:
        raise AdapterError("invalid_request")
    if not isinstance(credentials, dict) or set(credentials) - {"apiKey"}:
        raise AdapterError("invalid_request")
    api_key = credentials.get("apiKey", "")
    if not isinstance(api_key, str) or len(api_key) > 512 or any(
        ord(character) < 32 or ord(character) > 126 for character in api_key
    ):
        raise AdapterError("invalid_request")
    api_key = api_key.strip()
    if provider_id == "hunter" and not api_key and page != 1:
        raise AdapterError("invalid_request")
    if provider["credentialFields"][0]["required"] and not api_key:
        raise AdapterError("invalid_credentials")
    if provider_id in ("hibp", "hibp_pastes") and not re.fullmatch(r"[a-fA-F0-9]{32}", api_key):
        raise AdapterError("invalid_credentials")
    return SearchRequest(target, query, provider_id, {"apiKey": api_key}, hide_passwords, page)


def result(request: SearchRequest, records: list[dict[str, str]], count: int,
           error_code: str | None = None, **metadata: object) -> dict:
    from .errors import public_error

    response = {
        "target": "[hidden]" if request.query == "password" and request.hidePasswords else request.target,
        "query": request.query, "provider": request.provider,
        "status": "error" if error_code else "found" if count else "not_found",
        "records": records, "count": count, "page": request.page, "hasMore": False, **metadata,
    }
    if error_code:
        response["error"] = public_error(error_code)
    return response

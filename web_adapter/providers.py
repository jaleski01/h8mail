"""Supported provider contracts and server-side credential settings."""

import os

QUERY_TYPES = ("email", "username", "domain", "ip", "hash", "password")


def provider(provider_id: str, name: str, queries: tuple[str, ...], description: str,
             environment_variable: str = "", access_description: str = "",
             reason: str = "", tier_variable: str = "",
             free_query_types: tuple[str, ...] = (), api_documentation_url: str = "") -> dict:
    credentials = []
    if not reason and environment_variable:
        credentials.append({
            "key": "apiKey", "label": "API key", "type": "password",
            "required": True, "environmentVariable": environment_variable,
        })
    if not reason and tier_variable:
        credentials.append({
            "key": "apiTier", "label": "API tier", "type": "text",
            "required": False, "environmentVariable": tier_variable,
            "default": "paid", "options": ["paid", "free"],
        })
    return {
        "id": provider_id,
        "name": name,
        "available": not reason,
        "queryTypes": list(queries),
        "freeQueryTypes": list(free_query_types),
        "apiDocumentationUrl": api_documentation_url,
        "description": description,
        "accessDescription": access_description,
        "credentialFields": credentials,
        **({"unavailableReason": reason} if reason else {}),
    }


PROVIDERS = (
    provider("hibp", "Have I Been Pwned", ("email",),
             "Breach names from the HIBP account-search API.", "HIBP_API_KEY",
             "Paid API subscription required; this search is not anonymously accessible.",
             api_documentation_url="https://haveibeenpwned.com/API/V3"),
    provider("hibp_pastes", "HIBP Pastes", ("email",),
             "Paste references for an email address.", "HIBP_API_KEY",
             "Paid HIBP API subscription required; uses the same key as HIBP breach search.",
             api_documentation_url="https://haveibeenpwned.com/API/V3"),
    provider("emailrep", "EmailRep", ("email",),
             "Email reputation and exposure signals.", "EMAILREP_API_KEY",
             "An API key is required. Anonymous access is disabled and new EmailRep keys are not currently being issued.",
             api_documentation_url="https://docs.sublime.security/reference/emailrep-introduction"),
    provider("hunter", "Hunter", ("email", "domain"),
             "Email searches always include free Email Insight signals. A configured key adds business-domain contact discovery; public webmail searches keep the free signals.", "HUNTER_API_KEY",
             "Email Insight always works without a key, including when a key is configured. HUNTER_API_KEY adds Domain Search for business domains and direct domain queries; it may use account credits. Neither endpoint searches breach records.",
             free_query_types=("email",), api_documentation_url="https://hunter.io/api-documentation/v2"),
    provider("leaklookup", "Leak-Lookup", ("email", "username", "domain", "ip", "password"),
             "Breach sources or records, according to your Leak-Lookup subscription.", "LEAKLOOKUP_API_KEY",
             "API key and an active provider plan required.",
             api_documentation_url="https://leak-lookup.com/docs/search"),
    provider("snusbase", "Snusbase", QUERY_TYPES,
             "Current HTTPS search API; passwords are hidden by default.", "SNUSBASE_API_KEY",
             "Snusbase activation code and an active subscription required.",
             api_documentation_url="https://docs.snusbase.com/"),
    provider("dehashed", "DeHashed", QUERY_TYPES,
             "API v2 search with manual pagination up to the provider's 10,000-record query limit.", "DEHASHED_API_KEY",
             "API key and account credits required.",
             api_documentation_url="https://www.dehashed.com/api"),
    {**provider("intelx", "Intelligence X", (*QUERY_TYPES, "selector"),
                "Incremental text search and matching-line retrieval.", "INTELX_API_KEY",
                "IntelX lists public, free-account and paid API instances; third-party integrations require an API license. This adapter needs the account-assigned free or paid instance and API key.",
                tier_variable="INTELX_API_TIER", api_documentation_url="https://help.intelx.io/api/"),
     "apiRoute": "intelx"},
    provider("scylla", "Scylla", QUERY_TYPES, "Original CLI integration retained.",
             reason="The hosted adapter is disabled because its legacy request path disables TLS verification and no current secure API contract is verified.",
             api_documentation_url="https://scylla.so/"),
    provider("weleakinfo", "WeLeakInfo", QUERY_TYPES, "Original CLI integration retained.",
             reason="The hosted adapter is disabled because no current API contract is verified.",
             api_documentation_url="https://weleakinfo.to/"),
    provider("breachdirectory", "BreachDirectory", ("email", "username", "domain", "hash", "password"),
             "Current RapidAPI lookup for email, username, domain, hash and password.", "BREACHDIRECTORY_API_KEY",
             "A RapidAPI account/key and a BreachDirectory subscription are required.",
             api_documentation_url="https://rapidapi.com/breachdirectory-api-breachdirectory/api/breachdirectory"),
    provider("pwnedpasswords", "HIBP Pwned Passwords", ("password",),
             "Free password exposure lookup using HIBP's k-anonymity range API.",
             access_description="No account or key required. The server sends only the first five characters of the password's SHA-1 hash; the full hash comparison stays server-side.",
             free_query_types=("password",), api_documentation_url="https://haveibeenpwned.com/API/V3#PwnedPasswords"),
)
PROVIDER_BY_ID = {entry["id"]: entry for entry in PROVIDERS}


def get_provider_credentials(provider_id: str, environ: dict[str, str] | None = None) -> dict[str, str]:
    """Read only declared provider credentials from the server environment."""
    if not isinstance(provider_id, str):
        return {}
    entry = PROVIDER_BY_ID.get(provider_id)
    if entry is None or not entry["available"]:
        return {}
    values = os.environ if environ is None else environ
    credentials = {}
    for field in entry["credentialFields"]:
        variable = field.get("environmentVariable")
        if not isinstance(variable, str):
            continue
        value = values.get(variable, field.get("default", ""))
        if isinstance(value, str):
            credentials[field["key"]] = value.strip()
    return credentials


HOSTS = {
    "hibp": "haveibeenpwned.com", "hibp_pastes": "haveibeenpwned.com", "emailrep": "emailrep.io",
    "hunter": "api.hunter.io", "leaklookup": "leak-lookup.com",
    "snusbase": "api.snusbase.com", "dehashed": "api.dehashed.com",
    "breachdirectory": "breachdirectory.p.rapidapi.com",
    "intelx": "2.intelx.io", "pwnedpasswords": "api.pwnedpasswords.com",
}

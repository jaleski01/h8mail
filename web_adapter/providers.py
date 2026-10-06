"""Supported provider contracts and server-side credential settings."""

import os

QUERY_TYPES = ("email", "username", "domain", "ip", "hash", "password")


def provider(provider_id: str, name: str, queries: tuple[str, ...], description: str,
             environment_variable: str = "", access_description: str = "",
             reason: str = "", tier_variable: str = "") -> dict:
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
        "description": description,
        "accessDescription": access_description,
        "credentialFields": credentials,
        **({"unavailableReason": reason} if reason else {}),
    }


PROVIDERS = (
    provider("hibp", "Have I Been Pwned", ("email",),
             "Breach names from the HIBP account-search API.", "HIBP_API_KEY",
             "Paid API subscription required; this search is not anonymously accessible."),
    provider("hibp_pastes", "HIBP Pastes", ("email",),
             "Paste references for an email address.", "HIBP_API_KEY",
             "Paid HIBP API subscription required; uses the same key as HIBP breach search."),
    provider("emailrep", "EmailRep", ("email",),
             "Email reputation and exposure signals.", "EMAILREP_API_KEY",
             "API key required. Existing free/community quotas may apply; unauthenticated access is disabled and new keys may not be issued."),
    provider("hunter", "Hunter", ("email",),
             "Related domain email counts and addresses. This is not breach evidence.", "HUNTER_API_KEY",
             "API key required; free and paid quotas depend on the Hunter account."),
    provider("leaklookup", "Leak-Lookup", ("email", "username", "domain", "ip", "password"),
             "Breach sources or records, according to your Leak-Lookup subscription.", "LEAKLOOKUP_API_KEY",
             "API key and an active provider plan required."),
    provider("snusbase", "Snusbase", QUERY_TYPES,
             "Current HTTPS search API; passwords are hidden by default.", "SNUSBASE_API_KEY",
             "Snusbase activation code and an active subscription required."),
    provider("dehashed", "DeHashed", QUERY_TYPES,
             "API v2 search with manual pagination up to the provider's 10,000-record query limit.", "DEHASHED_API_KEY",
             "API key and account credits required."),
    {**provider("intelx", "Intelligence X", (*QUERY_TYPES, "selector"),
                "Incremental text search and matching-line retrieval.", "INTELX_API_KEY",
                "IntelX lists public, free-account and paid API instances; third-party integrations require an API license. This adapter needs the account-assigned free or paid instance and API key.",
                tier_variable="INTELX_API_TIER"),
     "apiRoute": "intelx"},
    provider("scylla", "Scylla", QUERY_TYPES, "Original CLI integration retained.",
             reason="The hosted adapter is disabled because its legacy request path disables TLS verification and no current secure API contract is verified."),
    provider("weleakinfo", "WeLeakInfo", QUERY_TYPES, "Original CLI integration retained.",
             reason="The hosted adapter is disabled because no current API contract is verified."),
    provider("breachdirectory", "BreachDirectory", ("email", "username", "domain", "hash", "password"),
             "Current RapidAPI lookup for email, username, domain, hash and password.", "BREACHDIRECTORY_API_KEY",
             "RapidAPI key and a BreachDirectory subscription; plan and quota are set in RapidAPI."),
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
    "intelx": "2.intelx.io",
}

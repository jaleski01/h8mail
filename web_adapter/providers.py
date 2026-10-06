"""Supported provider contracts and explicit serverless limitations."""

QUERY_TYPES = ("email", "username", "domain", "ip", "hash", "password")


def provider(provider_id: str, name: str, queries: tuple[str, ...], description: str,
             required: bool = True, reason: str = "") -> dict:
    return {
        "id": provider_id,
        "name": name,
        "available": not reason,
        "queryTypes": list(queries),
        "description": description,
        "credentialFields": [] if reason else [{
            "key": "apiKey", "label": "API key" if required else "API key (optional)",
            "type": "password", "required": required,
        }],
        **({"unavailableReason": reason} if reason else {}),
    }


PROVIDERS = (
    provider("hibp", "Have I Been Pwned", ("email",),
             "Breach names and paste references. A paid HIBP API subscription is required."),
    provider("hibp_pastes", "HIBP Pastes", ("email",),
             "Paste references for an email address. Requires a compatible HIBP API subscription."),
    provider("emailrep", "EmailRep", ("email",),
             "Email reputation and exposure signals. Anonymous access depends on provider policy.", False),
    provider("hunter", "Hunter", ("email",),
             "Related domain email counts; a key enables paginated related email addresses. This is not breach evidence.", False),
    provider("leaklookup", "Leak-Lookup", ("email", "username", "domain", "ip", "password"),
             "Breach sources or records, according to your Leak-Lookup API subscription."),
    provider("snusbase", "Snusbase", QUERY_TYPES,
             "Current HTTPS search API. Requires a Snusbase activation code; passwords are hidden by default."),
    provider("dehashed", "DeHashed", QUERY_TYPES,
             "API v2 search with manual pagination up to the provider's 10,000-record query limit. Requires API credits and a compatible subscription."),
    {**provider("intelx", "Intelligence X", (*QUERY_TYPES, "selector"),
                "Incremental text search and matching-line retrieval. Requires an IntelX key for your assigned API tier."),
     "apiRoute": "intelx", "credentialFields": [
         {"key": "apiKey", "label": "API key", "type": "password", "required": True},
         {"key": "apiTier", "label": "API tier: paid or free (default paid)", "type": "text", "required": False},
     ]},
    provider("scylla", "Scylla", QUERY_TYPES, "Original CLI integration retained.",
             reason="The original integration disables TLS verification and has no verified current web contract."),
    provider("weleakinfo", "WeLeakInfo", QUERY_TYPES, "Original CLI integration retained.",
             reason="The original service endpoints have no verified current web contract."),
    provider("breachdirectory", "BreachDirectory", ("email", "username", "domain", "hash", "password"),
             "Current RapidAPI lookup for email, username, domain, hash and password. Requires an active RapidAPI subscription."),
)
PROVIDER_BY_ID = {entry["id"]: entry for entry in PROVIDERS}

HOSTS = {
    "hibp": "haveibeenpwned.com", "hibp_pastes": "haveibeenpwned.com", "emailrep": "emailrep.io",
    "hunter": "api.hunter.io", "leaklookup": "leak-lookup.com",
    "snusbase": "api.snusbase.com", "dehashed": "api.dehashed.com",
    "breachdirectory": "breachdirectory.p.rapidapi.com",
    "intelx": "2.intelx.io",
}

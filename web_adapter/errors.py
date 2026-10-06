"""Public error codes deliberately exclude provider payloads and private input."""

MESSAGES = {
    "invalid_request": "The search request is invalid.",
    "invalid_credentials": "Check your provider API key and subscription.",
    "access_required": "A valid workspace access token is required.",
    "not_configured": "Set H8MAIL_ACCESS_TOKEN to at least 16 characters to enable remote searches.",
    "provider_unavailable": "This provider is not available in the web runtime.",
    "rate_limited": "The provider rate limit was reached. Try again later.",
    "provider_denied": "The provider denied access. Check your subscription or remaining credits.",
    "provider_error": "The provider could not complete this search.",
    "protocol_error": "The provider returned an unsupported response. No clean result can be confirmed.",
    "transport_blocked": "The provider attempted an unsupported or insecure connection.",
    "timeout": "The provider did not complete the search within the time limit.",
    "response_too_large": "The provider response exceeded the safe size limit. Narrow your search.",
    "payload_too_large": "The request exceeded the safe size limit.",
    "engine_error": "The search engine could not complete this search.",
    "invalid_selector": "Intelligence X requires a strong selector, such as an email, domain, IP, Bitcoin address or IBAN.",
    "incomplete_search": "The search is incomplete. No clean result can be confirmed for the unread portion.",
    "record_unavailable": "The selected Intelligence X record is unavailable or no longer accessible.",
    "not_found": "The API route was not found.",
    "method_not_allowed": "This HTTP method is not supported for this route.",
}


class AdapterError(Exception):
    """Carry only an approved public code across the HTTP and process boundaries."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(MESSAGES[code])


def public_error(code: str) -> dict[str, str]:
    return {"code": code, "message": MESSAGES[code]}

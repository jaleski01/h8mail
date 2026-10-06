"""Private subprocess entry point. Input and output never touch disk or logs."""

import json
import sys

from .contracts import MAX_REQUEST_BYTES, validate_request
from .engine import run_search
from .errors import AdapterError, public_error


def main() -> None:
    try:
        raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
        if len(raw) > MAX_REQUEST_BYTES:
            raise AdapterError("payload_too_large")
        request = validate_request(json.loads(raw))
        response = run_search(request)
    except (AdapterError, ValueError) as exc:
        code = exc.code if isinstance(exc, AdapterError) else "invalid_request"
        response = {"error": public_error(code)}
    sys.stdout.write(json.dumps(response, ensure_ascii=True, allow_nan=False))


if __name__ == "__main__":
    main()

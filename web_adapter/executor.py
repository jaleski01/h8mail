"""Bound subprocess duration and validate its output before returning results."""

import json
import os
from pathlib import Path
import subprocess
import sys

from .contracts import MAX_RECORDS, SearchRequest, result
from .providers import PROVIDERS

WORKER_TIMEOUT = 25
ROOT = Path(__file__).resolve().parent.parent


def execute_search(request: SearchRequest) -> dict:
    environment = os.environ.copy()
    environment.pop("H8MAIL_ACCESS_TOKEN", None)
    for provider in PROVIDERS:
        for field in provider["credentialFields"]:
            variable = field.get("environmentVariable")
            if variable:
                environment.pop(variable, None)
    environment["PYTHONIOENCODING"] = "utf-8"
    try:
        worker = subprocess.run(
            [sys.executable, "-m", "web_adapter.worker"],
            input=json.dumps(request.to_dict()), capture_output=True, text=True,
            timeout=WORKER_TIMEOUT, cwd=ROOT, env=environment, check=False,
        )
    except subprocess.TimeoutExpired:
        return result(request, [], 0, "timeout")
    except OSError:
        return result(request, [], 0, "engine_error")
    if worker.returncode != 0 or len(worker.stdout) > 2 * 1024 * 1024:
        return result(request, [], 0, "engine_error")
    try:
        payload = json.loads(worker.stdout)
    except (ValueError, UnicodeError):
        return result(request, [], 0, "engine_error")
    if (not isinstance(payload, dict) or payload.get("status") not in ("found", "not_found", "error")
            or payload.get("target") != request.target or payload.get("provider") != request.provider
            or payload.get("query") != request.query or type(payload.get("count")) is not int
            or payload["count"] < 0 or not isinstance(payload.get("records"), list)
            or len(payload["records"]) > MAX_RECORDS):
        return result(request, [], 0, "engine_error")
    for entry in payload["records"]:
        if not isinstance(entry, dict) or set(entry) != {"source", "field", "value"} or any(
            not isinstance(value, str) for value in entry.values()
        ):
            return result(request, [], 0, "engine_error")
    return payload

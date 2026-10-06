"""Loopback-only local companion for filesystem and long-running CLI features."""

from hmac import compare_digest
from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import uuid
from urllib.parse import unquote, urlsplit

from api.index import handler, health

ROOT = Path(__file__).resolve().parents[1]
QUERY_TYPES = {"email", "username", "domain", "ip", "hash", "password"}


def validate_settings(payload):
    """Accept structured options, never shell text or caller-selected executables."""
    defaults = {"targets": "", "urls": "", "query": "email", "loose": False, "localPaths": [], "gzipPaths": [], "configPaths": [], "apiKeys": [], "breachCompilationPath": "", "chaseLimit": 0, "powerChase": False, "singleFile": False, "skipDefaults": True, "hidePasswords": True}
    if not isinstance(payload, dict) or not set(payload).issubset(defaults):
        raise ValueError("Unknown local engine options.")
    settings = {**defaults, **payload}
    for key in ("targets", "urls", "query", "breachCompilationPath"):
        if not isinstance(settings[key], str) or len(settings[key]) > 16384 or "\x00" in settings[key]:
            raise ValueError("Invalid engine text input.")
    if not settings["targets"].strip() and not settings["urls"].strip():
        raise ValueError("Enter at least one target or URL.")
    if settings["query"] not in QUERY_TYPES:
        raise ValueError("Unsupported query type.")
    for key in ("loose", "powerChase", "singleFile", "skipDefaults", "hidePasswords"):
        if not isinstance(settings[key], bool):
            raise ValueError("Invalid engine toggle.")
    if type(settings["chaseLimit"]) is not int or not 0 <= settings["chaseLimit"] <= 25:
        raise ValueError("The chase limit must be between 0 and 25.")
    if settings["powerChase"] and not settings["chaseLimit"]:
        raise ValueError("Power chase requires a chase limit.")
    for key in ("localPaths", "gzipPaths", "configPaths", "apiKeys"):
        if not isinstance(settings[key], list) or len(settings[key]) > 100 or any(not isinstance(entry, str) or not entry or len(entry) > 4096 or "\x00" in entry for entry in settings[key]):
            raise ValueError("Invalid engine list input.")
    for key in ("localPaths", "gzipPaths", "configPaths"):
        for entry in settings[key]:
            validate_path(entry, file_only=key == "configPaths")
    if settings["breachCompilationPath"]:
        validate_path(settings["breachCompilationPath"])
    if len(settings["targets"].splitlines()) > 100 or len(settings["urls"].splitlines()) > 10:
        raise ValueError("Use at most 100 initial target lines and 10 URLs per local search.")
    for entry in settings["targets"].splitlines():
        entry = entry.strip()
        if entry.startswith("-"):
            raise ValueError("Targets cannot be CLI options.")
        if entry.startswith(("\\\\", "//")):
            raise ValueError("Network file paths are not supported.")
    if any(entry.startswith("-") or "=" not in entry for entry in settings["apiKeys"]):
        raise ValueError("Use key=value for provider configuration.")
    return settings


def validate_path(entry, file_only=False):
    path = Path(entry)
    if entry.startswith(("\\\\", "//")) or not path.is_absolute() or not path.exists() or (file_only and not path.is_file()):
        raise ValueError("Use existing absolute paths on this computer.")


def stop_process_tree(process):
    if process.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    if process.poll() is None:
        process.kill()


class LocalJobs:
    def __init__(self):
        self.lock = threading.Lock()
        self.jobs = {}
        self.processes = {}

    def start(self, payload):
        settings = validate_settings(payload)
        with self.lock:
            if any(job["status"] == "running" for job in self.jobs.values()):
                raise ValueError("A local search is already running. Cancel it before starting another.")
            self.jobs.clear()
            job_id = uuid.uuid4().hex
            self.jobs[job_id] = {"id": job_id, "status": "running", "results": None, "warnings": []}
        threading.Thread(target=self._execute, args=(job_id, settings), daemon=True).start()
        return self.get(job_id)

    def _execute(self, job_id, settings):
        try:
            with tempfile.TemporaryDirectory(prefix="h8mail-local-") as temporary_directory:
                output_path = Path(temporary_directory) / "result.json"
                options = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {"start_new_session": True}
                environment = {**os.environ, "PYTHONPATH": str(ROOT)}
                process = subprocess.Popen([sys.executable, "-m", "web_adapter.companion_worker", str(output_path)], cwd=temporary_directory, env=environment, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **options)
                with self.lock:
                    self.processes[job_id] = process
                    job = self.jobs.get(job_id)
                    cancelled = not job or job["status"] == "cancelled"
                if cancelled:
                    stop_process_tree(process)
                    process.communicate()
                    return
                try:
                    process.communicate(json.dumps(settings).encode(), timeout=900)
                except subprocess.TimeoutExpired:
                    stop_process_tree(process)
                    process.communicate()
                    self._finish(job_id, {"error": {"code": "timeout", "message": "The local search exceeded 15 minutes. Narrow the search or use the CLI directly."}})
                    return
                if not output_path.is_file() or output_path.stat().st_size > 2 * 1024 * 1024:
                    raise ValueError("Local process did not produce a valid result.")
                self._finish(job_id, json.loads(output_path.read_bytes()))
        except (OSError, ValueError):
            self._finish(job_id, {"error": {"code": "local_engine_failed", "message": "The local engine could not complete the search."}})
        finally:
            with self.lock:
                self.processes.pop(job_id, None)

    def _finish(self, job_id, outcome):
        with self.lock:
            job = self.jobs.get(job_id)
            if job and job["status"] != "cancelled":
                job.update(outcome)
                job["status"] = "error" if "error" in outcome else "completed"

    def get(self, job_id):
        with self.lock:
            job = self.jobs.get(job_id)
            return json.loads(json.dumps(job)) if job else None

    def cancel(self, job_id):
        with self.lock:
            job = self.jobs.get(job_id)
            if not job:
                return None
            if job["status"] == "running":
                job["status"] = "cancelled"
            process = self.processes.get(job_id)
        if process:
            stop_process_tree(process)
        return self.get(job_id)

    def close(self):
        with self.lock:
            job_ids = list(self.jobs)
        for job_id in job_ids:
            self.cancel(job_id)


class LocalHandler(handler):
    def _origin_allowed(self):
        port = self.server.server_port
        hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
        host = self.headers.get("Host", "")
        origin = self.headers.get("Origin")
        site = self.headers.get("Sec-Fetch-Site", "")
        return host in hosts and (not origin or origin in {f"http://{hostname}" for hostname in hosts}) and site not in ("cross-site", "same-site")

    def _authorized(self):
        authorization = self.headers.get("Authorization", "")
        return compare_digest(authorization.encode(), ("Bearer " + self.server.access_token).encode())

    def do_GET(self):
        if not self._origin_allowed():
            self._send(403, {"error": {"code": "blocked_origin", "message": "Use the local application address."}})
            return
        route = self._route()
        if route == "health":
            payload = health()
            payload.update(localCompanion=True, localAccessToken=self.server.access_token)
            payload["capabilities"]["localEngine"] = True
            self._send(200, payload)
        elif route.startswith("local/jobs/"):
            if not self._authorized():
                self._send(401, {"error": {"code": "access_required", "message": "Local access is required."}})
                return
            job = self.server.jobs.get(route.removeprefix("local/jobs/"))
            self._send(200 if job else 404, job or {"error": {"code": "not_found", "message": "The local search was not found."}})
        elif urlsplit(self.path).path.startswith("/api/"):
            super().do_GET()
        else:
            self._serve_static()

    def _serve_static(self):
        root = ROOT / "dist"
        path = (root / unquote(urlsplit(self.path).path).lstrip("/")).resolve()
        if not path.is_relative_to(root.resolve()) or (not path.is_file() and path != root.resolve()):
            self._send(404, {"error": {"code": "not_found", "message": "The file was not found."}})
            return
        if path == root.resolve():
            path = root / "index.html"
        if not path.is_file():
            self._send(503, {"error": {"code": "build_required", "message": "Run npm run build before starting the local application."}})
            return
        content_types = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml"}
        content = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_types.get(path.suffix, "application/octet-stream"))
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; worker-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        try:
            self.wfile.write(content)
        except (BrokenPipeError, ConnectionResetError):
            return

    def do_POST(self):
        if not self._origin_allowed():
            self._send(403, {"error": {"code": "blocked_origin", "message": "Use the local application address."}})
            return
        route = self._route()
        if route not in ("local/run", "local/cancel"):
            super().do_POST()
            return
        if not self._authorized():
            self._send(401, {"error": {"code": "access_required", "message": "Local access is required."}})
            return
        try:
            if self.headers.get("Content-Type", "").split(";", 1)[0] != "application/json" or self.headers.get("Transfer-Encoding"):
                raise ValueError("Send JSON engine options.")
            lengths = self.headers.get_all("Content-Length", [])
            if len(lengths) != 1 or not lengths[0].isdigit() or not 1 <= int(lengths[0]) <= 65536:
                raise ValueError("The local request exceeds 64 KiB or is malformed.")
            payload = json.loads(self.rfile.read(int(lengths[0])))
            if route == "local/run":
                job = self.server.jobs.start(payload)
            else:
                if not isinstance(payload, dict) or set(payload) != {"id"} or not isinstance(payload["id"], str):
                    raise ValueError("Provide the local search identifier.")
                job = self.server.jobs.cancel(payload["id"])
            self._send(200 if job else 404, job or {"error": {"code": "not_found", "message": "The local search was not found."}})
        except (ValueError, UnicodeError) as error:
            self._send(400, {"error": {"code": "invalid_request", "message": str(error)}})


class LocalServer(ThreadingHTTPServer):
    def __init__(self, port, token):
        super().__init__(("127.0.0.1", port), LocalHandler)
        self.access_token = token
        self.jobs = LocalJobs()

    def server_close(self):
        self.jobs.close()
        super().server_close()

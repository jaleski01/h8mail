"""Exercise the real preserved engine and local companion trust boundary."""

from http.client import HTTPConnection
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest

from web_adapter.companion import LocalServer, ROOT, validate_settings
from web_adapter.companion_worker import serialize_targets
from h8mail.utils.classes import target as Target


class CompanionValidationTests(unittest.TestCase):
    def test_rejects_unknown_options_and_cli_injection(self):
        for payload in ({"targets": "example@example.com", "command": "anything"}, {"targets": "  --debug"}, {"targets": "example@example.com", "apiKeys": ["--debug"]}, {"targets": "example@example.com", "localPaths": ["relative-path"]}):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                validate_settings(payload)

    def test_default_settings_preserve_private_local_search(self):
        settings = validate_settings({"targets": "example@example.com"})
        self.assertTrue(settings["hidePasswords"])
        self.assertTrue(settings["skipDefaults"])
        self.assertEqual(settings["chaseLimit"], 0)

    def test_intelx_dump_lines_are_hidden_by_default(self):
        target = Target("example@example.com")
        target.data.append(("INTELX.IO", "dump: example@example.com:synthetic-secret"))
        masked = serialize_targets([target], True)
        self.assertNotIn("synthetic-secret", json.dumps(masked))
        self.assertTrue(masked[0]["data"])
        self.assertIn("synthetic-secret", json.dumps(serialize_targets([target], False)))

    def test_preserved_engine_searches_local_files_and_masks_credentials(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            source = directory / "synthetic-source.txt"
            source.write_text("example@example.com:synthetic-secret\nother@example.org:another-secret\n", encoding="utf-8")
            output = directory / "result.json"
            payload = validate_settings({"targets": "example@example.com", "localPaths": [str(source)], "singleFile": True})
            completed = subprocess.run([sys.executable, "-m", "web_adapter.companion_worker", str(output)], input=json.dumps(payload), text=True, capture_output=True, timeout=15, cwd=directory, env={**os.environ, "PYTHONPATH": str(ROOT)})
            self.assertEqual(completed.returncode, 0)
            outcome = json.loads(output.read_text())
            self.assertNotIn("error", outcome)
            self.assertEqual(outcome["results"]["targets"][0]["target"], "example@example.com")
            self.assertEqual(outcome["results"]["targets"][0]["pwn_num"], 1)
            self.assertTrue(outcome["results"]["targets"][0]["data"])
            self.assertNotIn("synthetic-secret", json.dumps(outcome))
            self.assertEqual(completed.stdout, "")


class CompanionHTTPTests(unittest.TestCase):
    def setUp(self):
        self.server = LocalServer(0, "synthetic-local-access-token")
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(self, path, headers=None):
        connection = HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        try:
            connection.request("GET", path, headers=headers or {})
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def test_cross_origin_bootstrap_is_denied(self):
        status, payload = self.request("/api/health", {"Origin": "https://attacker.example"})
        self.assertEqual(status, 403)
        self.assertNotIn("localAccessToken", payload)

    def test_dns_rebinding_host_is_denied(self):
        status, payload = self.request("/api/health", {"Host": f"attacker.example:{self.server.server_port}"})
        self.assertEqual(status, 403)
        self.assertNotIn("localAccessToken", payload)

    def test_same_origin_bootstrap_returns_ephemeral_local_access(self):
        status, payload = self.request("/api/health")
        self.assertEqual(status, 200)
        self.assertTrue(payload["localCompanion"])
        self.assertEqual(payload["localAccessToken"], "synthetic-local-access-token")

    def test_local_jobs_require_authentication(self):
        status, _ = self.request("/api/local/jobs/not-a-job")
        self.assertEqual(status, 401)


if __name__ == "__main__":
    unittest.main()

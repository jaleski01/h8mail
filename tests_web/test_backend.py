"""Offline boundary and regression tests; never send personal data to providers."""

from contextlib import redirect_stderr
import http.client
from http.server import ThreadingHTTPServer
import io
import json
import os
import subprocess
import threading
import unittest
from unittest.mock import Mock, patch

import requests

from api.index import handler, health
from web_adapter.contracts import MAX_RECORDS, result, validate_request
from web_adapter.engine import run_search
from web_adapter.errors import AdapterError
from web_adapter.executor import execute_search
from web_adapter.providers import PROVIDERS
from web_adapter.transport import MAX_RESPONSE_BYTES, Transport


TOKEN = "synthetic-workspace-token-for-tests"
KEY = "00000000000000000000000000000000"


def search_request(provider="snusbase", query="email", target="analyst@example.test", **options):
    return validate_request({"target": target, "query": query, "provider": provider,
                             "credentials": {"apiKey": KEY}, **options})


class SyntheticResponse(requests.Response):
    def __init__(self, payload=None, status=200, raw=None):
        super().__init__()
        self.status_code = status
        self._content = json.dumps(payload).encode() if raw is None else raw
        self._content_consumed = True

    def iter_content(self, chunk_size):
        for offset in range(0, len(self._content), chunk_size):
            yield self._content[offset:offset + chunk_size]


class ContractTests(unittest.TestCase):
    def test_rejects_unknown_fields_and_nonboolean_privacy_option(self):
        for options in ({"url": "https://example.test"}, {"hidePasswords": "false"}):
            with self.assertRaises(AdapterError):
                search_request(**options)

    def test_rejects_malformed_targets_and_control_characters(self):
        for query, target in (("email", "bad@localhost"), ("ip", "999.0.0.1"),
                              ("domain", "example.test/secret"), ("username", "test\nheader")):
            with self.assertRaises(AdapterError):
                search_request(query=query, target=target)

    def test_normalizes_domain_and_preserves_password_spaces(self):
        self.assertEqual(search_request(target="Analyst@EXAMPLE.TEST").target, "Analyst@example.test")
        self.assertEqual(search_request(query="password", target=" pass word ").target, " pass word ")

    def test_rejects_unsupported_query_and_unavailable_provider(self):
        for provider, query in (("hibp", "domain"), ("scylla", "email")):
            with self.assertRaises(AdapterError):
                search_request(provider=provider, query=query)

    def test_pagination_is_bounded_to_providers_that_support_it(self):
        for payload in (
            {"target": "analyst@example.test", "provider": "snusbase", "page": 2,
             "credentials": {"apiKey": KEY}},
            {"target": "analyst@example.test", "provider": "dehashed", "page": 101,
             "credentials": {"apiKey": KEY}},
            {"target": "analyst@example.test", "provider": "hunter", "page": 2},
            {"target": "analyst@example.test", "provider": "hunter", "page": True,
             "credentials": {"apiKey": KEY}},
        ):
            with self.subTest(payload=payload), self.assertRaises(AdapterError):
                validate_request(payload)

    def test_optional_credentials_and_hibp_format(self):
        request = validate_request({"target": "analyst@example.test", "provider": "hunter"})
        self.assertEqual(request.credentials, {"apiKey": ""})
        for provider in ("hibp", "hibp_pastes", "snusbase"):
            with self.assertRaises(AdapterError):
                validate_request({"target": "analyst@example.test", "provider": provider})
        with self.assertRaises(AdapterError):
            validate_request({"target": "analyst@example.test", "provider": "hibp",
                              "credentials": {"apiKey": "bad"}})

    def test_health_does_not_disclose_configured_access_token(self):
        for token, expected in (("", False), ("short", False), (TOKEN, True)):
            with patch.dict(os.environ, {"H8MAIL_ACCESS_TOKEN": token}):
                metadata = health()
            self.assertEqual(metadata["remoteEnabled"], expected)
            self.assertNotIn(TOKEN, json.dumps(metadata))
            self.assertEqual(metadata["version"], metadata["engine"]["version"])


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.transport = Transport("snusbase")
        self.transport.session.request = Mock(return_value=SyntheticResponse({"size": 0, "results": {}}))

    def tearDown(self):
        self.transport.close()

    def test_blocks_insecure_url_host_port_and_credentials(self):
        for url in ("http://api.snusbase.com/data/search", "https://localhost/data/search",
                    "https://api.snusbase.com.evil.test/data/search",
                    "https://user@api.snusbase.com/data/search", "https://api.snusbase.com:8443/data/search"):
            with self.assertRaises(AdapterError) as raised:
                self.transport.request(url)
            self.assertEqual(raised.exception.code, "transport_blocked")
        self.transport.session.request.assert_not_called()

    def test_enforces_verified_tls_timeout_and_no_redirects(self):
        self.transport.request("https://api.snusbase.com/data/search", "POST", {"Auth": KEY})
        kwargs = self.transport.session.request.call_args.kwargs
        self.assertTrue(kwargs["verify"])
        self.assertFalse(kwargs["allow_redirects"])
        self.assertTrue(kwargs["stream"])
        self.assertEqual(kwargs["timeout"], (4, 8))
        self.assertFalse(self.transport.session.trust_env)

    def test_reports_auth_rate_limit_redirect_and_server_failures(self):
        for status, code in ((401, "invalid_credentials"), (403, "provider_denied"),
                             (429, "rate_limited"), (302, "provider_error"), (503, "provider_error")):
            self.transport.session.request.return_value = SyntheticResponse({"secret": KEY}, status)
            with self.assertRaises(AdapterError) as raised:
                self.transport.request("https://api.snusbase.com/data/search")
            self.assertEqual(raised.exception.code, code)
            self.assertNotIn(KEY, str(raised.exception))

    def test_rejects_oversized_and_malformed_responses(self):
        for raw, code in ((b"x" * (MAX_RESPONSE_BYTES + 1), "response_too_large"),
                          (b"<html>error</html>", "protocol_error")):
            self.transport.session.request.return_value = SyntheticResponse(raw=raw)
            with self.assertRaises(AdapterError) as raised:
                self.transport.request("https://api.snusbase.com/data/search")
            self.assertEqual(raised.exception.code, code)

    def test_reports_network_timeout_without_private_error_details(self):
        self.transport.session.request.side_effect = requests.Timeout("private-target-and-key")
        with self.assertRaises(AdapterError) as raised:
            self.transport.request("https://api.snusbase.com/data/search")
        self.assertEqual(raised.exception.code, "timeout")
        self.assertNotIn("private-target-and-key", str(raised.exception))


class EngineTests(unittest.TestCase):
    def run_provider(self, request, responses):
        transport = Transport(request.provider)
        transport.session.request = Mock(side_effect=responses)
        with patch("h8mail.utils.classes.sleep"):
            response = run_search(request, transport)
        return response, transport.session.request

    def test_hibp_counts_breaches_instead_of_fields(self):
        response, _ = self.run_provider(search_request("hibp"), [
            SyntheticResponse([{"Name": "SyntheticBreach", "Title": "Synthetic breach", "PwnCount": 100}]),
            SyntheticResponse([], 404),
        ])
        self.assertEqual(response["status"], "found")
        self.assertEqual(response["count"], 1)
        self.assertEqual(response["records"], [{"source": "HIBP", "field": "breach", "value": "SyntheticBreach"}])

    def test_hibp_retains_confirmed_breaches_when_optional_paste_request_fails(self):
        response, _ = self.run_provider(search_request("hibp"), [
            SyntheticResponse([{"Name": "SyntheticBreach"}]), SyntheticResponse({}, 429),
        ])
        self.assertEqual(response["status"], "found")
        self.assertEqual(response["count"], 1)
        self.assertEqual(response["warnings"][0]["code"], "rate_limited")

    def test_hibp_retains_confirmed_breaches_with_warning_for_invalid_optional_paste_payload(self):
        response, _ = self.run_provider(search_request("hibp"), [
            SyntheticResponse([{"Name": "SyntheticBreach"}]), SyntheticResponse([{"invalid": True}]),
        ])
        self.assertEqual(response["status"], "found")
        self.assertEqual(response["count"], 1)
        self.assertEqual(response["warnings"][0]["code"], "protocol_error")

    def test_hibp_pastes_can_be_requested_independently(self):
        response, calls = self.run_provider(search_request("hibp_pastes"), [
            SyntheticResponse([{"Source": "SyntheticPaste", "Id": "test-reference"}]),
        ])
        self.assertEqual(response["count"], 1)
        self.assertEqual(calls.call_count, 1)
        self.assertIn("/pasteaccount/", calls.call_args.args[1])

    def test_swallowed_upstream_errors_are_not_clean_results(self):
        for status, code in ((401, "invalid_credentials"), (429, "rate_limited"), (500, "provider_error")):
            response, _ = self.run_provider(search_request("hibp"), [SyntheticResponse({}, status)])
            self.assertEqual(response["status"], "error")
            self.assertEqual(response["error"]["code"], code)
        response, _ = self.run_provider(search_request("hibp"), [SyntheticResponse({"unsupported": True})])
        self.assertEqual(response["status"], "error")
        self.assertEqual(response["error"]["code"], "protocol_error")

    def test_hibp_and_emailrep_404_are_confirmed_empty_results(self):
        for provider in ("hibp", "hibp_pastes", "emailrep"):
            responses = [SyntheticResponse({}, 404)] * (2 if provider == "hibp" else 1)
            response, _ = self.run_provider(search_request(provider), responses)
            self.assertEqual(response["status"], "not_found")

    def test_hibp_queries_pastes_even_if_email_has_no_confirmed_breach(self):
        response, _ = self.run_provider(search_request("hibp"), [
            SyntheticResponse({}, 404), SyntheticResponse([{"Source": "SyntheticPaste", "Id": "only-paste"}]),
        ])
        self.assertEqual(response["status"], "found")
        self.assertEqual(response["count"], 1)
        self.assertEqual(response["records"][0]["field"], "paste")

    def test_emailrep_references_are_not_treated_as_breach_count(self):
        payload = {"reputation": "low", "references": 5, "details": {
            "deliverable": True, "credentials_leaked": True, "profiles": ["synthetic-service"],
            "first_seen": "never", "last_seen": "never", "data_breach": True,
        }}
        response, _ = self.run_provider(search_request("emailrep"), [SyntheticResponse(payload)])
        self.assertEqual(response["count"], 1)
        self.assertIn({"source": "EMAILREP", "field": "references", "value": "5"}, response["records"])

    def test_hunter_public_reports_domain_count_and_private_reports_related_addresses(self):
        public_request = validate_request({"target": "analyst@example.test", "provider": "hunter"})
        response, _ = self.run_provider(public_request, [SyntheticResponse({"data": {"total": 7}})])
        self.assertEqual(response["count"], 7)
        self.assertEqual(response["records"][0]["field"], "domain_email_count")
        response, _ = self.run_provider(search_request("hunter"), [SyntheticResponse({
            "data": {"emails": [{"value": "related@example.test"}]}, "meta": {"results": 3},
        })])
        self.assertEqual(response["count"], 3)
        self.assertFalse(response["hasMore"])
        self.assertEqual(response["records"][0]["value"], "related@example.test")

    def test_hunter_uses_manual_offset_pagination(self):
        request = search_request("hunter", page=3)
        response, calls = self.run_provider(request, [SyntheticResponse({
            "data": {"emails": [{"value": "third-page@example.test"}]}, "meta": {"results": 25},
        })])
        self.assertEqual(calls.call_args.args[0], "GET")
        self.assertEqual(calls.call_args.kwargs["params"], {
            "domain": "example.test", "api_key": KEY, "limit": 10, "offset": 20,
        })
        self.assertEqual(response["page"], 3)
        self.assertEqual(response["count"], 25)
        self.assertFalse(response["hasMore"])

    def test_hunter_reports_more_pages_when_the_current_page_is_full(self):
        request = search_request("hunter", page=2)
        response, _ = self.run_provider(request, [SyntheticResponse({
            "data": {"emails": [{"value": f"page-two-{index}@example.test"} for index in range(10)]},
            "meta": {"results": 25},
        })])
        self.assertTrue(response["hasMore"])
        self.assertEqual(response["total"], 25)

    def test_leaklookup_validates_provider_error_flag_and_preserves_breach_sources(self):
        response, _ = self.run_provider(search_request("leaklookup"), [SyntheticResponse({
            "error": "false", "message": {"SyntheticSource": []},
        })])
        self.assertEqual(response["count"], 1)
        self.assertEqual(response["records"][0]["value"], "SyntheticSource")
        for payload in ({"error": "true", "message": "provider-secret"}, {"error": 0, "message": []}):
            response, _ = self.run_provider(search_request("leaklookup"), [SyntheticResponse(payload)])
            self.assertEqual(response["status"], "error")

    def test_snusbase_uses_modern_contract_and_masks_secrets_before_response(self):
        response, calls = self.run_provider(search_request("snusbase", query="domain", target="example.test"), [
            SyntheticResponse({"size": 1, "results": {"SyntheticSource": [{
                "email": "analyst@example.test", "password": "synthetic-secret", "hash": "synthetic-hash",
            }]}}),
        ])
        self.assertEqual(response["count"], 1)
        self.assertNotIn("synthetic-secret", json.dumps(response))
        self.assertNotIn("synthetic-hash", json.dumps(response))
        self.assertEqual(calls.call_args.kwargs["json"]["types"], ["_domain"])
        self.assertEqual(calls.call_args.kwargs["headers"]["Auth"], KEY)
        self.assertIn("/data/search", calls.call_args.args[1])

    def test_explicit_password_reveal_does_not_change_masking_default(self):
        response, _ = self.run_provider(search_request("snusbase", hidePasswords=False), [
            SyntheticResponse({"size": 1, "results": {"SyntheticSource": [{"password": "synthetic-secret"}]}}),
        ])
        self.assertEqual(response["records"][0]["value"], "synthetic-secret")

    def test_dehashed_uses_v2_auth_and_handles_arrays_and_pagination(self):
        response, calls = self.run_provider(search_request("dehashed", query="ip", target="192.0.2.1"), [
            SyntheticResponse({"total": 3, "entries": [{"database_name": ["SyntheticSource"],
                "email": ["analyst@example.test"], "password": ["synthetic-secret"]}]}),
        ])
        self.assertEqual(response["count"], 3)
        self.assertFalse(response["hasMore"])
        self.assertNotIn("synthetic-secret", json.dumps(response))
        self.assertIn("/v2/search", calls.call_args.args[1])
        self.assertEqual(calls.call_args.kwargs["headers"]["Dehashed-Api-Key"], KEY)
        self.assertEqual(calls.call_args.kwargs["json"]["query"], 'ip_address:"192.0.2.1"')
        self.assertEqual(calls.call_args.kwargs["json"]["size"], 100)

    def test_dehashed_exposes_bounded_page_navigation_and_provider_ceiling(self):
        request = search_request("dehashed", page=2)
        response, calls = self.run_provider(request, [SyntheticResponse({
            "total": 205, "entries": [{"email": "second-page@example.test"}],
        })])
        self.assertEqual(calls.call_args.kwargs["json"]["page"], 2)
        self.assertEqual(response["total"], 205)
        self.assertTrue(response["hasMore"])
        capped, _ = self.run_provider(request, [SyntheticResponse({
            "total": 10_005, "entries": [{"email": "second-page@example.test"}],
        })])
        self.assertTrue(capped["truncated"])
        self.assertTrue(capped["hasMore"])

    def test_breachdirectory_uses_current_rapidapi_contract_and_masks_secrets(self):
        response, calls = self.run_provider(search_request("breachdirectory"), [SyntheticResponse({
            "success": True, "found": 1, "result": [{
                "email": "analyst@example.test", "password": "synthetic-secret",
                "sources": ["SyntheticBreach"],
            }],
        })])
        self.assertEqual(response["count"], 1)
        self.assertNotIn("synthetic-secret", json.dumps(response))
        self.assertEqual(calls.call_args.args[0], "GET")
        self.assertEqual(calls.call_args.args[1], "https://breachdirectory.p.rapidapi.com/")
        self.assertEqual(calls.call_args.kwargs["params"], {"func": "auto", "term": "analyst@example.test"})
        self.assertEqual(calls.call_args.kwargs["headers"]["X-RapidAPI-Key"], KEY)
        self.assertEqual(calls.call_args.kwargs["headers"]["X-RapidAPI-Host"], "breachdirectory.p.rapidapi.com")

    def test_breachdirectory_maps_all_query_types_and_hides_password_and_dehash_output(self):
        for query, target, function, payload in (
            ("username", "analyst", "auto", {"success": True, "found": 0, "result": []}),
            ("domain", "example.test", "domain", {"success": True, "found": 0, "result": []}),
            ("password", "synthetic-secret", "password", {"success": True, "found": 0, "result": []}),
            ("hash", "synthetic-hash", "dehash", {"success": True, "found": 1, "result": "clear-secret"}),
        ):
            with self.subTest(query=query):
                response, calls = self.run_provider(
                    search_request("breachdirectory", query=query, target=target),
                    [SyntheticResponse(payload)],
                )
                self.assertEqual(calls.call_args.kwargs["params"]["func"], function)
                self.assertNotIn("synthetic-secret", json.dumps(response))
                self.assertNotIn("clear-secret", json.dumps(response))
                if query == "password":
                    self.assertEqual(response["target"], "[hidden]")

    def test_breachdirectory_does_not_treat_provider_errors_as_empty_results(self):
        for payload in ({"success": False, "found": 0, "result": []},
                        {"success": True, "found": "0", "result": []}):
            response, _ = self.run_provider(search_request("breachdirectory"), [SyntheticResponse(payload)])
            self.assertEqual(response["status"], "error")
            self.assertEqual(response["error"]["code"], "protocol_error")

    def test_results_are_bounded_and_truncation_is_explicit(self):
        entries = [{"email": "analyst@example.test"}] * (MAX_RECORDS + 10)
        response, _ = self.run_provider(search_request("snusbase"), [
            SyntheticResponse({"size": len(entries), "results": {"SyntheticSource": entries}}),
        ])
        self.assertEqual(len(response["records"]), MAX_RECORDS)
        self.assertTrue(response["truncated"])

    def test_every_enabled_provider_rejects_malformed_success_payloads(self):
        for provider in PROVIDERS:
            if provider["available"] and not provider.get("apiRoute"):
                response, _ = self.run_provider(search_request(provider["id"]), [SyntheticResponse({})])
                self.assertEqual(response["status"], "error", provider["id"])
                self.assertEqual(response["error"]["code"], "protocol_error")

    def test_upstream_update_cannot_bypass_protected_transport(self):
        with patch("web_adapter.engine.invoke", side_effect=lambda *args: requests.get("https://unapproved.example.test")), \
                patch("requests.adapters.HTTPAdapter.send") as outbound:
            response = run_search(search_request())
        self.assertEqual(response["error"]["code"], "transport_blocked")
        outbound.assert_not_called()


class ExecutorTests(unittest.TestCase):
    def test_worker_uses_stdin_and_has_deadline_without_access_token(self):
        request = search_request()
        expected = result(request, [], 0)
        completed = subprocess.CompletedProcess([], 0, json.dumps(expected), "private stderr")
        with patch.dict(os.environ, {"H8MAIL_ACCESS_TOKEN": TOKEN}), patch(
            "web_adapter.executor.subprocess.run", return_value=completed
        ) as execute:
            self.assertEqual(execute_search(request), expected)
        call = execute.call_args
        self.assertNotIn(KEY, " ".join(call.args[0]))
        self.assertNotIn("H8MAIL_ACCESS_TOKEN", call.kwargs["env"])
        self.assertEqual(call.kwargs["timeout"], 25)
        self.assertTrue(call.kwargs["capture_output"])

    def test_timeout_and_malformed_worker_output_fail_safely(self):
        request = search_request()
        with patch("web_adapter.executor.subprocess.run", side_effect=subprocess.TimeoutExpired([], 25)):
            response = execute_search(request)
        self.assertEqual(response["error"]["code"], "timeout")
        with patch("web_adapter.executor.subprocess.run", return_value=subprocess.CompletedProcess([], 0, "{}", "")):
            response = execute_search(request)
        self.assertEqual(response["error"]["code"], "engine_error")

    def test_real_worker_rejects_invalid_input_without_network_or_cli_output(self):
        import sys
        from web_adapter.executor import ROOT

        process = subprocess.run([sys.executable, "-m", "web_adapter.worker"], input="{}",
                                 capture_output=True, text=True, cwd=ROOT, timeout=5, check=True)
        self.assertEqual(json.loads(process.stdout)["error"]["code"], "invalid_request")
        self.assertEqual(process.stderr, "")


class HttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def request(self, method, route, payload=None, token=TOKEN, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        outgoing_headers = {"Content-Type": "application/json", "Authorization": "Bearer " + token}
        outgoing_headers.update(headers or {})
        connection.request(method, route, body=json.dumps(payload) if body is None and payload is not None else body,
                           headers=outgoing_headers)
        response = connection.getresponse()
        encoded = response.read()
        result = response.status, dict(response.headers), json.loads(encoded)
        connection.close()
        return result

    def test_health_and_routes_work_without_access_and_do_not_cache(self):
        with patch.dict(os.environ, {"H8MAIL_ACCESS_TOKEN": ""}):
            status, headers, response = self.request("GET", "/api/health", token="")
            self.assertEqual(status, 200)
            self.assertFalse(response["remoteEnabled"])
            self.assertEqual(headers["Cache-Control"], "no-store, private")
            self.assertEqual(self.request("GET", "/api?route=health")[0], 200)
            self.assertEqual(self.request("GET", "/api/search")[0], 405)
            self.assertEqual(self.request("GET", "/api/missing")[0], 404)

    def test_remote_search_requires_server_configuration_and_bearer_even_on_localhost(self):
        payload = search_request().to_dict()
        with patch.dict(os.environ, {"H8MAIL_ACCESS_TOKEN": ""}):
            self.assertEqual(self.request("POST", "/api/search", payload)[0], 503)
        with patch.dict(os.environ, {"H8MAIL_ACCESS_TOKEN": TOKEN}), patch("api.index.execute_search") as execute:
            self.assertEqual(self.request("POST", "/api/search", payload, token="wrong")[0], 401)
            execute.assert_not_called()

    def test_authorized_request_has_no_sensitive_http_logs(self):
        request = search_request()
        logs = io.StringIO()
        with patch.dict(os.environ, {"H8MAIL_ACCESS_TOKEN": TOKEN}), patch(
            "api.index.execute_search", return_value=result(request, [], 0)
        ), redirect_stderr(logs):
            status, _, response = self.request("POST", "/api/search", request.to_dict())
        self.assertEqual(status, 200)
        self.assertEqual(response["status"], "not_found")
        self.assertEqual(logs.getvalue(), "")

    def test_invalid_input_and_oversized_payload_never_launch_worker(self):
        with patch.dict(os.environ, {"H8MAIL_ACCESS_TOKEN": TOKEN}), patch("api.index.execute_search") as execute:
            for body, expected in (("not-json", 400), ("{}", 400), ("x" * 20_000, 413)):
                self.assertEqual(self.request("POST", "/api/search", body=body)[0], expected)
            execute.assert_not_called()


if __name__ == "__main__":
    unittest.main()

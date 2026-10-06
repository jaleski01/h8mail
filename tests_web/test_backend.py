"""Offline boundary and regression tests; never send personal data to providers."""

from contextlib import redirect_stderr
import hashlib
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

from api.index import app as wsgi_app, handler, health
from web_adapter.contracts import MAX_RECORDS, result, validate_request
from web_adapter.engine import run_pwned_password_search, run_search
from web_adapter.errors import AdapterError
from web_adapter.executor import execute_search
from web_adapter.providers import PROVIDERS, PROVIDER_BY_ID
from web_adapter.transport import MAX_RESPONSE_BYTES, Transport


KEY = "00000000000000000000000000000000"


def search_request(provider="snusbase", query="email", target="analyst@example.test", **options):
    credentials = {field["key"]: field.get("default", KEY)
                   for field in PROVIDER_BY_ID[provider]["credentialFields"]}
    return validate_request({"target": target, "query": query, "provider": provider, **options}, credentials)


def public_search_payload(provider="snusbase", query="email", target="analyst@example.test", **options):
    return {"target": target, "query": query, "provider": provider, **options}


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
            public_search_payload("snusbase", page=2),
            public_search_payload("dehashed", page=101),
            public_search_payload("hunter", page=True),
        ):
            with self.subTest(payload=payload), self.assertRaises(AdapterError):
                validate_request(payload, {"apiKey": KEY})

    def test_provider_credentials_are_server_only_and_required(self):
        free_hunter = validate_request(public_search_payload("hunter"))
        self.assertEqual(free_hunter.credentials, {"apiKey": ""})
        with self.assertRaises(AdapterError):
            validate_request({**public_search_payload("hunter"), "credentials": {"apiKey": KEY}}, {"apiKey": KEY})
        request = validate_request(public_search_payload("hunter"), {"apiKey": KEY})
        self.assertEqual(request.credentials, {"apiKey": KEY})
        for provider in ("hibp", "hibp_pastes", "snusbase"):
            with self.assertRaises(AdapterError):
                validate_request(public_search_payload(provider))
        with self.assertRaises(AdapterError):
            validate_request(public_search_payload("hibp"), {"apiKey": "bad"})

    def test_health_shows_only_provider_key_configuration_booleans(self):
        secret = "secret-provider-key-that-must-never-leak"
        with patch.dict(os.environ, {"SNUSBASE_API_KEY": secret, "HIBP_API_KEY": KEY}):
            metadata = health()
        self.assertTrue(metadata["remoteEnabled"])
        self.assertNotIn(secret, json.dumps(metadata))
        self.assertNotIn(KEY, json.dumps(metadata))
        providers = {entry["id"]: entry for entry in metadata["providers"]}
        self.assertTrue(providers["snusbase"]["credentialFields"][0]["configured"])
        self.assertTrue(providers["hibp"]["credentialFields"][0]["configured"])
        self.assertEqual(providers["hunter"]["freeQueryTypes"], ["email"])
        self.assertEqual(providers["pwnedpasswords"]["freeQueryTypes"], ["password"])
        self.assertTrue(providers["hunter"]["apiDocumentationUrl"].startswith("https://"))
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

    def test_hunter_reports_domain_count_and_related_addresses(self):
        public_request = search_request("hunter")
        response, _ = self.run_provider(public_request, [SyntheticResponse({
            "data": {"emails": []}, "meta": {"results": 7},
        })])
        self.assertEqual(response["count"], 7)
        self.assertEqual(response["records"], [])
        response, _ = self.run_provider(search_request("hunter"), [SyntheticResponse({
            "data": {"emails": [{"value": "related@example.test"}]}, "meta": {"results": 3},
        })])
        self.assertEqual(response["count"], 3)
        self.assertFalse(response["hasMore"])
        self.assertEqual(response["records"][0]["value"], "related@example.test")

    def test_hunter_uses_anonymous_email_insight_without_provider_key(self):
        target = "analyst@example.test"
        request = validate_request(public_search_payload("hunter", target=target))
        response, calls = self.run_provider(request, [SyntheticResponse({"data": {
            "email": target, "gibberish": False, "pattern": True, "mx_records": True,
            "disposable": False, "webmail": True, "webmail_allowed": None,
        }, "meta": {"params": {"email": target}}})])
        self.assertEqual(calls.call_args.args[1], "https://api.hunter.io/v2/email-insight")
        self.assertEqual(calls.call_args.kwargs["params"], {"email": target})
        self.assertEqual(response["status"], "found")
        self.assertEqual(response["count"], 1)
        self.assertEqual(response["records"][0]["field"], "gibberish")
        self.assertIn("does not search breach records", response["notice"])

    def test_pwned_password_lookup_never_sends_the_full_password(self):
        request = validate_request(public_search_payload(
            "pwnedpasswords", query="password", target="password",
        ))
        worker_payload = request.to_dict()
        worker_credentials = worker_payload.pop("credentials")
        self.assertEqual(validate_request(worker_payload, worker_credentials), request)
        transport = Transport(request.provider)
        transport.session.request = Mock(side_effect=[SyntheticResponse(raw=(
                b"1E4C9B93F3F0682250B6CF8331B7EE68FD8:3\r\n"
                b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:0\r\n"
            ))])
        calls = transport.session.request
        with patch("web_adapter.engine.hashlib.sha1", wraps=hashlib.sha1) as sha1:
            response = run_pwned_password_search(request, transport)
        self.assertEqual(len(sha1.call_args_list), 2)
        self.assertTrue(all(call.kwargs["usedforsecurity"] is False for call in sha1.call_args_list))
        url = calls.call_args.args[1]
        self.assertEqual(url, "https://api.pwnedpasswords.com/range/5BAA6")
        self.assertEqual(calls.call_args.kwargs["headers"]["Add-Padding"], "true")
        self.assertEqual(calls.call_args.kwargs["headers"]["User-Agent"], "h8mail-web-adapter")
        self.assertNotIn("password", url.rsplit("/", 1)[-1])
        self.assertEqual(response["status"], "found")
        self.assertEqual(response["records"][0]["value"], "3")
        self.assertEqual(response["target"], "[hidden]")
        self.assertIn("only a padded SHA-1 prefix", response["notice"])

    def test_pwned_password_lookup_reports_absent_password_without_echoing_it(self):
        request = validate_request(public_search_payload(
            "pwnedpasswords", query="password", target="private-candidate",
        ))
        response, _ = self.run_provider(request, [SyntheticResponse(raw=(
            b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:0\r\n"
        ))])
        self.assertEqual(response["status"], "not_found")
        self.assertEqual(response["records"], [])
        self.assertEqual(response["target"], "[hidden]")

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
                query = "password" if "password" in provider["queryTypes"] else "email"
                request = search_request(provider["id"], query=query)
                response, _ = self.run_provider(request, [SyntheticResponse({})])
                self.assertEqual(response["status"], "error", provider["id"])
                self.assertEqual(response["error"]["code"], "protocol_error")

    def test_upstream_update_cannot_bypass_protected_transport(self):
        with patch("web_adapter.engine.invoke", side_effect=lambda *args: requests.get("https://unapproved.example.test")), \
                patch("requests.adapters.HTTPAdapter.send") as outbound:
            response = run_search(search_request())
        self.assertEqual(response["error"]["code"], "transport_blocked")
        outbound.assert_not_called()


class ExecutorTests(unittest.TestCase):
    def test_pwned_passwords_uses_its_bounded_transport_without_a_worker(self):
        request = search_request("pwnedpasswords", query="password", target="password")
        expected = result(request, [], 0)
        with patch("web_adapter.executor.run_pwned_password_search", return_value=expected) as lookup, \
                patch("web_adapter.executor.subprocess.run") as worker:
            self.assertEqual(execute_search(request), expected)
        lookup.assert_called_once_with(request)
        worker.assert_not_called()

    def test_worker_uses_stdin_and_does_not_inherit_provider_keys(self):
        request = search_request()
        expected = result(request, [], 0)
        completed = subprocess.CompletedProcess([], 0, json.dumps(expected), "private stderr")
        with patch.dict(os.environ, {"H8MAIL_ACCESS_TOKEN": "local-only-token",
                                    "SNUSBASE_API_KEY": KEY, "HIBP_API_KEY": KEY}), patch(
            "web_adapter.executor.subprocess.run", return_value=completed
        ) as execute:
            self.assertEqual(execute_search(request), expected)
        call = execute.call_args
        self.assertNotIn(KEY, " ".join(call.args[0]))
        self.assertNotIn("SNUSBASE_API_KEY", call.kwargs["env"])
        self.assertNotIn("HIBP_API_KEY", call.kwargs["env"])
        self.assertNotIn("H8MAIL_ACCESS_TOKEN", call.kwargs["env"])
        self.assertIn(KEY, call.kwargs["input"])
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

    def request(self, method, route, payload=None, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        outgoing_headers = {"Content-Type": "application/json"}
        outgoing_headers.update(headers or {})
        connection.request(method, route, body=json.dumps(payload) if body is None and payload is not None else body,
                           headers=outgoing_headers)
        response = connection.getresponse()
        encoded = response.read()
        result = response.status, dict(response.headers), json.loads(encoded)
        connection.close()
        return result

    def test_health_and_routes_work_without_shared_access_key_and_do_not_cache(self):
        status, headers, response = self.request("GET", "/api/health")
        self.assertEqual(status, 200)
        self.assertTrue(response["remoteEnabled"])
        self.assertEqual(headers["Cache-Control"], "no-store, private")
        self.assertEqual(self.request("GET", "/api?route=health")[0], 200)
        self.assertEqual(self.request("GET", "/api/search")[0], 405)
        self.assertEqual(self.request("GET", "/api/missing")[0], 404)

    def test_remote_search_uses_server_provider_key_without_visitor_token(self):
        request = search_request()
        payload = public_search_payload()
        with patch.dict(os.environ, {"SNUSBASE_API_KEY": KEY}), patch(
            "api.index.execute_search", return_value=result(request, [], 0)
        ) as execute:
            status, _, response = self.request("POST", "/api/search", payload)
        self.assertEqual(status, 200)
        self.assertEqual(response["status"], "not_found")
        self.assertEqual(execute.call_args.args[0].credentials["apiKey"], KEY)

    def test_remote_search_without_provider_key_returns_clear_error_and_never_starts_worker(self):
        with patch.dict(os.environ, {"SNUSBASE_API_KEY": ""}), patch("api.index.execute_search") as execute:
            status, _, response = self.request("POST", "/api/search", public_search_payload())
        self.assertEqual(status, 400)
        self.assertEqual(response["error"]["code"], "provider_not_configured")
        execute.assert_not_called()

    def test_provider_errors_are_logged_without_query_or_credentials(self):
        secret_target = "private-target@example.test"
        request = search_request(target=secret_target)
        logs = io.StringIO()
        with patch.dict(os.environ, {"SNUSBASE_API_KEY": KEY}), patch(
            "api.index.execute_search", return_value=result(request, [], 0)
        ), redirect_stderr(logs):
            status, _, response = self.request("POST", "/api/search", public_search_payload(target=secret_target))
            self.assertEqual(status, 200)
            error_response = result(request, [], 0, "provider_error")
            with patch("api.index.execute_search", return_value=error_response):
                status, _, response = self.request("POST", "/api/search", public_search_payload(target=secret_target))
        self.assertEqual(status, 200)
        self.assertEqual(response["status"], "error")
        self.assertIn('"event":"api_error"', logs.getvalue())
        self.assertIn('"provider":"snusbase"', logs.getvalue())
        self.assertNotIn(secret_target, logs.getvalue())
        self.assertNotIn(KEY, logs.getvalue())

    def test_browser_exceptions_are_logged_without_client_details(self):
        logs = io.StringIO()
        with redirect_stderr(logs):
            status, _, response = self.request("POST", "/api/client-error", {
                "type": "unhandled_rejection", "route": "app",
            })
        self.assertEqual(status, 202)
        self.assertEqual(response, {"accepted": True})
        self.assertIn('"event":"client_error"', logs.getvalue())
        self.assertIn('"type":"unhandled_rejection"', logs.getvalue())
        self.assertNotIn("target", logs.getvalue())
        self.assertNotIn("stack", logs.getvalue())

    def test_browser_provider_request_errors_are_logged_without_lookup_data(self):
        logs = io.StringIO()
        with redirect_stderr(logs):
            status, _, response = self.request("POST", "/api/client-error", {
                "type": "provider_lookup_error", "route": "app", "provider": "hunter",
            })
        self.assertEqual(status, 202)
        self.assertEqual(response, {"accepted": True})
        self.assertIn('"event":"client_error"', logs.getvalue())
        self.assertIn('"code":"provider_request_failed"', logs.getvalue())
        self.assertIn('"provider":"hunter"', logs.getvalue())
        self.assertNotIn("target", logs.getvalue())
        self.assertNotIn("example", logs.getvalue())

    def test_browser_error_endpoint_rejects_unbounded_client_fields(self):
        with patch("api.index.LOGGER.error") as log_error:
            status, _, response = self.request("POST", "/api/client-error", {
                "type": "uncaught_exception", "route": "app", "message": "private@example.test",
            })
        self.assertEqual(status, 400)
        self.assertEqual(response["error"]["code"], "invalid_request")
        self.assertEqual(log_error.call_count, 1)
        self.assertNotIn("private@example.test", log_error.call_args.args[0])

    def test_invalid_input_and_oversized_payload_never_launch_worker(self):
        with patch.dict(os.environ, {"SNUSBASE_API_KEY": KEY}), patch("api.index.execute_search") as execute:
            for body, expected in (("not-json", 400), ("{}", 400), ("x" * 20_000, 413)):
                self.assertEqual(self.request("POST", "/api/search", body=body)[0], expected)
            execute.assert_not_called()


class WsgiTests(unittest.TestCase):
    def request(self, method, path, payload=None):
        body = json.dumps(payload).encode("utf-8") if payload is not None else b""
        environ = {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "QUERY_STRING": "",
            "CONTENT_TYPE": "application/json" if payload is not None else "",
            "CONTENT_LENGTH": str(len(body)) if payload is not None else "",
            "wsgi.input": io.BytesIO(body),
        }
        captured = {}

        def start_response(status, headers):
            captured["status"] = status
            captured["headers"] = dict(headers)

        response = b"".join(wsgi_app(environ, start_response))
        return int(captured["status"].split(" ", 1)[0]), captured["headers"], json.loads(response)

    def test_wsgi_health_returns_uncached_json_without_access_key(self):
        status, headers, payload = self.request("GET", "/api/health")
        self.assertEqual(status, 200)
        self.assertTrue(payload["remoteEnabled"])
        self.assertEqual(headers["Cache-Control"], "no-store, private")

    def test_wsgi_search_uses_server_key_and_no_visitor_token(self):
        request = search_request()
        payload = result(request, [], 0)
        with patch.dict(os.environ, {"SNUSBASE_API_KEY": KEY}), patch(
            "api.index.execute_search", return_value=payload
        ) as execute:
            status, _, response = self.request("POST", "/api/search", public_search_payload())
        self.assertEqual(status, 200)
        self.assertEqual(response, payload)
        execute.assert_called_once()


if __name__ == "__main__":
    unittest.main()

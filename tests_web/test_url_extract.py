"""URL extraction tests use synthetic pages and never contact a real target."""

import socket
import unittest
from unittest.mock import MagicMock, patch

from web_adapter.url_extract import UrlExtractionError, extract_page, public_addresses, validate_url


class UrlExtractionTests(unittest.TestCase):
    def test_rejects_non_https_and_credentials(self):
        for url in ("http://example.com", "https://user:secret@example.com", "https://example.com:8443", "https://example.com\r\nInjected:yes"):
            with self.subTest(url=url), self.assertRaises(UrlExtractionError):
                validate_url(url)

    def test_rejects_private_and_mixed_dns_answers(self):
        for address in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "::ffff:8.8.8.8"):
            answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)), (socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443))]
            with self.subTest(address=address), patch("socket.getaddrinfo", return_value=answers), self.assertRaises(UrlExtractionError):
                public_addresses("example.com")

    @patch("web_adapter.url_extract.PinnedHTTPSConnection")
    @patch("web_adapter.url_extract.public_addresses", return_value=["8.8.8.8"])
    def test_extracts_deduplicated_emails_from_html(self, dns_mock, connection_mock):
        response = MagicMock(status=200)
        response.getheader.side_effect = lambda name, default=None: {"Content-Type": "text/html", "Content-Encoding": "identity"}.get(name, default)
        response.read.return_value = b"<p>Alice@example.com alice@example.com &lt;bob@example.org&gt;</p>"
        connection_mock.return_value.getresponse.return_value = response
        self.assertEqual(extract_page("https://example.com")["emails"], ["alice@example.com", "bob@example.org"])
        connection_mock.assert_called_once_with("example.com", "8.8.8.8")
        connection_mock.return_value.close.assert_called_once()

    @patch("web_adapter.url_extract.PinnedHTTPSConnection")
    @patch("web_adapter.url_extract.public_addresses")
    def test_redirect_to_private_address_is_checked_before_connection(self, dns_mock, connection_mock):
        dns_mock.side_effect = [["8.8.8.8"], UrlExtractionError("blocked_address", "Blocked")]
        response = MagicMock(status=302)
        response.getheader.return_value = "https://127.0.0.1/admin"
        connection_mock.return_value.getresponse.return_value = response
        with self.assertRaises(UrlExtractionError):
            extract_page("https://example.com")
        self.assertEqual(connection_mock.call_count, 1)


if __name__ == "__main__":
    unittest.main()

import io
import json
import unittest
from argparse import Namespace
from unittest.mock import MagicMock, patch

import cert_recon
import rclib


class CertificateReconTests(unittest.TestCase):
    def make_context(self, target):
        return rclib.Context(Namespace(), "cert-recon", target)

    def response(self, body):
        response = MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = body
        return response

    def test_normalize_domain_validates_and_normalizes(self):
        self.assertEqual(cert_recon.normalize_domain("Exämple.COM."), "xn--exmple-cua.com")
        for target in ("", "example.com/path", "*.example.com", "example.com:443",
                       "example", "bad..example.com", "-bad.example.com", "127.0.0.1"):
            with self.subTest(target=target):
                with self.assertRaises(ValueError):
                    cert_recon.normalize_domain(target)

    @patch("cert_recon.urllib.request.urlopen")
    def test_run_returns_only_exact_domain_suffixes_with_source_evidence(self, urlopen):
        urlopen.return_value = self.response(
            json.dumps(
                [
                    {"name_value": "*.api.example.com\nexample.com"},
                    {"name_value": "notexample.com\nunrelated.org"},
                    {"name_value": "bad..example.com"},
                ]
            ).encode()
        )
        ctx = self.make_context("Example.com")

        with patch("sys.stdout", new_callable=io.StringIO):
            self.assertEqual(cert_recon.run(ctx), 0)

        self.assertEqual(ctx.data["subdomains"], ["api.example.com", "example.com"])
        self.assertEqual(ctx.data["source"], cert_recon.SOURCE)
        self.assertIn("not DNS-verified", ctx.data["evidence"])
        self.assertEqual(ctx.data["certificates_examined"], 3)
        self.assertEqual(ctx.data["certificates_returned"], 3)
        request, = urlopen.call_args.args
        self.assertIn("q=%25.example.com", request.full_url)
        self.assertEqual(urlopen.call_args.kwargs["timeout"], cert_recon.REQUEST_TIMEOUT_SECONDS)

    @patch("cert_recon.urllib.request.urlopen")
    def test_invalid_target_does_not_make_network_request(self, urlopen):
        with patch("sys.stderr", new_callable=io.StringIO):
            self.assertEqual(cert_recon.run(self.make_context("https://example.com")), 2)
        urlopen.assert_not_called()

    @patch("cert_recon.urllib.request.urlopen")
    def test_response_size_is_bounded(self, urlopen):
        urlopen.return_value = self.response(b" " * (cert_recon.MAX_RESPONSE_BYTES + 1))
        ctx = self.make_context("example.com")
        with patch("sys.stderr", new_callable=io.StringIO) as stderr:
            self.assertEqual(cert_recon.run(ctx), 1)
        self.assertIn("5 MiB limit", stderr.getvalue())
        self.assertEqual(ctx.data, {})

    @patch("cert_recon.urllib.request.urlopen")
    def test_name_candidate_processing_is_bounded_and_marked_incomplete(self, urlopen):
        urlopen.return_value = self.response(
            json.dumps([{"name_value": "a.example.com\nb.example.com"}]).encode()
        )
        ctx = self.make_context("example.com")
        with patch.object(cert_recon, "MAX_NAME_CANDIDATES", 1):
            with patch("sys.stdout", new_callable=io.StringIO):
                self.assertEqual(cert_recon.run(ctx), 0)
        self.assertEqual(ctx.data["subdomains"], ["a.example.com"])
        self.assertEqual(ctx.data["name_candidates_examined"], 1)
        self.assertEqual(ctx.data["certificates_examined"], 1)
        self.assertEqual(ctx.data["certificates_returned"], 1)
        self.assertTrue(ctx.data["candidate_limit_reached"])
        self.assertTrue(ctx.data["results_truncated"])

    @patch("cert_recon.urllib.request.urlopen")
    def test_certificate_count_reports_only_records_examined_before_candidate_cap(self, urlopen):
        urlopen.return_value = self.response(
            json.dumps(
                [
                    {"name_value": "a.example.com\nb.example.com"},
                    {"name_value": "c.example.com"},
                ]
            ).encode()
        )
        ctx = self.make_context("example.com")
        with patch.object(cert_recon, "MAX_NAME_CANDIDATES", 1):
            with patch("sys.stdout", new_callable=io.StringIO):
                self.assertEqual(cert_recon.run(ctx), 0)
        self.assertEqual(ctx.data["certificates_examined"], 1)
        self.assertEqual(ctx.data["certificates_returned"], 2)
        self.assertEqual(ctx.data["name_candidates_examined"], 1)
        self.assertTrue(ctx.data["candidate_limit_reached"])

    @patch("cert_recon.urllib.request.urlopen")
    def test_http_failure_is_reported_without_exception_details(self, urlopen):
        from urllib.error import HTTPError

        urlopen.side_effect = HTTPError(
            "https://crt.sh/?q=%.private.example", 503, "unavailable", {}, None
        )
        with patch("sys.stderr", new_callable=io.StringIO) as stderr:
            self.assertEqual(cert_recon.run(self.make_context("private.example")), 1)
        self.assertIn("HTTP status 503", stderr.getvalue())
        self.assertNotIn("private.example", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()

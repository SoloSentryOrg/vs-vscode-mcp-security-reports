#!/usr/bin/env python3

from __future__ import annotations

import socket
import tempfile
import unittest
import zipfile
from pathlib import Path
from ssl import SSLCertVerificationError

from check_external_links import (
    ProbeResult,
    collect_report_links,
    display_url,
    probe_url,
    probe_with_retries,
    resolve_public_addresses,
    select_current_reports,
)
from validate_public_reports import ValidationError

RELATIONSHIPS = """\
<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink"
    Target="{target}" TargetMode="External"/>
</Relationships>
"""


def public_resolver(
    hostname: str, port: int, *, type: object
) -> list[tuple[object, ...]]:
    del hostname, port, type
    return [(None, None, None, None, ("93.184.216.34", 443))]


def private_resolver(
    hostname: str, port: int, *, type: object
) -> list[tuple[object, ...]]:
    del hostname, port, type
    return [(None, None, None, None, ("10.0.0.7", 443))]


def missing_domain_resolver(
    hostname: str, port: int, *, type: object
) -> list[tuple[object, ...]]:
    del hostname, port, type
    raise socket.gaierror(socket.EAI_NONAME, "name not known")


def temporary_dns_failure_resolver(
    hostname: str, port: int, *, type: object
) -> list[tuple[object, ...]]:
    del hostname, port, type
    raise socket.gaierror(socket.EAI_AGAIN, "temporary failure")


class FakeResponse:
    def __init__(self, status: int = 200, location: str | None = None) -> None:
        self.status = status
        self.location = location

    def getheader(self, name: str) -> str | None:
        if name == "Location":
            return self.location
        return None


class FakeConnection:
    def __init__(
        self,
        response: FakeResponse,
        request_error: Exception | None = None,
    ) -> None:
        self.response = response
        self.request_error = request_error

    def request(
        self,
        method: str,
        target: str,
        *,
        headers: dict[str, str],
    ) -> None:
        del method, target, headers
        if self.request_error is not None:
            raise self.request_error

    def getresponse(self) -> FakeResponse:
        return self.response

    def close(self) -> None:
        return None


def fake_connection_factory(
    hostname: str,
    address: str,
    port: int,
    timeout: float,
) -> FakeConnection:
    del hostname, address, port, timeout
    return FakeConnection(FakeResponse())


class ExternalLinkMonitorTests(unittest.TestCase):
    def test_select_current_reports_uses_latest_report_version(self) -> None:
        reports = [
            self._report("PostgreSQL", "1.26.0", "2026-07-29", "1.0"),
            self._report("PostgreSQL", "1.26.0", "2026-07-29", "1.1"),
        ]
        self.assertEqual(
            [record["report_version"] for record in select_current_reports(reports)],
            ["1.1"],
        )

    def test_select_current_reports_prefers_newer_assessment_date(self) -> None:
        reports = [
            self._report("Example", "1.0.0", "2026-07-29", "9.9"),
            self._report("Example", "1.0.0", "2026-07-30", "1.0"),
        ]
        self.assertEqual(
            [record["assessment_date"] for record in select_current_reports(reports)],
            ["2026-07-30"],
        )

    def test_select_current_reports_keeps_distinct_targets(self) -> None:
        reports = [
            self._report("Example", "1.0.0", "2026-07-29", "1.0"),
            self._report("Example", "2.0.0", "2026-07-29", "1.0"),
        ]
        self.assertEqual(len(select_current_reports(reports)), 2)

    def test_select_current_reports_rejects_ambiguous_rank(self) -> None:
        reports = [
            self._report("Example", "1.0.0", "2026-07-29", "1.0", "one"),
            self._report("Example", "1.0.0", "2026-07-29", "1.0", "two"),
        ]
        with self.assertRaises(ValidationError):
            select_current_reports(reports)

    def test_select_current_reports_rejects_malformed_record(self) -> None:
        with self.assertRaises(ValidationError):
            select_current_reports([{"assessment": "Example"}])

    def test_select_current_reports_rejects_noncanonical_date(self) -> None:
        reports = [
            self._report("Example", "1.0.0", "20260729", "1.0"),
        ]
        with self.assertRaises(ValidationError):
            select_current_reports(reports)

    @staticmethod
    def _report(
        assessment: str,
        target_version: str,
        assessment_date: str,
        report_version: str,
        suffix: str = "report",
    ) -> dict[str, object]:
        return {
            "assessment": assessment,
            "target_version": target_version,
            "assessment_date": assessment_date,
            "report_version": report_version,
            "path": f"reports/{assessment}/{suffix}.docx",
        }

    def test_display_url_removes_query_and_fragment(self) -> None:
        self.assertEqual(
            display_url("https://docs.github.com/path?token=value#section"),
            "https://docs.github.com/path",
        )

    def test_collect_report_links_requires_reviewed_host(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.docx"
            with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as package:
                package.writestr(
                    "word/_rels/document.xml.rels",
                    RELATIONSHIPS.format(
                        target="https://docs.github.com/example"
                    ),
                )
            self.assertEqual(
                collect_report_links(path, {"docs.github.com"}),
                {"https://docs.github.com/example"},
            )
            with self.assertRaises(ValidationError):
                collect_report_links(path, {"learn.microsoft.com"})

    def test_collect_report_links_rejects_malformed_xml(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.docx"
            with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as package:
                package.writestr(
                    "word/_rels/document.xml.rels",
                    b"<Relationships><Relationship",
                )
            with self.assertRaises(ValidationError):
                collect_report_links(path, {"docs.github.com"})

    def test_probe_url_accepts_success(self) -> None:
        value = "https://docs.github.com/example"
        result = probe_url(
            value,
            {"docs.github.com"},
            1,
            resolver=public_resolver,
            connection_factory=fake_connection_factory,
        )
        self.assertEqual(result, ProbeResult(value, "pass", "HTTP 200"))

    def test_probe_url_marks_access_or_method_restriction_indeterminate(
        self,
    ) -> None:
        value = "https://docs.github.com/example"
        for status in (401, 403, 405, 416, 429):
            with self.subTest(status=status):
                result = probe_url(
                    value,
                    {"docs.github.com"},
                    1,
                    resolver=public_resolver,
                    connection_factory=lambda *args, code=status: FakeConnection(
                        FakeResponse(status=code)
                    ),
                )
                self.assertEqual(
                    result,
                    ProbeResult(value, "indeterminate", f"HTTP {status}"),
                )

    def test_probe_url_marks_timeout_retryable(self) -> None:
        value = "https://docs.github.com/example"
        result = probe_url(
            value,
            {"docs.github.com"},
            1,
            resolver=public_resolver,
            connection_factory=lambda *args: FakeConnection(
                FakeResponse(),
                TimeoutError("read timed out"),
            ),
        )
        self.assertEqual(result.outcome, "indeterminate")
        self.assertTrue(result.retryable)
        self.assertIn("HTTPS connection failed", result.detail)

    def test_probe_url_rejects_certificate_validation_failure(self) -> None:
        value = "https://docs.github.com/example"
        result = probe_url(
            value,
            {"docs.github.com"},
            1,
            resolver=public_resolver,
            connection_factory=lambda *args: FakeConnection(
                FakeResponse(),
                SSLCertVerificationError("certificate verify failed"),
            ),
        )
        self.assertEqual(result.outcome, "fail")
        self.assertFalse(result.retryable)
        self.assertIn("TLS certificate validation failed", result.detail)

    def test_probe_url_marks_server_error_retryable(self) -> None:
        value = "https://docs.github.com/example"
        result = probe_url(
            value,
            {"docs.github.com"},
            1,
            resolver=public_resolver,
            connection_factory=lambda *args: FakeConnection(
                FakeResponse(status=503)
            ),
        )
        self.assertEqual(
            result,
            ProbeResult(value, "indeterminate", "HTTP 503", retryable=True),
        )

    def test_probe_url_keeps_missing_resources_terminal(self) -> None:
        value = "https://docs.github.com/example"
        for status in (404, 410):
            with self.subTest(status=status):
                result = probe_url(
                    value,
                    {"docs.github.com"},
                    1,
                    resolver=public_resolver,
                    connection_factory=lambda *args, code=status: FakeConnection(
                        FakeResponse(status=code)
                    ),
                )
                self.assertEqual(
                    result,
                    ProbeResult(value, "fail", f"HTTP {status}"),
                )

    def test_probe_with_retries_recovers_from_transient_failure(self) -> None:
        value = "https://docs.github.com/example"
        attempts = 0

        def recovering_probe(
            probe_value: str,
            allowed_hosts: set[str],
            timeout: float,
        ) -> ProbeResult:
            nonlocal attempts
            del allowed_hosts, timeout
            attempts += 1
            if attempts == 1:
                return ProbeResult(
                    probe_value,
                    "indeterminate",
                    "temporary timeout",
                    retryable=True,
                )
            return ProbeResult(probe_value, "pass", "HTTP 200")

        result = probe_with_retries(
            value,
            {"docs.github.com"},
            1,
            1,
            probe=recovering_probe,
        )
        self.assertEqual(result, ProbeResult(value, "pass", "HTTP 200"))
        self.assertEqual(attempts, 2)

    def test_probe_with_retries_warns_after_exhaustion(self) -> None:
        value = "https://docs.github.com/example"
        attempts = 0

        def transient_probe(
            probe_value: str,
            allowed_hosts: set[str],
            timeout: float,
        ) -> ProbeResult:
            nonlocal attempts
            del allowed_hosts, timeout
            attempts += 1
            return ProbeResult(
                probe_value,
                "indeterminate",
                "temporary timeout",
                retryable=True,
            )

        result = probe_with_retries(
            value,
            {"docs.github.com"},
            1,
            2,
            probe=transient_probe,
        )
        self.assertEqual(
            result,
            ProbeResult(value, "indeterminate", "temporary timeout"),
        )
        self.assertEqual(attempts, 3)

    def test_probe_url_rejects_private_dns(self) -> None:
        value = "https://docs.github.com/example"
        result = probe_url(
            value,
            {"docs.github.com"},
            1,
            resolver=private_resolver,
            connection_factory=fake_connection_factory,
        )
        self.assertEqual(result.outcome, "fail")
        self.assertIn("non-public DNS address", result.detail)

    def test_probe_url_rejects_permanent_dns_failure(self) -> None:
        value = "https://docs.github.com/example"
        result = probe_url(
            value,
            {"docs.github.com"},
            1,
            resolver=missing_domain_resolver,
            connection_factory=fake_connection_factory,
        )
        self.assertEqual(result.outcome, "fail")
        self.assertFalse(result.retryable)
        self.assertIn("DNS resolution failed", result.detail)

    def test_probe_url_marks_temporary_dns_failure_retryable(self) -> None:
        value = "https://docs.github.com/example"
        result = probe_url(
            value,
            {"docs.github.com"},
            1,
            resolver=temporary_dns_failure_resolver,
            connection_factory=fake_connection_factory,
        )
        self.assertEqual(result.outcome, "indeterminate")
        self.assertTrue(result.retryable)
        self.assertIn("DNS resolution failed", result.detail)

    def test_probe_url_rejects_unreviewed_host_before_request(self) -> None:
        value = "https://attacker.invalid/example"
        result = probe_url(
            value,
            {"docs.github.com"},
            1,
            resolver=public_resolver,
            connection_factory=fake_connection_factory,
        )
        self.assertEqual(result.outcome, "fail")
        self.assertIn("unsafe or unreviewed", result.detail)

    def test_validated_address_is_bound_to_connection(self) -> None:
        value = "https://docs.github.com/example"
        addresses: list[str] = []

        def recording_factory(
            hostname: str,
            address: str,
            port: int,
            timeout: float,
        ) -> FakeConnection:
            del hostname, port, timeout
            addresses.append(address)
            return FakeConnection(FakeResponse())

        result = probe_url(
            value,
            {"docs.github.com"},
            1,
            resolver=public_resolver,
            connection_factory=recording_factory,
        )
        self.assertEqual(result.outcome, "pass")
        self.assertEqual(addresses, ["93.184.216.34"])

    def test_redirect_to_unreviewed_host_is_rejected(self) -> None:
        value = "https://docs.github.com/example"
        result = probe_url(
            value,
            {"docs.github.com"},
            1,
            resolver=public_resolver,
            connection_factory=lambda *args: FakeConnection(
                FakeResponse(
                    status=302,
                    location="https://attacker.invalid/redirect",
                )
            ),
        )
        self.assertEqual(result.outcome, "fail")
        self.assertIn("unsafe or unreviewed", result.detail)

    def test_resolve_public_addresses_rejects_private_dns(self) -> None:
        with self.assertRaises(ValidationError):
            resolve_public_addresses(
                "https://docs.github.com/example",
                private_resolver,
            )


if __name__ == "__main__":
    unittest.main()

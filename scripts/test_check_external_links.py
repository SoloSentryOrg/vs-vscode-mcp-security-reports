#!/usr/bin/env python3

from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path

from check_external_links import (
    ProbeResult,
    collect_report_links,
    display_url,
    probe_url,
    resolve_public_addresses,
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


class FakeResponse:
    def __init__(self, status: int = 200, location: str | None = None) -> None:
        self.status = status
        self.location = location

    def getheader(self, name: str) -> str | None:
        if name == "Location":
            return self.location
        return None


class FakeConnection:
    def __init__(self, response: FakeResponse) -> None:
        self.response = response

    def request(
        self,
        method: str,
        target: str,
        *,
        headers: dict[str, str],
    ) -> None:
        del method, target, headers

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

    def test_probe_url_marks_access_control_indeterminate(self) -> None:
        value = "https://docs.github.com/example"
        result = probe_url(
            value,
            {"docs.github.com"},
            1,
            resolver=public_resolver,
            connection_factory=lambda *args: FakeConnection(
                FakeResponse(status=403)
            ),
        )
        self.assertEqual(
            result,
            ProbeResult(value, "indeterminate", "HTTP 403"),
        )

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

#!/usr/bin/env python3

from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from validate_public_reports import (
    allowlist_publication_conflict,
    external_target_is_safe,
    safe_relative,
    validate_allowlist_change_separation,
    validate_docx,
)

CONTENT_TYPES = """\
<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="xml" ContentType="application/xml"/>
</Types>
"""
DOCUMENT = """\
<?xml version="1.0" encoding="UTF-8"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:tbl><w:tr>
      <w:tc><w:p><w:r><w:t>Classification</w:t></w:r></w:p></w:tc>
      <w:tc><w:p><w:r><w:t>PUBLIC</w:t></w:r></w:p></w:tc>
    </w:tr></w:tbl>
  </w:body>
</w:document>
"""
DOCUMENT_WITH_ENTITY = """\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE w:document [
  <!ENTITY private "not-public">
]>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body><w:p><w:r><w:t>&private;</w:t></w:r></w:p></w:body>
</w:document>
"""
RELATIONSHIPS = """\
<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink"
    Target="http://example.com/report" TargetMode="External"/>
</Relationships>
"""
CORE = """\
<?xml version="1.0" encoding="UTF-8"?>
<cp:coreProperties
 xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
 xmlns:dc="http://purl.org/dc/elements/1.1/">
  <dc:creator>SoloSentry Assessment Environment</dc:creator>
  <cp:lastModifiedBy>SoloSentry Assessment Environment</cp:lastModifiedBy>
</cp:coreProperties>
"""


def write_docx(
    path: Path,
    *,
    creator: str = "SoloSentry Assessment Environment",
    document: str = DOCUMENT,
    macro: bool = False,
    relationships: str | None = None,
) -> None:
    core = CORE.replace(
        "SoloSentry Assessment Environment",
        creator,
    )
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as package:
        package.writestr("[Content_Types].xml", CONTENT_TYPES)
        package.writestr("word/document.xml", document)
        package.writestr("docProps/core.xml", core)
        if relationships is not None:
            package.writestr("word/_rels/document.xml.rels", relationships)
        if macro:
            package.writestr("word/vbaProject.bin", b"not-a-real-macro")


class PublicReportValidationTests(unittest.TestCase):
    def test_allowlist_and_report_changes_must_be_separate(self) -> None:
        self.assertTrue(
            allowlist_publication_conflict(
                {
                    "scripts/allowed-hyperlink-hosts.json",
                    "reports/New/report.docx",
                }
            )
        )
        self.assertTrue(
            allowlist_publication_conflict(
                {
                    "scripts/allowed-docx-custom-xml.json",
                    "reports/index.json",
                }
            )
        )
        self.assertFalse(
            allowlist_publication_conflict(
                {"scripts/allowed-hyperlink-hosts.json", "README.md"}
            )
        )

    def test_pull_request_without_base_sha_fails_closed(self) -> None:
        with patch.dict(
            "os.environ",
            {"GITHUB_EVENT_NAME": "pull_request", "REPORT_BASE_SHA": ""},
            clear=False,
        ):
            self.assertIn(
                "REPORT_BASE_SHA is required for pull-request allowlist review",
                validate_allowlist_change_separation(),
            )

    def test_safe_relative_rejects_escape_and_backslash(self) -> None:
        for value in ("../private.docx", "/tmp/private.docx", r"reports\\bad.docx"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    safe_relative(value)

    def test_external_target_requires_public_https(self) -> None:
        allowed = {"docs.github.com"}
        self.assertTrue(
            external_target_is_safe("https://docs.github.com/report", allowed)
        )
        self.assertFalse(external_target_is_safe("https://example.com/report", allowed))
        self.assertFalse(
            external_target_is_safe("http://docs.github.com/report", allowed)
        )
        self.assertFalse(external_target_is_safe("https://127.0.0.1/report", allowed))
        self.assertFalse(
            external_target_is_safe("https://93.184.216.34/report", allowed)
        )
        self.assertFalse(
            external_target_is_safe("https://user@docs.github.com/report", allowed)
        )

    def test_minimal_public_docx_passes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.docx"
            write_docx(path)
            self.assertEqual(validate_docx(path, set()), [])

    def test_macro_part_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.docx"
            write_docx(path, macro=True)
            failures = validate_docx(path, set())
            self.assertTrue(
                any("active or embedded DOCX part" in failure for failure in failures)
            )

    def test_dtd_and_entity_declarations_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.docx"
            write_docx(path, document=DOCUMENT_WITH_ENTITY)
            failures = validate_docx(path, set())
            self.assertIn(
                "DTD or entity declaration in DOCX part: word/document.xml",
                failures,
            )

    def test_utf16_dtd_and_entity_declarations_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.docx"
            document = DOCUMENT_WITH_ENTITY.replace(
                'encoding="UTF-8"',
                'encoding="UTF-16"',
            ).encode("utf-16")
            write_docx(path, document=document)
            failures = validate_docx(path, set())
            self.assertIn(
                "DTD or entity declaration in DOCX part: word/document.xml",
                failures,
            )

    def test_private_creator_metadata_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.docx"
            write_docx(path, creator="Jane Private")
            failures = validate_docx(path, set())
            self.assertIn("private creator metadata", failures)
            self.assertIn("private lastModifiedBy metadata", failures)

    def test_private_local_path_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.docx"
            document = DOCUMENT.replace(
                "</w:body>",
                "<w:p><w:r><w:t>/Users/private/report.docx</w:t></w:r></w:p></w:body>",
            )
            write_docx(path, document=document)
            failures = validate_docx(path, set())
            self.assertIn("private or local path marker: /users/", failures)

    def test_non_https_external_hyperlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.docx"
            write_docx(path, relationships=RELATIONSHIPS)
            failures = validate_docx(path, set())
            self.assertIn(
                "unsafe external hyperlink: http://example.com/report",
                failures,
            )

    def test_unreviewed_https_host_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.docx"
            relationships = RELATIONSHIPS.replace(
                "http://example.com/report",
                "https://attacker.invalid/credential-harvest",
            )
            write_docx(path, relationships=relationships)
            failures = validate_docx(path, set(), {"docs.github.com"})
            self.assertIn(
                "unsafe external hyperlink: "
                "https://attacker.invalid/credential-harvest",
                failures,
            )

    def test_public_ip_literal_hyperlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.docx"
            relationships = RELATIONSHIPS.replace(
                "http://example.com/report",
                "https://93.184.216.34/credential-harvest",
            )
            write_docx(path, relationships=relationships)
            failures = validate_docx(path, set(), {"docs.github.com"})
            self.assertIn(
                "unsafe external hyperlink: https://93.184.216.34/credential-harvest",
                failures,
            )

    def test_private_ipv6_is_rejected_but_loopback_is_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            private_path = directory_path / "private.docx"
            private_document = DOCUMENT.replace(
                "</w:body>",
                "<w:p><w:r><w:t>fd00::1234</w:t></w:r></w:p></w:body>",
            )
            write_docx(private_path, document=private_document)
            self.assertIn(
                "private IPv6 address in DOCX: fd00::1234",
                validate_docx(private_path, set(), set()),
            )

            loopback_path = directory_path / "loopback.docx"
            loopback_document = DOCUMENT.replace(
                "</w:body>",
                "<w:p><w:r><w:t>::1</w:t></w:r></w:p></w:body>",
            )
            write_docx(loopback_path, document=loopback_document)
            self.assertEqual(validate_docx(loopback_path, set(), set()), [])


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import json
import re
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

import import_publication_bundle as importer
from citation_policy_binding import PolicyError
from publication_catalogue import (
    CATALOGUE_BEGIN,
    CATALOGUE_END,
    REPORT_FIELD_ORDER,
    render_catalogue_table,
)
from test_validate_public_reports import RELATIONSHIPS, write_docx


class PublicationBundleImporterTests(unittest.TestCase):
    def test_v2_schema_and_importer_both_accept_supported_colon_request_id(self) -> None:
        release = self._write_bundle(assessment="Serena")
        release["request_id"] = "Serena MCP: the IDE for your agent/2026-07-26-v1.0"
        (self.bundle / "release.json").write_text(json.dumps(release))
        schema_path = Path(importer.__file__).resolve().parents[1] / "schemas/publication-bundle-v2.schema.json"
        schema = json.loads(schema_path.read_text())
        self.assertIsNotNone(re.fullmatch(schema["properties"]["request_id"]["pattern"], release["request_id"]))
        self.assertTrue(importer.import_bundle(self.bundle, check_only=True).startswith("PASS:"))

    def test_v2_policy_is_independently_checked_twice_before_import(self) -> None:
        release = self._write_bundle()
        release.update(schema_version=2, citation_policy={"commit": "b" * 40, "sha256": "c" * 64})
        (self.bundle / "release.json").write_text(json.dumps(release))
        with patch.object(importer, "validate_policy_binding", return_value={"a.example"}) as verify:
            result = importer.import_bundle(self.bundle, check_only=True)
        self.assertTrue(result.startswith("PASS:"))
        self.assertEqual(verify.call_count, 2)
        self.assertFalse((self.root / release["report"]["path"]).exists())

    def test_v2_stale_policy_stops_before_catalogue_mutation(self) -> None:
        release = self._write_bundle()
        release.update(schema_version=2, citation_policy={"commit": "b" * 40, "sha256": "c" * 64})
        (self.bundle / "release.json").write_text(json.dumps(release))
        before = (self.root / "reports/index.json").read_bytes()
        for responses in [[PolicyError("stale")], [{"a.example"}, PolicyError("changed")]]:
            with patch.object(importer, "validate_policy_binding", side_effect=responses), self.assertRaises(importer.ImportError):
                importer.import_bundle(self.bundle)
            self.assertEqual((self.root / "reports/index.json").read_bytes(), before)
            self.assertFalse((self.root / release["report"]["path"]).exists())

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "repo"
        self.bundle = Path(self.temporary.name) / "bundle"
        (self.root / "reports").mkdir(parents=True)
        self.bundle.mkdir()
        (self.root / "README.md").write_text(
            f"# Reports\n\n{CATALOGUE_BEGIN}\nold\n{CATALOGUE_END}\n",
            encoding="utf-8",
        )
        self.initial_report = {
            "assessment": "Existing",
            "target_version": "1.0",
            "assessment_date": "2026-07-01",
            "report_version": "1.0",
            "classification": "PUBLIC",
            "path": "reports/Existing/existing.docx",
            "sha256": "0" * 64,
            "word_pages": 1,
        }
        self._write_index([self.initial_report])
        self._patches = [
            patch.object(importer, "ROOT", self.root),
            patch.object(importer, "INDEX", self.root / "reports/index.json"),
            patch.object(importer, "SUMS", self.root / "reports/SHA256SUMS.txt"),
            patch.object(importer, "README", self.root / "README.md"),
            patch.object(importer, "load_custom_xml_allowlist", return_value=set()),
            patch.object(importer, "load_hyperlink_host_allowlist", return_value=set()),
            patch.object(importer, "validate_policy_binding", return_value=set()),
        ]
        for active_patch in self._patches:
            active_patch.start()
            self.addCleanup(active_patch.stop)

    def _write_index(self, reports: list[dict[str, object]]) -> None:
        payload = {
            "schema_version": 1,
            "repository": importer.REPOSITORY,
            "publication_model": "report-only-default-deny",
            "reports": reports,
        }
        (self.root / "reports/index.json").write_text(
            json.dumps(payload, indent=2) + "\n", encoding="utf-8"
        )
        (self.root / "reports/SHA256SUMS.txt").write_text("", encoding="utf-8")

    def _write_bundle(
        self,
        *,
        assessment: str = "New Assessment",
        filename: str = "new-2026-07-26-v1.0.docx",
        path: str | None = None,
        relationships: str | None = None,
    ) -> dict[str, object]:
        report_path = self.bundle / filename
        write_docx(report_path, relationships=relationships)
        report = {
            "assessment": assessment,
            "target_version": "2.0",
            "assessment_date": "2026-07-26",
            "report_version": "1.0",
            "classification": "PUBLIC",
            "path": path or f"reports/{assessment}/{filename}",
            "sha256": hashlib.sha256(report_path.read_bytes()).hexdigest(),
            "word_pages": 12,
        }
        release = {
            "schema_version": 2,
            "citation_policy": {"commit": "b" * 40, "sha256": "c" * 64},
            "request_id": f"{assessment}/2026-07-26-v1.0",
            "producer_revision": "a" * 40,
            "consumer_repository": importer.REPOSITORY,
            "report_file": filename,
            "report": report,
        }
        (self.bundle / "release.json").write_text(json.dumps(release), encoding="utf-8")
        return release

    def test_v1_is_readable_but_cannot_grant_current_import_readiness(self) -> None:
        release = self._write_bundle(); release["schema_version"] = 1; del release["citation_policy"]
        (self.bundle / "release.json").write_text(json.dumps(release))
        before = (self.root / "reports/index.json").read_bytes()
        self.assertTrue(importer.inspect_legacy_bundle(self.bundle).startswith("INSPECTED:"))
        for check in [False, True]:
            with self.assertRaisesRegex(importer.ImportError, "v2 bundle"):
                importer.import_bundle(self.bundle, check_only=check)
        self.assertEqual((self.root / "reports/index.json").read_bytes(), before)

    def test_legacy_policy_observation_does_not_destroy_historical_readability(self) -> None:
        release = self._write_bundle(relationships=RELATIONSHIPS.replace("http://example.com/report", "https://a.example/report"))
        release["schema_version"] = 1; del release["citation_policy"]
        (self.bundle / "release.json").write_text(json.dumps(release))
        before = (self.root / "reports/index.json").read_bytes()
        result = importer.inspect_legacy_bundle(self.bundle)
        self.assertIn("current safety observations: 1", result)
        self.assertIn("not current import readiness", result)
        self.assertEqual((self.root / "reports/index.json").read_bytes(), before)

    def test_source_swap_during_validation_cannot_import_unsafe_bytes(self) -> None:
        release = self._write_bundle(relationships=RELATIONSHIPS)
        source = self.bundle / release["report_file"]; unsafe = source.read_bytes()
        safe_path = Path(self.temporary.name) / "safe.docx"; write_docx(safe_path)
        safe_bytes = safe_path.read_bytes(); real = importer.validate_docx
        def swap(path, *args, **kwargs):
            source.write_bytes(safe_bytes)
            try:
                return real(path, *args, **kwargs)
            finally:
                source.write_bytes(unsafe)
        before = (self.root / "reports/index.json").read_bytes()
        with patch.object(importer, "validate_docx", side_effect=swap), self.assertRaisesRegex(importer.ImportError, "unsafe external hyperlink"):
            importer.import_bundle(self.bundle)
        self.assertEqual((self.root / "reports/index.json").read_bytes(), before)
        self.assertFalse((self.root / release["report"]["path"]).exists())

    def test_source_swap_before_copy_does_not_change_validated_snapshot(self) -> None:
        release = self._write_bundle(); source = self.bundle / release["report_file"]
        original = source.read_bytes(); malicious = Path(self.temporary.name) / "unsafe.docx"
        write_docx(malicious, relationships=RELATIONSHIPS)
        real = importer._prepare_destination
        def swap(path, destination):
            source.write_bytes(malicious.read_bytes())
            return real(path, destination)
        with patch.object(importer, "_prepare_destination", side_effect=swap):
            result = importer.import_bundle(self.bundle)
        self.assertTrue(result.startswith("IMPORTED:"))
        self.assertEqual((self.root / release["report"]["path"]).read_bytes(), original)

    def test_successful_import_is_deterministic_and_byte_identical(self) -> None:
        release = self._write_bundle()
        before = (self.bundle / release["report_file"]).read_bytes()
        result = importer.import_bundle(self.bundle)
        self.assertTrue(result.startswith("IMPORTED:"))
        destination = self.root / release["report"]["path"]
        self.assertEqual(destination.read_bytes(), before)
        first_index = (self.root / "reports/index.json").read_bytes()
        rendered_index = json.loads(first_index)
        self.assertTrue(
            all(
                tuple(report) == REPORT_FIELD_ORDER
                for report in rendered_index["reports"]
            )
        )
        first_sums = (self.root / "reports/SHA256SUMS.txt").read_bytes()
        first_readme = (self.root / "README.md").read_bytes()
        self.assertEqual(
            importer.import_bundle(self.bundle),
            "NOOP: identical report is already published",
        )
        self.assertEqual((self.root / "reports/index.json").read_bytes(), first_index)
        self.assertEqual(
            (self.root / "reports/SHA256SUMS.txt").read_bytes(), first_sums
        )
        self.assertEqual((self.root / "README.md").read_bytes(), first_readme)

    def test_public_safe_request_id_may_differ_from_display_name(self) -> None:
        release = self._write_bundle()
        release["request_id"] = (
            "Serena MCP: the IDE for your agent/2026-07-26-v1.0"
        )
        (self.bundle / "release.json").write_text(json.dumps(release), encoding="utf-8")
        self.assertTrue(importer.import_bundle(self.bundle).startswith("IMPORTED:"))

    def test_request_id_rejects_unsafe_private_assessment_components(self) -> None:
        for assessment in (
            "Serena/escape",
            "Serena\nInjected",
            "Serena | injected",
            ":Serena",
        ):
            with self.subTest(assessment=assessment):
                release = self._write_bundle()
                release["request_id"] = f"{assessment}/2026-07-26-v1.0"
                (self.bundle / "release.json").write_text(
                    json.dumps(release), encoding="utf-8"
                )
                with self.assertRaisesRegex(
                    importer.ImportError, "request ID does not match"
                ):
                    importer.import_bundle(self.bundle)

    def test_check_only_does_not_mutate(self) -> None:
        self._write_bundle()
        before = {
            path: path.read_bytes()
            for path in (
                self.root / "reports/index.json",
                self.root / "reports/SHA256SUMS.txt",
                self.root / "README.md",
            )
        }
        self.assertTrue(
            importer.import_bundle(self.bundle, check_only=True).startswith("PASS:")
        )
        self.assertFalse((self.root / "reports/New Assessment").exists())
        for path, content in before.items():
            self.assertEqual(path.read_bytes(), content)

    def test_existing_path_with_different_metadata_is_terminal_collision(self) -> None:
        release = self._write_bundle()
        self._write_index([release["report"]])
        release["report"]["word_pages"] = 99
        (self.bundle / "release.json").write_text(json.dumps(release), encoding="utf-8")
        with self.assertRaisesRegex(importer.ImportError, "terminal collision"):
            importer.import_bundle(self.bundle)

    def test_existing_digest_with_conflicting_metadata_is_terminal_collision(
        self,
    ) -> None:
        release = self._write_bundle()
        conflicting = {
            **release["report"],
            "assessment": "Different Assessment",
            "path": "reports/Different Assessment/different.docx",
        }
        self._write_index([conflicting])
        with self.assertRaisesRegex(importer.ImportError, "existing report digest"):
            importer.import_bundle(self.bundle)

    def test_rejects_extra_file(self) -> None:
        self._write_bundle()
        (self.bundle / "extra.txt").write_text("private", encoding="utf-8")
        with self.assertRaisesRegex(importer.ImportError, "exactly"):
            importer.import_bundle(self.bundle)

    def test_rejects_exact_two_entry_symlinked_report(self) -> None:
        release = self._write_bundle()
        report_path = self.bundle / str(release["report_file"])
        target = Path(self.temporary.name) / "outside.docx"
        report_path.replace(target)
        report_path.symlink_to(target)
        with self.assertRaisesRegex(importer.ImportError, "non-symlink"):
            importer.import_bundle(self.bundle)

    def test_rejects_symlinked_bundle_root(self) -> None:
        self._write_bundle()
        link = Path(self.temporary.name) / "bundle-link"
        link.symlink_to(self.bundle, target_is_directory=True)
        with self.assertRaisesRegex(importer.ImportError, "non-symlink"):
            importer.import_bundle(link)

    def test_rejects_wrong_schema_consumer_digest_and_path(self) -> None:
        cases = (
            ("schema_version", 3, "unsupported"),
            ("consumer_repository", "Other/repo", "wrong consumer"),
        )
        for field, value, message in cases:
            with self.subTest(field=field):
                release = self._write_bundle()
                release[field] = value
                (self.bundle / "release.json").write_text(
                    json.dumps(release), encoding="utf-8"
                )
                with self.assertRaisesRegex(importer.ImportError, message):
                    importer.import_bundle(self.bundle)
        release = self._write_bundle()
        release["report"]["sha256"] = "f" * 64
        (self.bundle / "release.json").write_text(json.dumps(release), encoding="utf-8")
        with self.assertRaisesRegex(importer.ImportError, "digest"):
            importer.import_bundle(self.bundle)
        release = self._write_bundle(path="../private.docx")
        (self.bundle / "release.json").write_text(json.dumps(release), encoding="utf-8")
        with self.assertRaisesRegex(importer.ImportError, "unsafe|layout"):
            importer.import_bundle(self.bundle)

    def test_rejects_non_public_and_display_injection(self) -> None:
        release = self._write_bundle()
        release["report"]["classification"] = "INTERNAL"
        (self.bundle / "release.json").write_text(json.dumps(release), encoding="utf-8")
        with self.assertRaisesRegex(importer.ImportError, "PUBLIC"):
            importer.import_bundle(self.bundle)
        self.bundle.joinpath("release.json").unlink()
        self.bundle.joinpath("new-2026-07-26-v1.0.docx").unlink()
        self._write_bundle(assessment="Bad | injected")
        with self.assertRaisesRegex(importer.ImportError, "Markdown"):
            importer.import_bundle(self.bundle)

    def test_rejects_unreviewed_hyperlink_host(self) -> None:
        relationships = RELATIONSHIPS.replace(
            "http://example.com/report", "https://unreviewed.invalid/report"
        )
        self._write_bundle(relationships=relationships)
        with self.assertRaisesRegex(importer.ImportError, "unsafe external hyperlink"):
            importer.import_bundle(self.bundle)

    def test_rejects_unreviewed_custom_xml(self) -> None:
        release = self._write_bundle()
        report_path = self.bundle / str(release["report_file"])
        with zipfile.ZipFile(report_path, "a", zipfile.ZIP_DEFLATED) as package:
            package.writestr("customXml/item1.xml", "<private>unexpected</private>")
        release["report"]["sha256"] = hashlib.sha256(
            report_path.read_bytes()
        ).hexdigest()
        (self.bundle / "release.json").write_text(json.dumps(release), encoding="utf-8")
        with self.assertRaisesRegex(importer.ImportError, "unreviewed custom XML"):
            importer.import_bundle(self.bundle)

    def test_transaction_restores_prior_files_on_replace_failure(self) -> None:
        release = self._write_bundle()
        original_index = (self.root / "reports/index.json").read_bytes()
        original_sums = (self.root / "reports/SHA256SUMS.txt").read_bytes()
        original_readme = (self.root / "README.md").read_bytes()
        real_replace = importer.os.replace
        calls = 0

        def fail_on_third(source: Path, destination: Path) -> None:
            nonlocal calls
            calls += 1
            if calls == 5:
                raise OSError("simulated replacement failure")
            real_replace(source, destination)

        with (
            patch.object(importer.os, "replace", side_effect=fail_on_third),
            self.assertRaisesRegex(OSError, "simulated"),
        ):
            importer.import_bundle(self.bundle)
        self.assertFalse((self.root / release["report"]["path"]).exists())
        self.assertEqual(
            (self.root / "reports/index.json").read_bytes(), original_index
        )
        self.assertEqual(
            (self.root / "reports/SHA256SUMS.txt").read_bytes(), original_sums
        )
        self.assertEqual((self.root / "README.md").read_bytes(), original_readme)

    def test_transaction_never_replaces_new_report_collision(self) -> None:
        incoming = Path(self.temporary.name) / "incoming"
        destination = Path(self.temporary.name) / "destination"
        incoming.write_bytes(b"incoming")
        destination.write_bytes(b"competing")
        with self.assertRaisesRegex(importer.ImportError, "terminal collision"):
            importer._replace_transaction([(incoming, destination, False)])
        self.assertEqual(destination.read_bytes(), b"competing")
        self.assertFalse(incoming.exists())

    def test_transaction_rolls_back_if_post_link_cleanup_fails(self) -> None:
        incoming = Path(self.temporary.name) / "incoming-cleanup"
        destination = Path(self.temporary.name) / "destination-cleanup"
        incoming.write_bytes(b"incoming")
        real_unlink = Path.unlink
        failed = False

        def fail_first_incoming_unlink(path: Path, missing_ok: bool = False) -> None:
            nonlocal failed
            if path == incoming and not failed:
                failed = True
                raise OSError("simulated cleanup failure")
            real_unlink(path, missing_ok=missing_ok)

        with (
            patch.object(
                Path, "unlink", autospec=True, side_effect=fail_first_incoming_unlink
            ),
            self.assertRaisesRegex(OSError, "simulated cleanup"),
        ):
            importer._replace_transaction([(incoming, destination, False)])
        self.assertFalse(destination.exists())
        self.assertFalse(incoming.exists())

    def test_catalogue_sorting_is_stable(self) -> None:
        reports = [
            {**self.initial_report, "assessment": "Zulu"},
            {**self.initial_report, "assessment": "alpha"},
        ]
        rendered = render_catalogue_table(reports)
        self.assertLess(rendered.index("alpha"), rendered.index("Zulu"))


if __name__ == "__main__":
    unittest.main()

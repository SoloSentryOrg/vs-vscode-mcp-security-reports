#!/usr/bin/env python3
"""Deterministic rendering helpers for the public report catalogue."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

CATALOGUE_BEGIN = "<!-- BEGIN GENERATED REPORT CATALOGUE -->"
CATALOGUE_END = "<!-- END GENERATED REPORT CATALOGUE -->"
INDEX_FIELDS = {
    "schema_version",
    "repository",
    "publication_model",
    "reports",
}
REPORT_FIELD_ORDER = (
    "assessment",
    "target_version",
    "assessment_date",
    "report_version",
    "classification",
    "path",
    "sha256",
    "word_pages",
)
REPORT_FIELDS = set(REPORT_FIELD_ORDER)
REPOSITORY = "SoloSentryOrg/vs-vscode-mcp-security-reports"


class CatalogueError(ValueError):
    """Raised when catalogue content cannot be rendered safely."""


def _markdown_text(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CatalogueError("catalogue display values must be non-empty strings")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise CatalogueError("catalogue display values contain control characters")
    escaped = value.replace("\\", "\\\\")
    for character in ("|", "[", "]", "<", ">"):
        escaped = escaped.replace(character, f"\\{character}")
    return escaped


def report_sort_key(report: dict[str, object]) -> tuple[str, str, str, str]:
    return (
        str(report["assessment"]).casefold(),
        str(report["assessment_date"]),
        str(report["report_version"]),
        str(report["path"]),
    )


def sorted_reports(
    reports: list[dict[str, object]],
) -> list[dict[str, object]]:
    return sorted(reports, key=report_sort_key)


def render_catalogue_table(reports: list[dict[str, object]]) -> str:
    lines = [
        CATALOGUE_BEGIN,
        "| Assessment | Assessed version | Report |",
        "| --- | --- | --- |",
    ]
    for report in sorted_reports(reports):
        assessment = _markdown_text(report["assessment"])
        version = _markdown_text(report["target_version"])
        path = str(report["path"])
        if any(ord(character) < 32 or ord(character) == 127 for character in path):
            raise CatalogueError("report path contains control characters")
        safe_path = path.replace("<", "%3C").replace(">", "%3E")
        lines.append(f"| {assessment} | {version} | [DOCX](<{safe_path}>) |")
    lines.append(CATALOGUE_END)
    return "\n".join(lines)


def replace_catalogue_section(readme: str, rendered: str) -> str:
    if readme.count(CATALOGUE_BEGIN) != 1 or readme.count(CATALOGUE_END) != 1:
        raise CatalogueError("README must contain exactly one catalogue marker pair")
    start = readme.index(CATALOGUE_BEGIN)
    end = readme.index(CATALOGUE_END, start) + len(CATALOGUE_END)
    return f"{readme[:start]}{rendered}{readme[end:]}"


def render_index(reports: list[dict[str, object]]) -> str:
    payload: dict[str, Any] = {
        "schema_version": 1,
        "repository": REPOSITORY,
        "publication_model": "report-only-default-deny",
        "reports": [
            {field: report[field] for field in REPORT_FIELD_ORDER}
            for report in sorted_reports(reports)
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def render_sums(reports: list[dict[str, object]]) -> str:
    return "".join(
        f"{report['sha256']}  {report['path']}\n"
        for report in sorted(reports, key=lambda item: str(item["path"]))
    )


def read_index_payload(path: Path) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or set(payload) != INDEX_FIELDS:
        raise CatalogueError("report index has missing or unexpected fields")
    if (
        payload["schema_version"] != 1
        or payload["repository"] != REPOSITORY
        or payload["publication_model"] != "report-only-default-deny"
    ):
        raise CatalogueError("report index contract identity is invalid")
    reports = payload.get("reports")
    if not isinstance(reports, list):
        raise CatalogueError("report index reports must be a list")
    return payload

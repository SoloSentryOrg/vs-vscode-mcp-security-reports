#!/usr/bin/env python3
"""Fail-closed validation for the report-only public repository."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import stat
import subprocess
import sys
import zipfile
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit
# ElementTree is safe here only after _read_xml rejects DTD/entity declarations
# and the enclosing OOXML package enforces strict per-entry size bounds.
from xml.etree import ElementTree as ET  # nosemgrep: python.lang.security.use-defused-xml.use-defused-xml


ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "reports/index.json"
SUMS = ROOT / "reports/SHA256SUMS.txt"
CUSTOM_XML_ALLOWLIST = Path(__file__).with_name("allowed-docx-custom-xml.json")
HYPERLINK_HOST_ALLOWLIST = Path(__file__).with_name(
    "allowed-hyperlink-hosts.json"
)

W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
CP = "http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
DC = "http://purl.org/dc/elements/1.1/"
EP = "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"

MAX_INDEX_BYTES = 1024 * 1024
MAX_PACKAGE_BYTES = 50 * 1024 * 1024
MAX_PACKAGE_ENTRIES = 2_000
MAX_ENTRY_BYTES = 32 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 200 * 1024 * 1024
MAX_COMPRESSION_RATIO = 1_000

REPORT_FIELDS = {
    "assessment",
    "target_version",
    "assessment_date",
    "report_version",
    "classification",
    "path",
    "sha256",
    "word_pages",
}
STATIC_PATHS = {
    ".gitattributes",
    ".github/CODEOWNERS",
    ".github/pull_request_template.md",
    ".github/workflows/report-publication.yml",
    ".gitignore",
    "AGENTS.md",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "LICENSE",
    "README.md",
    "SECURITY.md",
    "reports/SHA256SUMS.txt",
    "reports/index.json",
    "scripts/allowed-docx-custom-xml.json",
    "scripts/allowed-hyperlink-hosts.json",
    "scripts/test_validate_public_reports.py",
    "scripts/validate_public_reports.py",
}
ACTIVE_PART_PREFIXES = (
    "word/activex/",
    "word/embeddings/",
    "word/vbaproject",
)
PRIVATE_PART_PREFIXES = (
    "docprops/custom.xml",
    "word/comments",
    "word/people",
)
ACTIVE_RELATIONSHIP_SUFFIXES = (
    "/attachedtemplate",
    "/control",
    "/oleobject",
    "/package",
    "/vbaproject",
)
ACTIVE_CONTENT_TYPE_MARKERS = (
    "macroenabled",
    "vbaproject",
    "activex",
    "oleobject",
)
REVISION_ELEMENTS = ("ins", "del", "moveFrom", "moveTo")
OLD_CONTROL_VALUES = {
    "internal-confidential",
    "confidential - internal security assessment",
    "confidential - internal",
    "confidential",
    "internal",
}
OLD_DISTRIBUTION_VALUES = {"need-to-know internal distribution only"}
PRIVATE_HOST_SUFFIXES = (".internal", ".local", ".localhost")
CONTROL_PART = re.compile(r"word/(?:document|header[0-9]+|footer[0-9]+)\.xml")
INLINE_PRIVATE_CLASSIFICATION = re.compile(
    r"classification:\s*(?:internal-confidential|"
    r"confidential\s*-\s*internal security assessment|"
    r"confidential\s*-\s*internal|confidential)",
    re.IGNORECASE,
)
EMAIL = re.compile(
    r"(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![\w.-])",
    re.IGNORECASE,
)
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
IPV6 = re.compile(
    r"(?<![0-9A-Fa-f:.])"
    r"(?:[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]+)"
    r"(?![0-9A-Fa-f:.])"
)
PRIVATE_PATH_MARKERS = (
    "/users/",
    "/private/var/",
    "c:\\users\\",
    "file://",
)
PRIVATE_IPV4_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16")
)
PRIVATE_IPV6_NETWORKS = tuple(
    ipaddress.ip_network(value) for value in ("fc00::/7", "fe80::/10")
)


class ValidationError(ValueError):
    """Raised for a publication contract failure."""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def safe_relative(value: str) -> Path:
    if (
        not isinstance(value, str)
        or not value
        or "\x00" in value
        or "\\" in value
    ):
        raise ValidationError(f"unsafe publication path: {value!r}")
    pure = PurePosixPath(value)
    if pure.is_absolute() or ".." in pure.parts or "." in pure.parts:
        raise ValidationError(f"unsafe publication path: {value!r}")
    return Path(*pure.parts)


def regular_file(root: Path, value: str) -> Path:
    relative = safe_relative(value)
    current = root
    for component in relative.parts[:-1]:
        current = current / component
        metadata = current.lstat()
        if current.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
            raise ValidationError(f"non-directory or symlink parent: {value}")
    path = root / relative
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise ValidationError(f"path must be a regular non-symlink file: {value}")
    try:
        path.resolve(strict=True).relative_to(root.resolve(strict=True))
    except ValueError as exc:
        raise ValidationError(f"path escapes repository root: {value}") from exc
    return path


def load_custom_xml_allowlist(path: Path = CUSTOM_XML_ALLOWLIST) -> set[str]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    values = payload.get("sha256")
    if not isinstance(values, list) or not values:
        raise ValidationError("custom XML allowlist is missing or empty")
    output = set(values)
    if len(output) != len(values) or any(
        not isinstance(value, str)
        or not re.fullmatch(r"[0-9a-f]{64}", value)
        for value in output
    ):
        raise ValidationError("custom XML allowlist contains invalid digests")
    return output


def load_hyperlink_host_allowlist(
    path: Path = HYPERLINK_HOST_ALLOWLIST,
) -> set[str]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    values = payload.get("hosts")
    if not isinstance(values, list) or not values:
        raise ValidationError("hyperlink host allowlist is missing or empty")
    output = set(values)
    if len(output) != len(values) or any(
        not isinstance(value, str)
        or value != value.casefold()
        or value != value.rstrip(".")
        or not re.fullmatch(
            r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
            r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
            value,
        )
        for value in output
    ):
        raise ValidationError("hyperlink host allowlist contains invalid hosts")
    return output


def load_index(path: Path = INDEX) -> list[dict[str, object]]:
    if path.is_symlink() or not path.is_file():
        raise ValidationError("report index must be a regular non-symlink file")
    if path.stat().st_size > MAX_INDEX_BYTES:
        raise ValidationError("report index is oversized")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if set(payload) != {
        "schema_version",
        "repository",
        "publication_model",
        "reports",
    }:
        raise ValidationError("report index has missing or unexpected fields")
    if payload["schema_version"] != 1:
        raise ValidationError("unsupported report index schema")
    if payload["repository"] != "SoloSentryOrg/vs-vscode-mcp-security-reports":
        raise ValidationError("report index targets the wrong repository")
    if payload["publication_model"] != "report-only-default-deny":
        raise ValidationError("unsupported publication model")
    reports = payload["reports"]
    if not isinstance(reports, list) or not reports:
        raise ValidationError("report index contains no reports")
    return reports


def _read_xml(package: zipfile.ZipFile, name: str) -> ET.Element:
    try:
        raw = package.read(name)
        lowered = raw.lower()
        if b"<!doctype" in lowered or b"<!entity" in lowered:
            raise ValidationError(f"DTD or entity declaration in DOCX part: {name}")
        return ET.fromstring(raw)
    except KeyError as exc:
        raise ValidationError(f"missing required DOCX part: {name}") from exc
    except ET.ParseError as exc:
        raise ValidationError(f"invalid XML in DOCX part: {name}") from exc


def _text(element: ET.Element) -> str:
    return "".join(node.text or "" for node in element.iter())


def _metadata_is_generic(value: str) -> bool:
    normalized = " ".join(re.sub(r"[^a-z0-9]+", " ", value.casefold()).split())
    return normalized in {
        "",
        "solosentry",
        "solosentry assessment environment",
        "assessment automation",
        "security assessment automation",
    }


def external_target_is_safe(
    target: str, allowed_hosts: set[str] | None = None
) -> bool:
    parsed = urlsplit(target)
    if (
        parsed.scheme.casefold() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        return False
    hostname = parsed.hostname.casefold().rstrip(".")
    if hostname == "localhost" or hostname.endswith(PRIVATE_HOST_SUFFIXES):
        return False
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return allowed_hosts is not None and hostname in allowed_hosts
    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def _validate_package_bounds(
    path: Path, package: zipfile.ZipFile, failures: list[str]
) -> None:
    if path.stat().st_size > MAX_PACKAGE_BYTES:
        failures.append(f"DOCX exceeds {MAX_PACKAGE_BYTES} bytes")
    entries = package.infolist()
    if len(entries) > MAX_PACKAGE_ENTRIES:
        failures.append(f"DOCX has more than {MAX_PACKAGE_ENTRIES} entries")
    names = [entry.filename for entry in entries]
    if len(names) != len(set(names)):
        failures.append("DOCX contains duplicate entry names")
    total = 0
    for entry in entries:
        pure = PurePosixPath(entry.filename)
        if (
            pure.is_absolute()
            or ".." in pure.parts
            or "\\" in entry.filename
            or "\x00" in entry.filename
        ):
            failures.append(f"unsafe DOCX entry path: {entry.filename!r}")
        if entry.flag_bits & 0x1:
            failures.append(f"encrypted DOCX entry: {entry.filename}")
        total += entry.file_size
        if entry.file_size > MAX_ENTRY_BYTES:
            failures.append(f"oversized DOCX entry: {entry.filename}")
        ratio = (
            float("inf")
            if entry.compress_size == 0 and entry.file_size
            else entry.file_size / max(entry.compress_size, 1)
        )
        if ratio > MAX_COMPRESSION_RATIO:
            failures.append(f"excessive compression ratio: {entry.filename}")
    if total > MAX_UNCOMPRESSED_BYTES:
        failures.append("DOCX uncompressed content is oversized")


def _validate_relationships(
    package: zipfile.ZipFile,
    allowed_hosts: set[str],
    failures: list[str],
) -> None:
    for name in package.namelist():
        if not name.casefold().endswith(".rels"):
            continue
        root = _read_xml(package, name)
        for relation in root:
            relation_type = relation.get("Type", "")
            target = relation.get("Target", "")
            if relation_type.casefold().endswith(ACTIVE_RELATIONSHIP_SUFFIXES):
                failures.append(f"active relationship: {name}")
            if relation.get("TargetMode") != "External":
                continue
            if not relation_type.casefold().endswith("/hyperlink"):
                failures.append(f"external non-hyperlink relationship: {name}")
            elif not external_target_is_safe(target, allowed_hosts):
                failures.append(f"unsafe external hyperlink: {target}")


def _validate_active_content(
    package: zipfile.ZipFile,
    allowed_custom_xml: set[str],
    failures: list[str],
) -> None:
    names = package.namelist()
    for name in names:
        lowered = name.casefold()
        if lowered.endswith(".bin") or lowered.startswith(ACTIVE_PART_PREFIXES):
            failures.append(f"active or embedded DOCX part: {name}")
        if lowered.startswith(PRIVATE_PART_PREFIXES):
            failures.append(f"private-review DOCX part: {name}")
    content_types = _read_xml(package, "[Content_Types].xml")
    for item in content_types:
        content_type = item.get("ContentType", "").casefold()
        if any(marker in content_type for marker in ACTIVE_CONTENT_TYPE_MARKERS):
            failures.append(
                f"active DOCX content type: {item.get('ContentType', '')}"
            )
    for name in names:
        lowered = name.casefold()
        if lowered.startswith("word/") and lowered.endswith(".xml"):
            root = _read_xml(package, name)
            for local_name in REVISION_ELEMENTS:
                if next(root.iter(f"{{{W}}}{local_name}"), None) is not None:
                    failures.append(f"tracked revision w:{local_name} in {name}")
    for name in names:
        lowered = name.casefold()
        if lowered.startswith("customxml/") and lowered.endswith(".xml"):
            digest = hashlib.sha256(package.read(name)).hexdigest()
            if digest not in allowed_custom_xml:
                failures.append(f"unreviewed custom XML part: {name}")


def _validate_metadata(package: zipfile.ZipFile, failures: list[str]) -> None:
    core = _read_xml(package, "docProps/core.xml")
    for namespace, name in ((DC, "creator"), (CP, "lastModifiedBy")):
        node = core.find(f"{{{namespace}}}{name}")
        value = (node.text or "").strip() if node is not None else ""
        if not _metadata_is_generic(value):
            failures.append(f"private {name} metadata")
    if "docProps/app.xml" not in package.namelist():
        return
    extended = _read_xml(package, "docProps/app.xml")
    for name in ("Manager", "Company"):
        node = extended.find(f"{{{EP}}}{name}")
        value = (node.text or "").strip() if node is not None else ""
        if not _metadata_is_generic(value):
            failures.append(f"private {name} metadata")
    hyperlink_base = extended.find(f"{{{EP}}}HyperlinkBase")
    if hyperlink_base is not None and (hyperlink_base.text or "").strip():
        failures.append("HyperlinkBase metadata must be blank")


def _validate_classification(
    package: zipfile.ZipFile, failures: list[str]
) -> None:
    public_markers = 0
    for name in package.namelist():
        if not CONTROL_PART.fullmatch(name):
            continue
        root = _read_xml(package, name)
        for row in root.iter(f"{{{W}}}tr"):
            cells = list(row.findall(f"./{{{W}}}tc"))
            if len(cells) < 2:
                continue
            label = _text(cells[0]).strip().casefold()
            value = _text(cells[1]).strip()
            if label == "classification":
                if value == "PUBLIC":
                    public_markers += 1
                elif value.casefold() in OLD_CONTROL_VALUES:
                    failures.append(f"private classification in {name}")
            if (
                label == "distribution"
                and value.casefold() in OLD_DISTRIBUTION_VALUES
            ):
                failures.append(f"private distribution restriction in {name}")
        for node in root.iter(f"{{{W}}}t"):
            value = node.text or ""
            if "Classification: PUBLIC" in value:
                public_markers += 1
            if INLINE_PRIVATE_CLASSIFICATION.search(value):
                failures.append(f"private inline classification in {name}")
    if public_markers == 0:
        failures.append("no explicit PUBLIC document-control classification")


def _validate_sensitive_text(
    package: zipfile.ZipFile, failures: list[str]
) -> None:
    chunks: list[str] = []
    for name in package.namelist():
        if not name.casefold().endswith((".xml", ".rels")):
            continue
        root = _read_xml(package, name)
        chunks.extend(node.text or "" for node in root.iter())
        chunks.extend(value for value in root.attrib.values())
        for node in root.iter():
            chunks.extend(value for value in node.attrib.values())
    for chunk in chunks:
        lowered = chunk.casefold()
        for marker in PRIVATE_PATH_MARKERS:
            if marker in lowered:
                failures.append(f"private or local path marker: {marker}")
        if EMAIL.search(chunk):
            failures.append("email address in DOCX content or relationships")
        for candidate in IPV4.findall(chunk):
            try:
                address = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if any(address in network for network in PRIVATE_IPV4_NETWORKS):
                failures.append(f"private IP address in DOCX: {candidate}")
        for candidate in IPV6.findall(chunk):
            try:
                address = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if not isinstance(address, ipaddress.IPv6Address):
                continue
            mapped = address.ipv4_mapped
            if any(address in network for network in PRIVATE_IPV6_NETWORKS) or (
                mapped is not None
                and any(mapped in network for network in PRIVATE_IPV4_NETWORKS)
            ):
                failures.append(f"private IPv6 address in DOCX: {candidate}")


def validate_docx(
    path: Path,
    allowed_custom_xml: set[str],
    allowed_hosts: set[str] | None = None,
) -> list[str]:
    failures: list[str] = []
    if path.is_symlink() or not path.is_file():
        return ["report must be a regular non-symlink file"]
    if path.suffix.casefold() != ".docx":
        return ["report must use the .docx extension"]
    try:
        with zipfile.ZipFile(path) as package:
            _validate_package_bounds(path, package, failures)
            if failures:
                return sorted(set(failures))
            _read_xml(package, "word/document.xml")
            _validate_relationships(package, allowed_hosts or set(), failures)
            _validate_active_content(package, allowed_custom_xml, failures)
            _validate_metadata(package, failures)
            _validate_classification(package, failures)
            _validate_sensitive_text(package, failures)
    except (zipfile.BadZipFile, ValidationError) as exc:
        failures.append(str(exc))
    return sorted(set(failures))


def parse_sums(path: Path = SUMS) -> dict[str, str]:
    output: dict[str, str] = {}
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not line:
            continue
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not match:
            raise ValidationError(f"invalid checksum line {line_number}")
        digest, value = match.groups()
        safe_relative(value)
        if value in output:
            raise ValidationError(f"duplicate checksum path: {value}")
        output[value] = digest
    return output


def candidate_paths(root: Path = ROOT) -> set[str]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
        timeout=30,
    )
    return {
        value.decode("utf-8", errors="strict")
        for value in result.stdout.split(b"\0")
        if value
    }


def main() -> int:
    failures: list[str] = []
    try:
        reports = load_index()
        allowed_custom_xml = load_custom_xml_allowlist()
        allowed_hosts = load_hyperlink_host_allowlist()
        sums = parse_sums()
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValidationError) as exc:
        print(f"FAIL: {exc}")
        return 1

    expected_paths: set[str] = set()
    expected_sums: dict[str, str] = {}
    for index, record in enumerate(reports, start=1):
        if not isinstance(record, dict) or set(record) != REPORT_FIELDS:
            failures.append(f"report record {index} has missing or unexpected fields")
            continue
        value = record["path"]
        try:
            relative = safe_relative(value)
        except ValidationError as exc:
            failures.append(str(exc))
            continue
        if (
            len(relative.parts) != 3
            or relative.parts[0] != "reports"
            or relative.suffix.casefold() != ".docx"
        ):
            failures.append(f"report path violates layout: {value}")
            continue
        if not isinstance(record["assessment"], str) or not record[
            "assessment"
        ].strip():
            failures.append(f"missing assessment name: {value}")
        if record["classification"] != "PUBLIC":
            failures.append(f"report is not PUBLIC: {value}")
        if not isinstance(record["word_pages"], int) or record["word_pages"] < 1:
            failures.append(f"invalid Word page count: {value}")
        if not isinstance(record["target_version"], str) or not record[
            "target_version"
        ].strip():
            failures.append(f"missing target version: {value}")
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(record["assessment_date"])):
            failures.append(f"invalid assessment date: {value}")
        if not re.fullmatch(r"\d+\.\d+", str(record["report_version"])):
            failures.append(f"invalid report version: {value}")
        digest = record["sha256"]
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            failures.append(f"invalid report SHA-256: {value}")
            continue
        if value in expected_paths:
            failures.append(f"duplicate report path: {value}")
            continue
        expected_paths.add(value)
        expected_sums[value] = digest
        try:
            path = regular_file(ROOT, value)
        except (OSError, ValidationError) as exc:
            failures.append(str(exc))
            continue
        actual = sha256(path)
        if actual != digest:
            failures.append(f"catalogue digest mismatch: {value}")
        for failure in validate_docx(path, allowed_custom_xml, allowed_hosts):
            failures.append(f"{value}: {failure}")

    if sums != expected_sums:
        failures.append("SHA256SUMS.txt does not exactly match the report catalogue")

    actual_paths = candidate_paths()
    allowed_paths = STATIC_PATHS | expected_paths
    unexpected = sorted(actual_paths - allowed_paths)
    missing = sorted(allowed_paths - actual_paths)
    if unexpected:
        failures.append(f"unexpected default-deny paths: {unexpected}")
    if missing:
        failures.append(f"required publication paths are missing: {missing}")

    if failures:
        print("FAIL: public report validation")
        for failure in sorted(set(failures)):
            print(f"  ERROR: {failure}")
        return 1
    print(
        f"PASS: {len(expected_paths)} PUBLIC reports are hash-bound, "
        "package-safe, and default-deny accounted"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

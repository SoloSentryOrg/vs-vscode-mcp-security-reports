#!/usr/bin/env python3
"""Validate and atomically import one public assessment bundle."""

from __future__ import annotations

import argparse
import contextlib
import datetime
import fcntl
import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
from collections.abc import Iterator
from pathlib import Path

from publication_catalogue import (
    REPORT_FIELDS,
    REPOSITORY,
    CatalogueError,
    read_index_payload,
    render_catalogue_table,
    render_index,
    render_sums,
    replace_catalogue_section,
)
from validate_public_reports import (
    MAX_PACKAGE_BYTES,
    ValidationError,
    load_custom_xml_allowlist,
    load_hyperlink_host_allowlist,
    safe_relative,
    sha256,
    validate_docx,
)

ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "reports/index.json"
SUMS = ROOT / "reports/SHA256SUMS.txt"
README = ROOT / "README.md"
RELEASE_FIELDS = {
    "schema_version",
    "request_id",
    "producer_revision",
    "consumer_repository",
    "report_file",
    "report",
}
RUN_KEY = re.compile(r"\d{4}-\d{2}-\d{2}-v\d+\.\d+")
HEX_40 = re.compile(r"[0-9a-f]{40}")
HEX_64 = re.compile(r"[0-9a-f]{64}")
VERSION = re.compile(r"\d+\.\d+")
DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
SAFE_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._()+-]*")
REQUEST_ASSESSMENT_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._()+:-]*")
MAX_RELEASE_BYTES = 64 * 1024


class ImportError(ValueError):
    """Raised for a fail-closed publication import."""


def _regular_file(path: Path, label: str) -> None:
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise ImportError(f"{label} must be a regular non-symlink file")


def _safe_display(value: object, label: str, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ImportError(f"invalid {label}")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ImportError(f"{label} contains control characters")
    if any(character in value for character in ("|", "[", "]", "<", ">")):
        raise ImportError(f"{label} contains unescaped Markdown characters")
    return value


def _load_release(bundle: Path) -> tuple[dict[str, object], Path]:
    if bundle.is_symlink() or not bundle.is_dir():
        raise ImportError("bundle must be a regular non-symlink directory")
    entries = list(bundle.iterdir())
    if len(entries) != 2:
        raise ImportError("bundle must contain exactly release.json and one DOCX")
    for entry in entries:
        _regular_file(entry, f"bundle entry {entry.name!r}")
    names = {entry.name for entry in entries}
    if "release.json" not in names:
        raise ImportError("bundle is missing release.json")
    report_names = names - {"release.json"}
    if len(report_names) != 1:
        raise ImportError("bundle must contain exactly one report")
    report_name = next(iter(report_names))
    if Path(report_name).suffix.casefold() != ".docx":
        raise ImportError("bundle report must use the .docx extension")
    release_path = bundle / "release.json"
    if release_path.stat().st_size > MAX_RELEASE_BYTES:
        raise ImportError("release.json is oversized")
    try:
        release = json.loads(release_path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ImportError(f"invalid release.json: {exc}") from exc
    if not isinstance(release, dict) or set(release) != RELEASE_FIELDS:
        raise ImportError("release.json has missing or unexpected fields")
    if release["schema_version"] != 1:
        raise ImportError("unsupported publication bundle schema")
    if release["consumer_repository"] != REPOSITORY:
        raise ImportError("bundle targets the wrong consumer repository")
    if not isinstance(release["producer_revision"], str) or not HEX_40.fullmatch(
        release["producer_revision"]
    ):
        raise ImportError("invalid producer revision")
    if release["report_file"] != report_name:
        raise ImportError("bundle filename does not match release.json")
    if (
        not isinstance(report_name, str)
        or len(report_name) > 255
        or not SAFE_COMPONENT.fullmatch(report_name)
    ):
        raise ImportError("unsafe bundle report filename")
    return release, bundle / report_name


def _validate_report(
    release: dict[str, object], report_path: Path
) -> dict[str, object]:
    report = release["report"]
    if not isinstance(report, dict) or set(report) != REPORT_FIELDS:
        raise ImportError("report metadata has missing or unexpected fields")
    _safe_display(report["assessment"], "assessment", 200)
    _safe_display(report["target_version"], "target version", 100)
    if report["classification"] != "PUBLIC":
        raise ImportError("report classification must be PUBLIC")
    if not isinstance(report["assessment_date"], str) or not DATE.fullmatch(
        report["assessment_date"]
    ):
        raise ImportError("invalid assessment date")
    try:
        datetime.date.fromisoformat(report["assessment_date"])
    except ValueError as exc:
        raise ImportError("invalid assessment date") from exc
    if not isinstance(report["report_version"], str) or not VERSION.fullmatch(
        report["report_version"]
    ):
        raise ImportError("invalid report version")
    if (
        not isinstance(report["word_pages"], int)
        or isinstance(report["word_pages"], bool)
        or report["word_pages"] < 1
    ):
        raise ImportError("invalid Word page count")
    if not isinstance(report["sha256"], str) or not HEX_64.fullmatch(report["sha256"]):
        raise ImportError("invalid report SHA-256")
    if not isinstance(report["path"], str):
        raise ImportError("invalid public report path")
    try:
        relative = safe_relative(report["path"])
    except ValidationError as exc:
        raise ImportError(str(exc)) from exc
    if (
        len(relative.parts) != 3
        or relative.parts[0] != "reports"
        or not SAFE_COMPONENT.fullmatch(relative.parts[1])
        or not SAFE_COMPONENT.fullmatch(relative.name)
        or relative.suffix.casefold() != ".docx"
        or relative.name != release["report_file"]
    ):
        raise ImportError("public report path violates the v1 layout")
    request_id = release["request_id"]
    if not isinstance(request_id, str) or "/" not in request_id:
        raise ImportError("invalid public-safe request ID")
    request_assessment, request_run_key = request_id.rsplit("/", 1)
    if (
        not REQUEST_ASSESSMENT_COMPONENT.fullmatch(request_assessment)
        or not RUN_KEY.fullmatch(request_run_key)
        or request_run_key != f"{report['assessment_date']}-v{report['report_version']}"
    ):
        raise ImportError("request ID does not match report metadata")
    if report_path.stat().st_size > MAX_PACKAGE_BYTES:
        raise ImportError("bundle report is oversized")
    actual_digest = sha256(report_path)
    if actual_digest != report["sha256"]:
        raise ImportError("bundle report digest mismatch")
    failures = validate_docx(
        report_path,
        load_custom_xml_allowlist(),
        load_hyperlink_host_allowlist(),
    )
    if failures:
        raise ImportError("report validation failed: " + "; ".join(failures))
    return report


def _prepare_text(path: Path, content: str) -> Path:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        return temporary
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _replace_transaction(
    replacements: list[tuple[Path, Path, bool]],
) -> None:
    """Replace several files and restore every prior file on any failure."""
    backups: list[tuple[Path, Path]] = []
    installed: list[Path] = []
    try:
        for temporary, destination, replace_existing in replacements:
            if not replace_existing:
                try:
                    os.link(temporary, destination, follow_symlinks=False)
                except FileExistsError as exc:
                    raise ImportError(
                        "terminal collision at public report path"
                    ) from exc
                installed.append(destination)
                temporary.unlink()
                continue
            if destination.exists() or destination.is_symlink():
                descriptor, backup_name = tempfile.mkstemp(
                    prefix=f".{destination.name}.rollback.",
                    dir=destination.parent,
                )
                os.close(descriptor)
                backup = Path(backup_name)
                backup.unlink()
                os.replace(destination, backup)
                backups.append((backup, destination))
            os.replace(temporary, destination)
            installed.append(destination)
    except BaseException:
        for destination in reversed(installed):
            destination.unlink(missing_ok=True)
        for backup, destination in reversed(backups):
            if backup.exists():
                os.replace(backup, destination)
        raise
    else:
        for backup, _ in backups:
            backup.unlink(missing_ok=True)
    finally:
        for temporary, _, _ in replacements:
            temporary.unlink(missing_ok=True)


def _prepare_destination(report_path: Path, destination: Path) -> Path:
    reports_root = ROOT / "reports"
    root_metadata = reports_root.lstat()
    if reports_root.is_symlink() or not stat.S_ISDIR(root_metadata.st_mode):
        raise ImportError("reports root must be a regular non-symlink directory")
    if destination.parent.exists() or destination.parent.is_symlink():
        parent_metadata = destination.parent.lstat()
        if destination.parent.is_symlink() or not stat.S_ISDIR(parent_metadata.st_mode):
            raise ImportError(
                "report destination parent must be a non-symlink directory"
            )
    else:
        destination.parent.mkdir(mode=0o755)
    try:
        destination.parent.resolve(strict=True).relative_to(
            reports_root.resolve(strict=True)
        )
    except ValueError as exc:
        raise ImportError("report destination escapes the reports root") from exc
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", dir=destination.parent
    )
    temporary_report = Path(temporary_name)
    try:
        with (
            report_path.open("rb") as source,
            os.fdopen(descriptor, "wb") as destination_handle,
        ):
            shutil.copyfileobj(source, destination_handle, length=1024 * 1024)
            destination_handle.flush()
            os.fsync(destination_handle.fileno())
        return temporary_report
    except BaseException:
        temporary_report.unlink(missing_ok=True)
        raise


@contextlib.contextmanager
def _publication_lock() -> Iterator[None]:
    lock_root = Path(tempfile.gettempdir()) / ".solosentry-publication-locks"
    lock_root.mkdir(mode=0o700, exist_ok=True)
    metadata = lock_root.lstat()
    if (
        lock_root.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise ImportError("publication lock directory is not private")
    identity = hashlib.sha256(
        str(ROOT.resolve(strict=True)).encode("utf-8")
    ).hexdigest()
    lock_path = lock_root / f"{identity}.lock"
    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(lock_path, flags, 0o600)
    with os.fdopen(descriptor, "a+b") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        yield


def _import_bundle_locked(bundle: Path, *, check_only: bool = False) -> str:
    if bundle.is_symlink():
        raise ImportError("bundle must be a regular non-symlink directory")
    release, report_path = _load_release(bundle.absolute())
    report = _validate_report(release, report_path)
    payload = read_index_payload(INDEX)
    reports = payload["reports"]
    assert isinstance(reports, list)
    if any(
        not isinstance(item, dict) or set(item) != REPORT_FIELDS for item in reports
    ):
        raise ImportError("existing report index contains an invalid record")
    existing_paths = [str(item["path"]) for item in reports]
    if len(existing_paths) != len(set(existing_paths)):
        raise ImportError("existing report index contains duplicate paths")
    existing = [item for item in reports if item.get("path") == report["path"]]
    if existing:
        if len(existing) == 1 and existing[0] == report:
            destination = ROOT / str(report["path"])
            if (
                destination.is_file()
                and not destination.is_symlink()
                and sha256(destination) == report["sha256"]
            ):
                return "NOOP: identical report is already published"
        raise ImportError("terminal collision at existing public report path")
    if any(
        item.get("sha256") == report["sha256"] and item != report for item in reports
    ):
        raise ImportError("terminal collision on existing report digest")

    new_reports = [*reports, report]
    index_content = render_index(new_reports)
    sums_content = render_sums(new_reports)
    readme_content = replace_catalogue_section(
        README.read_text(encoding="utf-8"),
        render_catalogue_table(new_reports),
    )
    destination = ROOT / str(report["path"])
    if destination.exists() or destination.is_symlink():
        raise ImportError("terminal collision at existing public report path")
    if check_only:
        return f"PASS: validated publication for {report['path']}"

    temporary_report: Path | None = None
    prepared: list[tuple[Path, Path, bool]] = []
    try:
        temporary_report = _prepare_destination(report_path, destination)
        if sha256(temporary_report) != report["sha256"]:
            raise ImportError("copied report is not byte-identical")
        prepared = [
            (temporary_report, destination, False),
            (_prepare_text(INDEX, index_content), INDEX, True),
            (_prepare_text(SUMS, sums_content), SUMS, True),
            (_prepare_text(README, readme_content), README, True),
        ]
        _replace_transaction(prepared)
    finally:
        if temporary_report is not None:
            temporary_report.unlink(missing_ok=True)
        for temporary, _, _ in prepared:
            temporary.unlink(missing_ok=True)
    return f"IMPORTED: {report['path']}"


def import_bundle(bundle: Path, *, check_only: bool = False) -> str:
    with _publication_lock():
        return _import_bundle_locked(bundle, check_only=check_only)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", type=Path)
    parser.add_argument(
        "--check",
        action="store_true",
        help="validate the bundle without modifying the repository",
    )
    arguments = parser.parse_args()
    try:
        print(import_bundle(arguments.bundle, check_only=arguments.check))
    except (OSError, json.JSONDecodeError, CatalogueError, ImportError) as exc:
        print(f"FAIL: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

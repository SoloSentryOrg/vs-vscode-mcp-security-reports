#!/usr/bin/env python3
"""Monitor reviewed external hyperlinks embedded in published DOCX reports."""

from __future__ import annotations

import argparse
import http.client
import ipaddress
import socket
import ssl
import zipfile
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit

from validate_public_reports import (
    ROOT,
    ValidationError,
    _read_xml,
    external_target_is_safe,
    load_custom_xml_allowlist,
    load_hyperlink_host_allowlist,
    load_index,
    regular_file,
    validate_docx,
)

USER_AGENT = (
    "SoloSentry-public-report-link-monitor/1.0 "
    "(https://github.com/SoloSentryOrg/vs-vscode-mcp-security-reports)"
)
INDETERMINATE_HTTP_CODES = {401, 403, 429}
MAX_WORKERS = 16
MAX_RETRIES = 2
MAX_REDIRECTS = 5


class TransientProbeError(ValidationError):
    """A bounded network failure that is not proof of a broken citation."""


@dataclass(frozen=True)
class ProbeResult:
    url: str
    outcome: str
    detail: str
    retryable: bool = False


def display_url(value: str) -> str:
    """Remove query strings and fragments from log output."""
    parsed = urlsplit(value)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def require_safe_url(value: str, allowed_hosts: set[str]) -> None:
    if not external_target_is_safe(value, allowed_hosts):
        raise ValidationError(f"unsafe or unreviewed external URL: {display_url(value)}")


def resolve_public_addresses(
    value: str,
    resolver: Callable[..., list[tuple[object, ...]]] = socket.getaddrinfo,
) -> tuple[str, ...]:
    parsed = urlsplit(value)
    hostname = parsed.hostname
    if not hostname:
        raise ValidationError(f"external URL has no hostname: {display_url(value)}")
    port = parsed.port or 443
    try:
        answers = resolver(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        permanent_errors = {
            value
            for value in (
                getattr(socket, "EAI_NONAME", None),
                getattr(socket, "EAI_NODATA", None),
            )
            if value is not None
        }
        error_type = (
            ValidationError
            if exc.errno in permanent_errors
            else TransientProbeError
        )
        raise error_type(f"DNS resolution failed for {hostname}: {exc}") from exc
    except OSError as exc:
        raise TransientProbeError(
            f"DNS resolution failed for {hostname}: {exc}"
        ) from exc
    if not answers:
        raise TransientProbeError(
            f"DNS resolution returned no addresses for {hostname}"
        )
    addresses: set[str] = set()
    for answer in answers:
        address = ipaddress.ip_address(answer[4][0])
        if (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
            or address.is_unspecified
        ):
            raise ValidationError(
                f"non-public DNS address for {hostname}: {address}"
            )
        addresses.add(str(address))
    return tuple(sorted(addresses))


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connect to a validated IP while retaining hostname TLS verification."""

    def __init__(
        self,
        hostname: str,
        address: str,
        port: int,
        timeout: float,
    ) -> None:
        super().__init__(
            hostname,
            port=port,
            timeout=timeout,
            context=ssl.create_default_context(),
        )
        self.pinned_address = address

    def connect(self) -> None:
        raw_socket = socket.create_connection(
            (self.pinned_address, self.port),
            self.timeout,
            self.source_address,
        )
        self.sock = self._context.wrap_socket(
            raw_socket,
            server_hostname=self.host,
        )


def collect_report_links(path: Path, allowed_hosts: set[str]) -> set[str]:
    links: set[str] = set()
    try:
        with zipfile.ZipFile(path) as package:
            for name in package.namelist():
                if not name.casefold().endswith(".rels"):
                    continue
                root = _read_xml(package, name)
                for relationship in root:
                    if relationship.get("TargetMode") != "External":
                        continue
                    relation_type = relationship.get("Type", "")
                    target = relationship.get("Target", "")
                    if not relation_type.casefold().endswith("/hyperlink"):
                        raise ValidationError(
                            f"external non-hyperlink relationship in {path.name}"
                        )
                    require_safe_url(target, allowed_hosts)
                    links.add(target)
    except zipfile.BadZipFile as exc:
        raise ValidationError(f"invalid DOCX package: {path}") from exc
    return links


def collect_links() -> tuple[set[str], set[str]]:
    allowed_hosts = load_hyperlink_host_allowlist()
    allowed_custom_xml = load_custom_xml_allowlist()
    links: set[str] = set()
    for record in load_index():
        path = regular_file(ROOT, str(record["path"]))
        failures = validate_docx(path, allowed_custom_xml, allowed_hosts)
        if failures:
            raise ValidationError(
                f"{record['path']} failed DOCX validation: {failures}"
            )
        links.update(collect_report_links(path, allowed_hosts))
    return links, allowed_hosts


def make_pinned_connection(
    hostname: str,
    address: str,
    port: int,
    timeout: float,
) -> PinnedHTTPSConnection:
    return PinnedHTTPSConnection(hostname, address, port, timeout)


def fetch_status(
    value: str,
    timeout: float,
    *,
    resolver: Callable[..., list[tuple[object, ...]]] = socket.getaddrinfo,
    connection_factory: Callable[[str, str, int, float], object] = (
        make_pinned_connection
    ),
) -> tuple[int, str | None]:
    parsed = urlsplit(value)
    hostname = parsed.hostname
    if not hostname:
        raise ValidationError(f"external URL has no hostname: {display_url(value)}")
    port = parsed.port or 443
    target = parsed.path or "/"
    if parsed.query:
        target = f"{target}?{parsed.query}"
    addresses = resolve_public_addresses(value, resolver)
    last_error: Exception | None = None
    for address in addresses:
        connection = connection_factory(hostname, address, port, timeout)
        try:
            connection.request(
                "GET",
                target,
                headers={
                    "Accept": "*/*",
                    "Range": "bytes=0-0",
                    "User-Agent": USER_AGENT,
                },
            )
            response = connection.getresponse()
            return int(response.status), response.getheader("Location")
        except ssl.SSLCertVerificationError as exc:
            raise ValidationError(
                f"TLS certificate validation failed for {hostname}: {exc}"
            ) from exc
        except ssl.SSLError as exc:
            raise ValidationError(
                f"TLS connection failed for {hostname}: {exc}"
            ) from exc
        except (OSError, http.client.HTTPException) as exc:
            last_error = exc
        finally:
            connection.close()
    raise TransientProbeError(
        f"HTTPS connection failed for {hostname}: {last_error}"
    )


def probe_url(
    value: str,
    allowed_hosts: set[str],
    timeout: float,
    *,
    resolver: Callable[..., list[tuple[object, ...]]] = socket.getaddrinfo,
    connection_factory: Callable[[str, str, int, float], object] = (
        make_pinned_connection
    ),
) -> ProbeResult:
    shown = display_url(value)
    try:
        current = value
        for redirect_count in range(MAX_REDIRECTS + 1):
            require_safe_url(current, allowed_hosts)
            status, location = fetch_status(
                current,
                timeout,
                resolver=resolver,
                connection_factory=connection_factory,
            )
            if status in {301, 302, 303, 307, 308}:
                if not location:
                    return ProbeResult(shown, "fail", f"HTTP {status} without Location")
                if redirect_count == MAX_REDIRECTS:
                    return ProbeResult(shown, "fail", "redirect limit exceeded")
                current = urljoin(current, location)
                continue
            if status in INDETERMINATE_HTTP_CODES:
                return ProbeResult(shown, "indeterminate", f"HTTP {status}")
            if 500 <= status < 600:
                return ProbeResult(
                    shown,
                    "indeterminate",
                    f"HTTP {status}",
                    retryable=True,
                )
            if 200 <= status < 400:
                return ProbeResult(shown, "pass", f"HTTP {status}")
            return ProbeResult(shown, "fail", f"HTTP {status}")
        return ProbeResult(shown, "fail", "redirect limit exceeded")
    except TransientProbeError as exc:
        return ProbeResult(shown, "indeterminate", str(exc), retryable=True)
    except (OSError, ValidationError, ValueError) as exc:
        return ProbeResult(shown, "fail", str(exc))


def probe_with_retries(
    value: str,
    allowed_hosts: set[str],
    timeout: float,
    retries: int,
    *,
    probe: Callable[[str, set[str], float], ProbeResult] = probe_url,
) -> ProbeResult:
    result = ProbeResult(display_url(value), "fail", "not attempted")
    for _ in range(retries + 1):
        result = probe(value, allowed_hosts, timeout)
        if not result.retryable:
            return result
    return ProbeResult(result.url, "indeterminate", result.detail)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check reviewed external DOCX citation links."
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Per-request timeout in seconds (default: 10).",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=8,
        help="Concurrent request limit, 1-16 (default: 8).",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=1,
        help="Retries for transient failures, 0-2 (default: 1).",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not 0.5 <= args.timeout <= 30:
        print("FAIL: --timeout must be between 0.5 and 30 seconds")
        return 2
    if not 1 <= args.workers <= MAX_WORKERS:
        print(f"FAIL: --workers must be between 1 and {MAX_WORKERS}")
        return 2
    if not 0 <= args.retries <= MAX_RETRIES:
        print(f"FAIL: --retries must be between 0 and {MAX_RETRIES}")
        return 2
    try:
        links, allowed_hosts = collect_links()
    except (OSError, KeyError, ValidationError, ValueError) as exc:
        print(f"FAIL: {exc}")
        return 1

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        results = list(
            executor.map(
                lambda value: probe_with_retries(
                    value,
                    allowed_hosts,
                    args.timeout,
                    args.retries,
                ),
                sorted(links),
            )
        )

    failures = [result for result in results if result.outcome == "fail"]
    indeterminate = [
        result for result in results if result.outcome == "indeterminate"
    ]
    for result in failures:
        print(f"ERROR: {result.url}: {result.detail}")
    for result in indeterminate:
        print(f"WARN: {result.url}: {result.detail}")
    if failures:
        print(
            f"FAIL: {len(failures)} of {len(results)} reviewed external links failed"
        )
        return 1
    print(
        f"PASS: {len(results)} reviewed external links checked; "
        f"{len(indeterminate)} access-controlled or rate-limited"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

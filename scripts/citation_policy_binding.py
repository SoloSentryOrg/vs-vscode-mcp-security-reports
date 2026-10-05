#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independent fixed-origin consumer-policy readback for v2 bundle imports."""
from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import ssl
import stat
import subprocess
import sys

REPOSITORY = "SoloSentryOrg/vs-vscode-mcp-security-reports"
POLICY_PATH = "scripts/allowed-hyperlink-hosts.json"
ROOT_API = "/repos/" + REPOSITORY
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
SHA64 = re.compile(r"[0-9a-f]{64}\Z")
HOST = re.compile(r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}\Z")
MAX_API_BYTES = 256 * 1024
MAX_POLICY_BYTES = 64 * 1024
DEADLINE = 45


class PolicyError(ValueError):
    pass


def strict_json(raw: bytes):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise PolicyError("duplicate policy JSON key")
            result[key] = value
        return result
    def nonfinite(value):
        raise PolicyError("non-finite policy JSON value")
    try:
        return json.loads(raw, object_pairs_hook=unique, parse_constant=nonfinite)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise PolicyError("invalid policy JSON") from exc


def _api(path: str):
    connection = http.client.HTTPSConnection("api.github.com", timeout=10, context=ssl.create_default_context())
    try:
        connection.request("GET", path, headers={"Accept": "application/vnd.github+json",
                           "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "SoloSentry-public-citation-policy/1.0"})
        response = connection.getresponse()
        if response.status != 200:
            raise PolicyError("protected consumer policy read unavailable or redirected")
        raw = response.read(MAX_API_BYTES + 1)
        if len(raw) > MAX_API_BYTES:
            raise PolicyError("policy API response exceeds bound")
        value = strict_json(raw)
        if not isinstance(value, dict):
            raise PolicyError("policy API object is invalid")
        return value
    finally:
        connection.close()


def _protected_policy():
    branch = _api(ROOT_API + "/branches/main")
    commit = branch.get("commit", {})
    if (branch.get("protected") is not True or not isinstance(commit, dict)
            or not isinstance(commit.get("sha"), str) or not SHA40.fullmatch(commit["sha"])):
        raise PolicyError("protected consumer main is unverifiable")
    revision = commit["sha"]
    item = _api(ROOT_API + "/contents/" + POLICY_PATH + "?ref=" + revision)
    encoded = item.get("content")
    if (item.get("type") != "file" or item.get("path") != POLICY_PATH
            or item.get("encoding") != "base64" or not isinstance(encoded, str)
            or len(encoded) > MAX_POLICY_BYTES * 2):
        raise PolicyError("consumer policy source is invalid")
    raw = base64.b64decode(encoded.replace("\n", ""), validate=True)
    if not raw or len(raw) > MAX_POLICY_BYTES:
        raise PolicyError("consumer policy exceeds bound")
    blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw, usedforsecurity=False).hexdigest()
    if item.get("sha") != blob:
        raise PolicyError("consumer policy Git blob identity mismatch")
    value = strict_json(raw)
    if not isinstance(value, dict) or set(value) != {"hosts"}:
        raise PolicyError("consumer policy schema is invalid")
    hosts = value["hosts"]
    if (not isinstance(hosts, list) or not hosts or len(hosts) > 4096
            or any(not isinstance(host, str) for host in hosts)
            or hosts != sorted(set(hosts))
            or any(not HOST.fullmatch(host) or host.endswith((".local", ".internal", ".localhost")) for host in hosts)):
        raise PolicyError("consumer host policy is invalid")
    final = _api(ROOT_API + "/branches/main")
    if (final.get("protected") is not True or not isinstance(final.get("commit"), dict)
            or final["commit"].get("sha") != revision):
        raise PolicyError("protected consumer main changed during readback")
    return {"commit": revision, "sha256": hashlib.sha256(raw).hexdigest(), "hosts": hosts}


def read_protected_policy():
    try:
        worker = subprocess.run([sys.executable, "-I", str(Path(__file__).resolve()), "--read-protected-policy"],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                env={key: os.environ[key] for key in ("SYSTEMROOT", "WINDIR") if key in os.environ}, timeout=DEADLINE)
    except subprocess.TimeoutExpired as exc:
        raise PolicyError("consumer policy worker deadline exceeded") from exc
    if worker.returncode != 0 or len(worker.stdout) > MAX_API_BYTES:
        raise PolicyError("consumer policy worker failed")
    result = strict_json(worker.stdout)
    if (not isinstance(result, dict) or set(result) != {"commit", "sha256", "hosts"}
            or not isinstance(result["commit"], str) or not SHA40.fullmatch(result["commit"])
            or not isinstance(result["sha256"], str) or not SHA64.fullmatch(result["sha256"])
            or not isinstance(result["hosts"], list) or not result["hosts"] or len(result["hosts"]) > 4096
            or any(not isinstance(host, str) or not HOST.fullmatch(host)
                   or host.endswith((".local", ".internal", ".localhost")) for host in result["hosts"])
            or result["hosts"] != sorted(set(result["hosts"]))):
        raise PolicyError("consumer policy worker result is invalid")
    return result


def validate_policy_binding(binding: object, root: Path) -> set[str]:
    if (not isinstance(binding, dict) or set(binding) != {"commit", "sha256"}
            or not isinstance(binding["commit"], str) or not SHA40.fullmatch(binding["commit"])
            or not isinstance(binding["sha256"], str) or not SHA64.fullmatch(binding["sha256"])):
        raise PolicyError("bundle consumer policy binding is invalid")
    current = read_protected_policy()
    if any(binding[key] != current[key] for key in binding):
        raise PolicyError("bundle consumer policy binding is stale")
    # Independent local policy must match protected main; never use bundle hosts.
    path = root / POLICY_PATH
    if root.is_symlink() or (root / "scripts").is_symlink():
        raise PolicyError("local policy parent must not be a symlink")
    raw = bounded_file(path, MAX_POLICY_BYTES)
    if hashlib.sha256(raw).hexdigest() != current["sha256"]:
        raise PolicyError("local policy differs from protected main")
    return set(current["hosts"])


def bounded_file(path: Path, maximum: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum:
            raise PolicyError("input is not a bounded regular file")
        raw = os.read(descriptor, maximum + 1)
        after = os.fstat(descriptor)
        identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        if len(raw) != before.st_size or identity(before) != identity(after):
            raise PolicyError("input changed during acquisition")
    finally:
        os.close(descriptor)
    return raw


if __name__ == "__main__":
    try:
        if sys.argv[1:] != ["--read-protected-policy"]:
            raise PolicyError("unsupported policy reader command")
        result = json.dumps(_protected_policy(), separators=(",", ":")).encode()
        if len(result) > MAX_API_BYTES:
            raise PolicyError("policy worker output exceeds bound")
        sys.stdout.buffer.write(result)
    except (PolicyError, OSError, ValueError, http.client.HTTPException):
        raise SystemExit(1)

# SPDX-License-Identifier: MIT
"""Consumer-owned policy verification uses offline fixtures, never producer trust."""
import base64
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import citation_policy_binding as policy

RAW = b'{"hosts":["a.example"]}'
COMMIT = "a" * 40
DIGEST = hashlib.sha256(RAW).hexdigest()


class PolicyBindingTests(unittest.TestCase):
    def fixture(self):
        branch = {"protected": True, "commit": {"sha": COMMIT}}
        item = {"type": "file", "path": policy.POLICY_PATH, "encoding": "base64",
                "content": base64.b64encode(RAW).decode(),
                "sha": hashlib.sha1(b"blob " + str(len(RAW)).encode() + b"\0" + RAW, usedforsecurity=False).hexdigest()}
        return branch, item

    def test_exact_protected_policy_and_git_blob(self):
        branch, item = self.fixture()
        with patch.object(policy, "_api", side_effect=[branch, item, branch]) as api:
            self.assertEqual(policy._protected_policy(), {"commit": COMMIT, "sha256": DIGEST, "hosts": ["a.example"]})
            self.assertEqual(api.call_args_list[1].args[0], policy.ROOT_API + "/contents/" + policy.POLICY_PATH + "?ref=" + COMMIT)

    def test_unprotected_changed_or_corrupt_policy_fails(self):
        branch, item = self.fixture()
        cases = [[{"protected": False, "commit": branch["commit"]}],
                 [branch, {**item, "sha": "0" * 40}],
                 [branch, item, {"protected": True, "commit": {"sha": "b" * 40}}]]
        for responses in cases:
            with patch.object(policy, "_api", side_effect=responses), self.assertRaises(policy.PolicyError):
                policy._protected_policy()

    def test_worker_deadline_has_no_auth_proxy_or_certificate_context(self):
        with patch.object(policy.subprocess, "run", side_effect=subprocess.TimeoutExpired("fixture", 1)) as run, self.assertRaises(policy.PolicyError):
            policy.read_protected_policy()
        self.assertEqual(run.call_args.kwargs["timeout"], 45)
        self.assertIn("-I", run.call_args.args[0])
        self.assertTrue(set(run.call_args.kwargs["env"]) <= {"SYSTEMROOT", "WINDIR"})

    def test_worker_wrong_identity_duplicate_json_and_oversize_fail(self):
        results = [b'{"commit":"a","sha256":"b","hosts":[]}', b'{"a":1,"a":2}', b"x" * (policy.MAX_API_BYTES + 1)]
        for result in results:
            with patch.object(policy.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, result)), self.assertRaises(policy.PolicyError):
                policy.read_protected_policy()

    def test_stale_binding_or_modified_local_policy_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); path = root / policy.POLICY_PATH
            path.parent.mkdir(); path.write_bytes(RAW)
            current = {"commit": COMMIT, "sha256": DIGEST, "hosts": ["a.example"]}
            with patch.object(policy, "read_protected_policy", return_value=current):
                self.assertEqual(policy.validate_policy_binding({"commit": COMMIT, "sha256": DIGEST}, root), {"a.example"})
                for binding in [{"commit": "b" * 40, "sha256": DIGEST}, {"commit": COMMIT, "sha256": "0" * 64}, {"commit": COMMIT, "sha256": DIGEST, "hosts": ["evil.example"]}]:
                    with self.assertRaises(policy.PolicyError):
                        policy.validate_policy_binding(binding, root)
                path.write_bytes(b'{"hosts":["evil.example"]}')
                with self.assertRaises(policy.PolicyError):
                    policy.validate_policy_binding({"commit": COMMIT, "sha256": DIGEST}, root)


if __name__ == "__main__":
    unittest.main()

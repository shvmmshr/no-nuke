"""
Adapter tests: command normalization (Claude string vs Codex argv array),
apply_patch path extraction, and end-to-end hook decisions for both harnesses.

Run: python3 -m unittest discover -s tests
"""

import importlib.util
import json
import os
import subprocess
import sys
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_HOOK = os.path.join(_ROOT, "hooks", "no_nuke.py")

_spec = importlib.util.spec_from_file_location("no_nuke_hook", _HOOK)
hook = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(hook)


class NormalizeCommandTests(unittest.TestCase):
    def test_string_passthrough(self):
        self.assertEqual(
            hook._normalize_command({"command": "rm -rf /"}), "rm -rf /")

    def test_bash_lc_array_extracts_script(self):
        self.assertEqual(
            hook._normalize_command({"command": ["bash", "-lc", "rm -rf /"]}),
            "rm -rf /")

    def test_sh_c_array_extracts_script(self):
        self.assertEqual(
            hook._normalize_command({"command": ["sh", "-c", "git reset --hard"]}),
            "git reset --hard")

    def test_direct_argv_array_reconstructs(self):
        out = hook._normalize_command({"command": ["rm", "-rf", "/etc"]})
        self.assertIn("rm", out)
        self.assertIn("-rf", out)
        self.assertIn("/etc", out)

    def test_missing_command_returns_none(self):
        self.assertIsNone(hook._normalize_command({}))


class ApplyPatchTests(unittest.TestCase):
    def test_extracts_update_and_add_and_delete(self):
        patch = (
            "*** Begin Patch\n"
            "*** Update File: src/app.py\n"
            "*** Add File: .env\n"
            "*** Delete File: old.txt\n"
            "*** End Patch\n"
        )
        paths = hook._apply_patch_paths({"patch": patch})
        self.assertEqual(paths, ["src/app.py", ".env", "old.txt"])

    def test_no_patch(self):
        self.assertEqual(hook._apply_patch_paths({}), [])


def _run_hook(event, *args):
    p = subprocess.run(
        [sys.executable, _HOOK, *args],
        input=json.dumps(event), capture_output=True, text=True)
    out = p.stdout.strip()
    return json.loads(out) if out else None


class EndToEndHookTests(unittest.TestCase):
    def test_codex_array_rm_rf_root_denied(self):
        res = _run_hook(
            {"tool_name": "shell",
             "tool_input": {"command": ["bash", "-lc", "rm -rf /"]},
             "cwd": "/tmp"}, "--harness", "codex")
        self.assertEqual(
            res["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_codex_warn_emits_nothing(self):
        res = _run_hook(
            {"tool_name": "shell",
             "tool_input": {"command": ["bash", "-lc", "docker system prune -a"]},
             "cwd": "/tmp"}, "--harness", "codex")
        self.assertIsNone(res)  # no decision on warn under codex

    def test_codex_apply_patch_env_asks(self):
        res = _run_hook(
            {"tool_name": "apply_patch",
             "tool_input": {"patch": "*** Update File: .env\n+X=1\n"},
             "cwd": "/tmp"})
        self.assertEqual(
            res["hookSpecificOutput"]["permissionDecision"], "ask")

    def test_claude_string_deny(self):
        res = _run_hook(
            {"tool_name": "Bash",
             "tool_input": {"command": "rm -rf /"}, "cwd": "/tmp"})
        self.assertEqual(
            res["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_claude_warn_defers_with_context(self):
        res = _run_hook(
            {"tool_name": "Bash",
             "tool_input": {"command": "docker system prune -a"},
             "cwd": "/tmp"})
        self.assertEqual(
            res["hookSpecificOutput"]["permissionDecision"], "defer")
        self.assertIn("additionalContext", res["hookSpecificOutput"])

    def test_allow_emits_nothing(self):
        res = _run_hook(
            {"tool_name": "Bash", "tool_input": {"command": "ls -la"},
             "cwd": "/tmp"})
        self.assertIsNone(res)

    def test_malformed_event_asks(self):
        p = subprocess.run(
            [sys.executable, _HOOK], input="not json",
            capture_output=True, text=True)
        res = json.loads(p.stdout)
        self.assertEqual(
            res["hookSpecificOutput"]["permissionDecision"], "ask")


if __name__ == "__main__":
    unittest.main()

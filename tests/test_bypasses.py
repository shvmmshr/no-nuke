"""
Regression tests for ways a destructive command used to slip past the guard.

Each case here was an ALLOW (or a too-soft ASK) before the fix that added it.
Run: python3 -m unittest discover -s tests   (from the repo root)
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import check  # noqa: E402
from engine.config import Config  # noqa: E402

CWD = "/Users/example/Developer/project-plans/skill/no-nuke"


def action(cmd):
    return check(cmd, cwd=CWD, config=Config.default()).action


class WrapperTests(unittest.TestCase):
    """Wrappers that run another command must not hide it."""

    def test_wrappers_are_unwrapped(self):
        for cmd in (
            "nohup rm -rf /",
            "time rm -rf /",
            "time -p rm -rf /",
            "timeout 5 rm -rf /",
            "timeout -s KILL 5 rm -rf /",
            "nice rm -rf /",
            "nice -n 10 rm -rf /",
            "env -i rm -rf /",
            "env -u PATH FOO=1 rm -rf /",
            "command rm -rf /",
            "exec rm -rf /",
            "builtin command rm -rf /",
            "nohup nice timeout 5 rm -rf /",
        ):
            with self.subTest(cmd=cmd):
                self.assertEqual(action(cmd), "deny")

    def test_sudo_with_options_still_sees_the_command(self):
        for cmd in ("sudo -u root rm -rf /", "sudo -E rm -rf /",
                    "sudo -- rm -rf /", "doas -u root rm -rf /"):
            with self.subTest(cmd=cmd):
                self.assertEqual(action(cmd), "deny")

    def test_wrapped_benign_commands_stay_allowed(self):
        for cmd in ("nohup npm start", "time make build", "nice -n 5 pytest",
                    "timeout 30 npm test", "command -v rm", "env FOO=1 ls"):
            with self.subTest(cmd=cmd):
                self.assertEqual(action(cmd), "allow")


class ShellSyntaxTests(unittest.TestCase):
    """Grouping and control-flow keywords must not hide the command."""

    def test_grouping_and_keywords(self):
        for cmd in (
            "(rm -rf /)",
            "( rm -rf / )",
            "{ rm -rf /; }",
            "! rm -rf /",
            "if true; then rm -rf /; fi",
            "if rm -rf /; then echo ok; fi",
            "for f in a; do rm -rf /; done",
            "while true; do rm -rf /; done",
            "until false; do rm -rf /; done",
            "if false; then :; else rm -rf /; fi",
        ):
            with self.subTest(cmd=cmd):
                self.assertEqual(action(cmd), "deny")

    def test_benign_control_flow_allowed(self):
        for cmd in ("for f in *.md; do echo $f; done",
                    "if [ -f x ]; then cat x; fi", "(cd src && ls)"):
            with self.subTest(cmd=cmd):
                self.assertEqual(action(cmd), "allow")


if __name__ == "__main__":
    unittest.main()

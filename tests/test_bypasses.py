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


class BackgroundAndSubstitutionTests(unittest.TestCase):
    """Commands after & and inside substitutions run too."""

    def test_command_after_background_ampersand(self):
        for cmd in ("sleep 1 & rm -rf /", "true & git push -f origin main"):
            with self.subTest(cmd=cmd):
                self.assertEqual(action(cmd), "deny")

    def test_substitution_contents_are_checked(self):
        for cmd in ("echo $(rm -rf /)", 'echo "$(rm -rf /)"',
                    "echo `rm -rf /`", "cat <(rm -rf /)",
                    "x=$(git push --force origin main)"):
            with self.subTest(cmd=cmd):
                self.assertEqual(action(cmd), "deny")

    def test_redirections_with_ampersand_stay_allowed(self):
        for cmd in ("npm run build 2>&1 | tail -5", "sleep 2 & echo done",
                    "make &> build.log", "echo hi >&2", "make |& tee log",
                    "echo $(date)", "echo `whoami`"):
            with self.subTest(cmd=cmd):
                self.assertEqual(action(cmd), "allow")


class PathSpellingTests(unittest.TestCase):
    """Other spellings of root, home and the project must match too."""

    def test_root_home_and_parent_spellings_denied(self):
        for cmd in ("rm -rf /*", "rm -rf ~/", "rm -rf ~/*", "rm -rf $HOME/",
                    "rm -rf ${HOME}", "rm -rf ${HOME}/", "rm -rf \"$HOME\"/",
                    "rm -rf ../", "rm -rf ./", "rm -rf $PWD",
                    "rm -rf ~/Developer/*", "rm -rf ${HOME}/.ssh"):
            with self.subTest(cmd=cmd):
                self.assertEqual(action(cmd), "deny")

    def test_scoped_globs_are_not_escalated(self):
        self.assertEqual(action("rm -rf build/*"), "ask")
        self.assertEqual(action("rm *.log"), "allow")
        self.assertEqual(action("rm -rf ~/Developer/app/build"), "ask")


class GitPushRefspecTests(unittest.TestCase):
    """Every way of forcing or deleting a protected branch."""

    def test_force_or_delete_protected_branch_denied(self):
        for cmd in ("git push -fu origin main", "git push origin +main",
                    "git push --force origin HEAD:main",
                    "git push -f origin refs/heads/main",
                    "git push origin +HEAD:master",
                    "git push origin --delete main", "git push origin -d main",
                    "git push origin :main", "git push origin :refs/heads/main"):
            with self.subTest(cmd=cmd):
                self.assertEqual(action(cmd), "deny")

    def test_force_push_other_branch_asks(self):
        self.assertEqual(action("git push origin +feature"), "ask")
        self.assertEqual(action("git push -fu origin feature"), "ask")

    def test_delete_other_remote_branch_warns(self):
        self.assertEqual(action("git push origin --delete feature"), "warn")
        self.assertEqual(action("git push origin :feature"), "warn")

    def test_normal_pushes_allowed(self):
        for cmd in ("git push origin main", "git push -u origin main",
                    "git push origin feature:feature", "git push origin HEAD",
                    "git push --force-with-lease origin main", "git push --tags",
                    "git push origin main:mainline"):
            with self.subTest(cmd=cmd):
                self.assertEqual(action(cmd), "allow")


class XargsTests(unittest.TestCase):
    """xargs runs the command after its own options, with stdin as targets."""

    def test_inner_flags_are_kept(self):
        self.assertEqual(action("ls | xargs rm -rf build"), "ask")
        self.assertEqual(action("xargs -0 -n 1 rm -rf build"), "ask")
        self.assertEqual(action("xargs rm -rf /"), "deny")

    def test_delete_with_targets_from_stdin(self):
        self.assertEqual(action("find . -name x | xargs rm -rf"), "ask")
        self.assertEqual(action("find . | xargs -I{} rm -rf {}"), "ask")
        self.assertEqual(action("find . -name '*.pyc' | xargs rm"), "warn")

    def test_benign_xargs_allowed(self):
        self.assertEqual(action("echo a b | xargs echo"), "allow")
        self.assertEqual(action("git ls-files | xargs wc -l"), "allow")


class MoveOverwriteTests(unittest.TestCase):
    """Moving a protected path away, or writing over one, needs a human."""

    def test_moving_protected_paths_asks(self):
        for cmd in ("mv .git /tmp/x", "mv ~/.ssh /tmp/keys",
                    "mv ~/Developer /tmp/dev", "mv .env .env.bak"):
            with self.subTest(cmd=cmd):
                self.assertEqual(action(cmd), "ask")

    def test_overwriting_protected_files_asks(self):
        for cmd in ("mv notes.txt .env", "cp /dev/null .env",
                    "cp .env.example .env", "truncate -s 0 .env",
                    "mv -f key.new id_ed25519"):
            with self.subTest(cmd=cmd):
                self.assertEqual(action(cmd), "ask")

    def test_no_clobber_copies_allowed(self):
        self.assertEqual(action("cp -n .env.example .env"), "allow")
        self.assertEqual(action("cp --no-clobber .env.example .env"), "allow")

    def test_templates_are_not_secrets(self):
        for cmd in ("rm .env.example", "mv .env.example .env.sample",
                    "cp .env.example .env.local.example", "rm config.pem.dist"):
            with self.subTest(cmd=cmd):
                self.assertEqual(action(cmd), "allow")

    def test_ordinary_moves_allowed(self):
        for cmd in ("mv a.txt b.txt", "cp -r src dist", "truncate -s 0 app.log"):
            with self.subTest(cmd=cmd):
                self.assertEqual(action(cmd), "allow")


if __name__ == "__main__":
    unittest.main()

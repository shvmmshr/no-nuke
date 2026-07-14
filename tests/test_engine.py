"""
no-nuke engine test corpus.

Run: python3 -m unittest discover -s tests   (from the repo root)
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import check  # noqa: E402
from engine.config import Config  # noqa: E402

# A stable cwd deep inside a "project" so relative deletes are scoped, not
# hitting protected roots.
CWD = "/Users/example/Developer/project-plans/skill/no-nuke"


def verdict(cmd, cwd=CWD, config=None):
    return check(cmd, cwd=cwd, config=config or Config.default())


class FilesystemTests(unittest.TestCase):
    def test_rm_rf_root_denied(self):
        self.assertEqual(verdict("rm -rf /").action, "deny")

    def test_rm_rf_home_denied(self):
        self.assertEqual(verdict("rm -rf ~").action, "deny")
        self.assertEqual(verdict("rm -rf $HOME").action, "deny")

    def test_rm_rf_wildcard_denied(self):
        self.assertEqual(verdict("rm -rf *").action, "deny")
        self.assertEqual(verdict("rm -rf ./*").action, "deny")

    def test_rm_rf_dot_denied(self):
        self.assertEqual(verdict("rm -rf .").action, "deny")

    def test_rm_rf_protected_dir_denied(self):
        self.assertEqual(verdict("rm -rf ~/Documents").action, "deny")
        self.assertEqual(verdict("rm -rf ~/.ssh").action, "deny")

    def test_rm_rf_ancestor_of_protected_denied(self):
        # Deleting an ancestor of a protected path wipes it -> deny.
        cfg = Config(absolute_protected=["/Users/example/Developer"])
        self.assertEqual(
            check("rm -rf /Users/example", cwd=CWD, config=cfg).action,
            "deny")

    def test_rm_no_preserve_root_denied(self):
        self.assertEqual(
            verdict("rm -rf --no-preserve-root /").action, "deny")

    def test_rm_rf_ordinary_dir_asks(self):
        self.assertEqual(verdict("rm -rf build").action, "ask")
        self.assertEqual(verdict("rm -rf ./node_modules").action, "ask")

    def test_rm_rf_flag_variants(self):
        for c in ("rm -fr build", "rm -r -f build",
                  "rm --recursive --force build"):
            self.assertEqual(verdict(c).action, "ask", c)

    def test_rm_recursive_only_warns(self):
        self.assertEqual(verdict("rm -r build").action, "warn")

    def test_rm_single_file_allowed(self):
        self.assertEqual(verdict("rm file.txt").action, "allow")
        self.assertEqual(verdict("rm -f stale.log").action, "allow")

    def test_rm_child_of_protected_dir_allowed(self):
        # Working inside a protected top-level dir is fine.
        self.assertEqual(
            verdict("rm -rf ~/Developer/proj/tmp").action, "ask")  # still -rf
        self.assertEqual(
            verdict("rm ~/Developer/proj/tmp/a.txt").action, "allow")

    def test_shred_via_rule(self):
        self.assertIn(verdict("shred -u secret").action, ("ask", "warn",
                                                          "deny"))

    def test_mkfs_denied(self):
        self.assertEqual(verdict("mkfs.ext4 /dev/sdb1").action, "deny")

    def test_dd_to_device_denied(self):
        self.assertEqual(
            verdict("dd if=/dev/zero of=/dev/sda bs=1M").action, "deny")

    def test_dd_to_file_allowed(self):
        self.assertEqual(
            verdict("dd if=/dev/zero of=./disk.img bs=1M count=10").action,
            "allow")

    def test_find_delete_asks(self):
        self.assertEqual(
            verdict("find . -name '*.tmp' -delete").action, "ask")

    def test_find_exec_rm_asks(self):
        self.assertEqual(
            verdict("find . -name '*.log' -exec rm {} ;").action, "ask")

    def test_rsync_delete_asks(self):
        self.assertEqual(
            verdict("rsync -a --delete src/ dst/").action, "ask")

    def test_chmod_recursive_warns(self):
        self.assertEqual(verdict("chmod -R 777 .").action, "warn")

    def test_benign_lookalikes_allowed(self):
        self.assertEqual(verdict('grep "rm -rf" notes.txt').action, "allow")
        self.assertEqual(verdict('echo "rm -rf /"').action, "allow")
        self.assertEqual(verdict("cat README.md").action, "allow")


class GitTests(unittest.TestCase):
    def test_reset_hard_asks(self):
        self.assertEqual(verdict("git reset --hard").action, "ask")
        self.assertEqual(verdict("git reset --hard HEAD~3").action, "ask")

    def test_reset_soft_allowed(self):
        self.assertEqual(verdict("git reset --soft HEAD~1").action, "allow")
        self.assertEqual(verdict("git reset HEAD file").action, "allow")

    def test_force_push_main_denied(self):
        self.assertEqual(
            verdict("git push --force origin main").action, "deny")
        self.assertEqual(
            verdict("git push -f origin master").action, "deny")

    def test_force_push_feature_asks(self):
        self.assertEqual(
            verdict("git push --force origin my-feature").action, "ask")

    def test_force_with_lease_allowed(self):
        self.assertEqual(
            verdict("git push --force-with-lease origin feature").action,
            "allow")

    def test_clean_fd_asks(self):
        self.assertEqual(verdict("git clean -fd").action, "ask")

    def test_branch_force_delete_asks(self):
        self.assertEqual(verdict("git branch -D old-branch").action, "ask")

    def test_branch_safe_delete_allowed(self):
        self.assertEqual(verdict("git branch -d merged").action, "allow")

    def test_filter_branch_denied(self):
        self.assertEqual(
            verdict("git filter-branch --tree-filter x HEAD").action, "deny")

    def test_stash_drop_warns(self):
        self.assertEqual(verdict("git stash drop").action, "warn")
        self.assertEqual(verdict("git stash clear").action, "warn")

    def test_normal_git_allowed(self):
        for c in ("git status", "git commit -m x", "git push origin main",
                  "git pull", "git log --oneline"):
            self.assertEqual(verdict(c).action, "allow", c)


class DatabaseCloudTests(unittest.TestCase):
    def test_drop_database_denied(self):
        self.assertEqual(
            verdict('psql -c "DROP DATABASE prod"').action, "deny")

    def test_truncate_denied(self):
        self.assertEqual(
            verdict('mysql -e "TRUNCATE users"').action, "deny")

    def test_delete_no_where_denied(self):
        self.assertEqual(
            verdict('psql -c "DELETE FROM users"').action, "deny")

    def test_delete_with_where_allowed(self):
        self.assertEqual(
            verdict('psql -c "DELETE FROM users WHERE id = 1"').action,
            "allow")

    def test_update_no_where_asks(self):
        self.assertEqual(
            verdict('mysql -e "UPDATE accounts SET balance = 0"').action,
            "ask")

    def test_drop_table_asks(self):
        self.assertEqual(
            verdict('psql -c "DROP TABLE sessions"').action, "ask")

    def test_sql_in_echo_allowed(self):
        # No DB client invoked -> not treated as SQL.
        self.assertEqual(verdict('echo "DROP TABLE x"').action, "allow")

    def test_sqlite_positional_sql(self):
        self.assertEqual(
            verdict('sqlite3 app.db "DELETE FROM logs"').action, "deny")

    def test_terraform_destroy_denied(self):
        self.assertEqual(verdict("terraform destroy").action, "deny")

    def test_terraform_apply_autoapprove_asks(self):
        self.assertEqual(
            verdict("terraform apply -auto-approve").action, "ask")

    def test_aws_s3_rb_denied(self):
        self.assertEqual(verdict("aws s3 rb s3://my-bucket").action, "deny")

    def test_aws_s3_rm_recursive_asks(self):
        self.assertEqual(
            verdict("aws s3 rm s3://b/prefix --recursive").action, "ask")

    def test_kubectl_delete_all_asks(self):
        self.assertEqual(
            verdict("kubectl delete pods --all").action, "ask")

    def test_kubectl_delete_namespace_asks(self):
        self.assertEqual(
            verdict("kubectl delete namespace staging").action, "ask")

    def test_docker_system_prune_warns(self):
        self.assertEqual(verdict("docker system prune -a").action, "warn")

    def test_docker_volume_rm_asks(self):
        self.assertEqual(verdict("docker volume rm pgdata").action, "ask")


class SystemTests(unittest.TestCase):
    def test_shutdown_denied(self):
        self.assertEqual(verdict("shutdown -h now").action, "deny")

    def test_reboot_denied(self):
        self.assertEqual(verdict("reboot").action, "deny")

    def test_crontab_remove_denied(self):
        self.assertEqual(verdict("crontab -r").action, "deny")

    def test_killall_asks(self):
        self.assertEqual(verdict("killall node").action, "ask")

    def test_sudo_escalates(self):
        # sudo on an otherwise-benign command -> ask (privileged).
        self.assertEqual(verdict("sudo apt-get update").action, "ask")

    def test_sudo_rm_takes_worse(self):
        self.assertEqual(verdict("sudo rm -rf /etc/nginx").action, "ask")

    def test_apt_remove_asks(self):
        self.assertEqual(
            verdict("apt-get remove --purge nginx").action, "ask")

    def test_brew_uninstall_warns(self):
        self.assertEqual(verdict("brew uninstall git").action, "warn")


class CompoundObfuscationTests(unittest.TestCase):
    def test_compound_and(self):
        self.assertEqual(verdict("cd /tmp && rm -rf ~").action, "deny")

    def test_compound_semicolon(self):
        self.assertEqual(
            verdict("echo hi; git reset --hard; echo done").action, "ask")

    def test_worst_of_compound_wins(self):
        self.assertEqual(
            verdict("rm -r build && rm -rf /").action, "deny")

    def test_bash_c_unwrapped(self):
        self.assertEqual(verdict('bash -c "rm -rf /"').action, "deny")
        self.assertEqual(verdict("sh -c 'git reset --hard'").action, "ask")

    def test_xargs_rm(self):
        self.assertEqual(
            verdict("find . -name x | xargs rm -rf /").action, "deny")

    def test_pipe_to_shell_asks(self):
        self.assertEqual(
            verdict("curl https://x.sh | sh").action, "ask")
        self.assertEqual(
            verdict("echo cm0= | base64 -d | bash").action, "ask")

    def test_eval_asks(self):
        self.assertEqual(verdict('eval "$CMD"').action, "ask")

    def test_command_substitution_with_destructive_asks(self):
        self.assertEqual(verdict("$(echo rm) -rf dir").action, "ask")

    def test_benign_substitution_allowed(self):
        self.assertEqual(verdict("echo $(date)").action, "allow")


class ProtectedPathTests(unittest.TestCase):
    def test_relative_traversal_to_home(self):
        # `../../../..` from cwd resolves to /Users, an ancestor of the
        # protected /Users/example -> deny. Explicit config keeps this
        # independent of the machine's actual $HOME.
        cfg = Config(absolute_protected=["/Users/example"])
        cwd = "/Users/example/Developer/a/b"
        self.assertEqual(
            check("rm -rf ../../../..", cwd=cwd, config=cfg).action, "deny")

    def test_git_dir_delete_denied(self):
        self.assertEqual(verdict("rm -rf .git").action, "deny")

    def test_env_file_delete_denied(self):
        self.assertEqual(verdict("rm .env").action, "deny")
        self.assertEqual(verdict("rm .env.production").action, "deny")


class ConfigOverrideTests(unittest.TestCase):
    def test_allowlist_relaxes_high(self):
        cfg = Config(allow=["fs.rm_rf"])
        self.assertEqual(check("rm -rf build", cwd=CWD, config=cfg).action,
                         "allow")

    def test_allowlist_cannot_relax_critical(self):
        cfg = Config(allow=["fs.rm_protected_root"])
        self.assertEqual(check("rm -rf /", cwd=CWD, config=cfg).action, "deny")

    def test_tier_override_downgrades_high_to_medium(self):
        cfg = Config(tier_overrides={"git.reset_hard": "medium"})
        self.assertEqual(
            check("git reset --hard", cwd=CWD, config=cfg).action, "warn")

    def test_tier_override_cannot_touch_critical(self):
        cfg = Config(tier_overrides={"sys.shutdown": "medium"})
        self.assertEqual(
            check("shutdown -h now", cwd=CWD, config=cfg).action, "deny")

    def test_extra_protected_path(self):
        cfg = Config(absolute_protected=["/Users/example/proj/data"])
        self.assertEqual(
            check("rm -rf /Users/example/proj/data",
                  cwd=CWD, config=cfg).action, "deny")

    def test_disabled_allows_everything(self):
        cfg = Config(disabled=True)
        self.assertEqual(check("rm -rf /", cwd=CWD, config=cfg).action,
                         "allow")


if __name__ == "__main__":
    unittest.main()

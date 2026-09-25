<!--
  no-nuke advisory snippet for Codex CLI.
  Codex reads AGENTS.md (not Claude-style skills), so append this block to your
  ~/.codex/AGENTS.md (global) or <repo>/.codex/AGENTS.md (project). It is purely
  advisory — the blocking enforcement is the PreToolUse hook. Do NOT replace
  your existing AGENTS.md; append.
-->

## Destructive-command guard (no-nuke)

This machine runs **no-nuke**, a PreToolUse guard that inspects every shell
command and file edit before it runs and may **deny**, **ask**, or **warn**.
When you see a message tagged `[no-nuke:<rule_id>]`, the guard has flagged the
command — **do not try to route around it** (no `bash -c`, base64, renaming,
wrappers like `nohup`/`timeout`/`sudo`, subshells, `$( )`, `python -c` or
`node -e`, or splitting to dodge the pattern; the guard inspects those too).
Take the safe
alternative it names, or explain to the human why the command is necessary and
let them decide.

Reach for these instead:

- `rm -rf <dir>` → move to trash / delete named paths; never `*`, `~`, `.`, `/`.
- `git reset --hard` → `git stash` first, or `git reset --soft`.
- `git push --force` → `git push --force-with-lease`; never force-push `main`.
- `DELETE`/`TRUNCATE`/`DROP` → add a `WHERE`, back up first, use a transaction.
- `terraform destroy` / `kubectl delete --all` → plan/review and confirm.
- Overwriting `.env` or keys → `cp -n`, and back up first.
- Prefer dry-run flags (`-n`, `--dry-run`, `--dryrun`) and back up before bulk
  or irreversible operations.

Never edit `.no-nuke.json` to weaken the guard, with a tool or from the shell;
both are blocked, and critical rules apply even when it says `disabled`.
You can check any command yourself: `no-nuke check "<command>"`.

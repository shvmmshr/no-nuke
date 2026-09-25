---
name: no-nuke
description: Use when a shell command, git operation, database statement, or file write could be destructive — or when a no-nuke guard denies/asks about a command. Explains why the guard fired and the safe alternative to use instead of trying to bypass it.
---

# no-nuke — working safely around the destructive-command guard

This project runs **no-nuke**, a PreToolUse guard that inspects every `Bash`,
`Write`, and `Edit` before it executes. It classifies commands into tiers:

- **deny** (critical) — the command is blocked. It will not run.
- **ask** (high) — the human is prompted to confirm before it runs.
- **warn** (medium) — it runs, but you're told why it's risky.

When you see a message tagged `[no-nuke:<rule_id>]`, the guard has flagged the
command. **Do not try to route around it** (no `bash -c`, base64 tricks,
renaming the command, wrapping it in `nohup`/`timeout`/`sudo`/a subshell/`$( )`,
moving it into `python -c` or `node -e`, or splitting it to dodge the pattern.
The guard inspects those too, and dodging a safety guard is never the right
move). Instead, take
the safe alternative it suggests, or explain to the human why you believe the
command is necessary and let them decide.

## Safe alternatives to reach for

| Instead of… | Do this |
|---|---|
| `rm -rf <dir>` | Move to trash (`trash <dir>` / `mv <dir> ~/.Trash/`) so it's recoverable; delete named paths, never `*`, `~`, `.`, or `/`. |
| `git reset --hard` | `git stash` first (recoverable), or `git reset --soft` to keep changes staged. |
| `git push --force` | `git push --force-with-lease` — refuses to clobber unexpected remote commits. Never force-push `main`/`master`. |
| `git clean -fd` | `git clean -n` (dry run) to see what would be deleted first. |
| `DELETE FROM t` / `TRUNCATE` | Add a `WHERE` clause; run inside a transaction so you can `ROLLBACK`; back up first. |
| `DROP DATABASE` / `DROP TABLE` | `pg_dump` / `mysqldump` a backup first and confirm the exact name. |
| `terraform destroy` | `terraform plan -destroy`, review it, get human sign-off. |
| `kubectl delete ... --all` | Delete named resources; double-check the namespace/context. |
| `docker system prune` | Review `docker ps -a` / `docker volume ls`; avoid `--volumes`. |
| bulk `chmod -R` / `chown -R` | Scope to specific files, or verify the tree first. |
| `cp .env.example .env` / overwriting a secrets file | `cp -n` so an existing file is never replaced; back it up first if it must change. |
| `find … \| xargs rm -rf` | Print the list first, review it, then delete the named paths. |

## General habits

- **Back up before bulk or irreversible operations.** A quick copy or `git
  stash` turns a mistake into a non-event.
- **Prefer dry-run flags** (`-n`, `--dry-run`, `--dryrun`) to preview.
- **Never disable the guard** by editing `.no-nuke.json`, with a tool or from
  the shell. Both are blocked, and critical rules apply even when the config
  says `disabled`. If a rule is wrong for this repo, tell the human so *they*
  can adjust the config.
- **When denied, stop and reconsider.** A denial usually means the command is
  broader or more dangerous than intended (wrong path, missing `WHERE`, a
  wildcard). Re-read the command before proposing anything.

## Checking a command yourself

You can ask the guard about any command via the CLI:

```
no-nuke check "rm -rf build"
```

It prints the verdict and exits `0` (allow/warn), `1` (ask), or `2` (deny).

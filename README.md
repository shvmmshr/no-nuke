<div align="center">

# no-nuke

**A destructive-command guard for AI coding agents.**

Stops your agent from `rm -rf`-ing the wrong folder, `git reset --hard`-ing your
work, or `DROP DATABASE`-ing prod — *before* the command runs.

[![tests](https://github.com/shvmmshr/no-nuke/actions/workflows/tests.yml/badge.svg)](https://github.com/shvmmshr/no-nuke/actions/workflows/tests.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![python: 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](#requirements)
[![zero deps](https://img.shields.io/badge/dependencies-0-green.svg)](#requirements)
[![works with](https://img.shields.io/badge/works%20with-Claude%20Code%20%7C%20Codex%20CLI-8A2BE2.svg)](#install)

</div>

---

AI agents occasionally run commands that wreck your machine. Plain instructions
don't help — a confused or prompt-injected agent ignores them. **no-nuke is hard
enforcement**: it hooks the agent *before* a command runs, inspects it
structurally (not a dumb substring match), and **blocks**, **asks**, or
**warns** — with a safe alternative for every block, protected paths, a
per-project config, and an audit log.

```console
$ no-nuke check "rm -rf /"
DENY: rm -rf /
  rule:   fs.rm_protected_root (critical)
  reason: `rm` targets a protected/wildcard location (/) — this can wipe your home or filesystem.
  safer:  Delete a specific named path, or move items to the trash instead.

$ no-nuke check 'grep "rm -rf" notes.txt'
ALLOW: grep "rm -rf" notes.txt        # structural parsing — not fooled by strings
```

## Contents

- [Why](#why) · [Features](#features) · [Install](#install) · [How it works](#how-it-works)
- [Tiers](#tiers) · [What it catches](#what-it-catches) · [Configuration](#configuration)
- [Audit log](#audit-log) · [CLI & other frameworks](#cli--other-frameworks)
- [Claude Code vs Codex](#claude-code-vs-codex) · [Adding rules](#adding-rules)
- [Limitations](#limitations) · [Contributing](#contributing) · [License](#license)

## Why

> "The agent deleted my project." "It force-pushed over main." "It dropped the
> dev database while 'cleaning up'."

Every AI-agent user eventually hits one of these. no-nuke is the seatbelt: it
can't stop *every* crash, but it stops the common catastrophes and the obvious
footguns, and it's honest — when it can't fully understand a command, it
escalates to *ask* instead of guessing.

## Features

- **Hard enforcement**, not advice — a `PreToolUse` hook the model can't ignore.
- **Structural parsing** — splits `&&`/`|`/`;`, unwraps `bash -c`, `xargs`, and
  `curl | sh`, so obfuscated commands are still caught while `grep "rm -rf"` is
  not falsely flagged.
- **Four categories** — filesystem, git, database/cloud, and system-level.
- **Tiered** — critical→deny, high→ask, medium→warn. Nothing else is touched.
- **Protected paths** — `/`, `~`, `~/.ssh`, `.git`, `.env`, and more can't be
  deleted or overwritten, even indirectly.
- **Per-project config** — relax rules per repo, but **critical rules can never
  be disabled**, and agents can't edit the config to disarm the guard.
- **Audit log** of everything flagged.
- **Works with Claude Code *and* OpenAI Codex CLI** from one adapter.
- **Zero dependencies** — pure Python 3 stdlib.

## Install

### Requirements

Python 3.8+ (standard library only — no `pip install`, no dependencies).

### Claude Code — as a plugin

```
/plugin marketplace add shvmmshr/no-nuke
/plugin install no-nuke
```

### Personal install (Claude Code and/or Codex)

```bash
git clone https://github.com/shvmmshr/no-nuke.git
cd no-nuke
./install.sh                 # Claude Code always; Codex too if ~/.codex exists
```

| Command | Effect |
|---|---|
| `./install.sh` | Auto: Claude Code always, Codex if `~/.codex` exists |
| `./install.sh --target codex` | Codex only |
| `./install.sh --target both` | Both, creating dirs as needed |
| `./install.sh --uninstall` | Remove (respects `--target`) |

- **Claude Code** → merges the hook into `~/.claude/settings.json` (backed up
  first). Restart / start a new session to activate.
- **Codex CLI** → writes `~/.codex/hooks.json`. **Then run `/hooks` in the Codex
  TUI and _trust_ the no-nuke hook** — Codex won't run an untrusted hook (trust
  is pinned to the file's content hash).

## How it works

A `PreToolUse` hook runs on every shell command and file edit. The command goes
to the engine, which:

1. **Splits** compound commands on `&&`, `||`, `;`, `|` (quote-aware).
2. **Unwraps** `bash -c`, `xargs`, and pipes-into-shell so hidden commands are
   still inspected.
3. **Parses** each sub-command into argv and runs structural checkers —
   filesystem, git, SQL, cloud, system — plus a declarative ruleset.
4. **Resolves protected paths**: deletes/overwrites targeting `/`, `~`, `.git`,
   `.env`, `~/.ssh`, … are denied — including a parent that *contains* them.
5. Returns the **highest-severity** verdict.

## Tiers

| Tier | Action | Meaning | Examples |
|------|--------|---------|----------|
| **critical** | **deny** | Blocked outright | `rm -rf /`, `dd of=/dev/sda`, force-push to `main`, `DROP DATABASE`, `terraform destroy`, `shutdown` |
| **high** | **ask** | Human must confirm | `rm -rf <dir>`, `git reset --hard`, `git clean -fd`, `DROP TABLE`, `kubectl delete --all`, any `sudo` |
| **medium** | **warn** | Runs, but flagged | `chmod -R`, `docker system prune`, `git stash drop`, `brew uninstall` |
| *none* | *allow* | Silent | everything else — the guard never auto-approves unrelated commands |

## What it catches

<details>
<summary><b>Filesystem</b> — rm, dd, shred, find -delete, chmod -R …</summary>

`rm -rf` on `/` `~` `*` `.` or protected paths → **deny**; on any dir → **ask**.
`dd of=/dev/*`, `mkfs`, `wipefs -a`, `fdisk /dev/*` → **deny**. `shred`,
`find -delete`, `find -exec rm`, `rsync --delete` → **ask**. `chmod -R`,
`chown -R` → **warn**. All flag orders handled (`-rf`, `-fr`, `-r -f`).
</details>

<details>
<summary><b>Git</b> — reset --hard, force-push, clean, filter-branch …</summary>

Force-push to `main`/`master`/`prod`, `filter-branch`, `filter-repo` → **deny**.
`reset --hard`, `clean -f`, `branch -D`, other force-push → **ask**.
`stash drop/clear`, `checkout -- .` → **warn**. `--force-with-lease`,
`reset --soft`, `branch -d`, normal push/pull/commit → **allow**.
</details>

<details>
<summary><b>Database & cloud</b> — DROP, TRUNCATE, DELETE, terraform, kubectl, aws …</summary>

`DROP DATABASE`, `TRUNCATE`, `DELETE`-without-`WHERE`, `terraform destroy`,
`aws s3 rb`, `dynamodb delete-table` → **deny**. `DROP TABLE`,
`UPDATE`-without-`WHERE`, `kubectl delete --all`/namespace/pv,
`aws s3 rm --recursive`, `docker volume rm`, `gcloud … delete` → **ask**.
`docker system prune`, `docker rmi`, `helm uninstall` → **warn**. SQL is only
flagged when an actual DB client runs it — `echo "DROP TABLE x"` is fine.
</details>

<details>
<summary><b>System</b> — shutdown, reboot, crontab -r, killall, package removal …</summary>

`shutdown`, `reboot`, `halt`, `crontab -r` → **deny**. `killall`, any `sudo`,
`apt remove/purge` → **ask**. `brew uninstall`, `pkill -9`, `npm uninstall -g`,
`launchctl unload`, `defaults delete` → **warn**.
</details>

## Configuration

Drop a `.no-nuke.json` at your repo root (see [`.no-nuke.example.json`](.no-nuke.example.json)):

```json
{
  "disabled": false,
  "allow": ["docker.system_prune"],
  "tier_overrides": { "git.reset_hard": "medium" },
  "protected_paths": ["./data", "./migrations"],
  "protected_names": ["*.pem"]
}
```

| Field | Effect |
|-------|--------|
| `allow` | Rule IDs to downgrade to *allow*. |
| `tier_overrides` | Remap a rule's tier (e.g. `high` → `medium`). |
| `protected_paths` | Extra dirs to protect from deletion. |
| `protected_names` | Extra basename globs to protect (e.g. `*.pem`). |
| `disabled` | Turn the guard off for this repo. |

> **Safety guardrail:** config can only relax **high/medium** rules. **Critical
> rules can never be disabled or downgraded**, and agents are blocked from
> editing `.no-nuke.json` itself — so the guard can't be disarmed from inside a
> session.

## Audit log

Every non-allow event is appended to `~/.no-nuke/audit.jsonl`:

```json
{"ts":"2026-07-14T10:30:00","tool":"Bash","cwd":"/repo","command":"rm -rf /","action":"deny","tier":"critical","rule_id":"fs.rm_protected_root","reason":"…"}
```

## CLI & other frameworks

The engine is harness-agnostic. Any agent framework can gate on the exit code:

```bash
no-nuke check "<command>" [--cwd DIR] [--json]
#  exit 0 = allow/warn   1 = ask   2 = deny
```

Or import it directly:

```python
from engine import check, load_config
v = check("rm -rf build", cwd="/repo", config=load_config("/repo"))
print(v.action, v.rule_id, v.reason)   # ask fs.rm_rf  Recursive force delete …
```

## Claude Code vs Codex

Codex CLI adopted the same `PreToolUse` hook contract as Claude Code, so one
adapter (`hooks/no_nuke.py`) serves both — it absorbs the differences:

| | Claude Code | Codex CLI |
|---|---|---|
| Shell command | `command` string | often argv array `["bash","-lc","…"]` (normalized) |
| Edit tool | `Write` / `Edit` / `MultiEdit` | `apply_patch` (paths parsed from the patch) |
| allow / warn | `defer` (+ context on warn) | emit no decision → Codex's own approval flow |
| deny / ask | `permissionDecision` | same |

Codex's `rules`/execpolicy (Starlark) and OS sandbox are complementary layers;
no-nuke is the content-aware, cross-harness one.

## Adding rules

Straightforward `command + tokens → tier` rules go in
[`rules/rules.json`](rules/rules.json). Context-sensitive checks (protected
paths, git history, SQL `WHERE`-clauses, shell unwrapping) live in
[`engine/engine.py`](engine/engine.py). Add a test to
[`tests/`](tests/) and run:

```bash
python3 -m unittest discover -s tests
```

## Limitations

no-nuke is a **safety net, not a sandbox.** It raises the bar against accidents
and obvious footguns; a determined adversary with shell access can still craft
payloads it doesn't recognize. For genuinely untrusted agents, also run them in
a real sandbox (container / VM). no-nuke's job is to stop the *common*
catastrophes — and to escalate to *ask* whenever it can't be sure.

## Contributing

Issues and PRs welcome — especially new rules and false-positive reports. Please
include a test case (a command + its expected tier) with any rule change. The
whole engine is dependency-free Python, so `python3 -m unittest discover -s
tests` is the entire CI.

## License

[MIT](LICENSE) © shvmmshr

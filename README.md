# no-nuke 🚫☢️

**A destructive-command guard for AI coding agents.** Works with **Claude Code**
and **OpenAI Codex CLI**.

AI agents occasionally run commands that wreck your machine — `rm -rf` the wrong
directory, `git reset --hard` over your work, `DROP DATABASE` on prod. Plain
instructions don't help: a confused or prompt-injected agent ignores them.

no-nuke is **hard enforcement**. It hooks into the agent *before* a command
runs, inspects it structurally (not just a substring match), and **blocks**,
**asks**, or **warns** based on a tiered ruleset — with protected paths, a
per-project config, an audit log, and a safe-alternative suggestion for every
block.

```
$ no-nuke check "rm -rf /"
DENY: rm -rf /
  rule:   fs.rm_protected_root (critical)
  reason: `rm` targets a protected/wildcard location (/) — this can wipe your home or filesystem.
  safer:  Delete a specific named path, or move items to the trash instead.
```

## How it works

A `PreToolUse` hook runs on every `Bash`, `Write`, and `Edit`. The command goes
to the engine, which:

1. **Splits** compound commands on `&&`, `||`, `;`, `|` (quote-aware).
2. **Unwraps** `bash -c`, `xargs`, and pipes-into-shell so hidden commands are
   still inspected.
3. **Parses** each sub-command into argv and runs structural checkers —
   filesystem, git, SQL, cloud, system — plus a declarative ruleset.
4. **Resolves protected paths**: `rm`/`dd`/redirects targeting `/`, `~`,
   `~/Documents`, `.git`, `.env`, `~/.ssh`, … are denied.
5. Returns the **highest-severity** verdict.

## Tiers

| Tier | Action | Meaning | Examples |
|------|--------|---------|----------|
| **critical** | **deny** | Blocked outright | `rm -rf /`, `dd of=/dev/sda`, force-push to `main`, `DROP DATABASE`, `terraform destroy`, `shutdown` |
| **high** | **ask** | Human must confirm | `rm -rf <dir>`, `git reset --hard`, `git clean -fd`, `DROP TABLE`, `kubectl delete --all`, any `sudo` |
| **medium** | **warn** | Runs, but flagged | `chmod -R`, `docker system prune`, `git stash drop`, `brew uninstall` |

Everything else is allowed silently (the guard defers to your normal permission
flow — it never auto-approves unrelated commands).

## Install

### As a Claude Code plugin (shareable)

Add this repo as a plugin so the hook + skill install together:

```
/plugin marketplace add <this-repo-url>
/plugin install no-nuke
```

### Personal install (this machine)

```
./install.sh                 # Claude Code always; Codex too if ~/.codex exists
./install.sh --target codex  # Codex only
./install.sh --target both   # both
./install.sh --uninstall     # remove (respects --target)
```

- **Claude Code** → merges the hook into `~/.claude/settings.json` (backed up
  first). Restart / start a new session to activate.
- **Codex CLI** → writes `~/.codex/hooks.json` with `--harness codex`. **Then
  run `/hooks` in the Codex TUI and *trust* the no-nuke hook** — Codex will not
  run an untrusted hook (trust is pinned to the file's content hash).

Requires `python3` (stdlib only — zero dependencies).

### How the two harnesses differ (and why one adapter works)

Codex CLI adopted the same `PreToolUse` hook contract as Claude Code (stdin JSON
event → stdout `hookSpecificOutput` decision), so `hooks/no_nuke.py` serves
both. It absorbs the differences automatically:

| | Claude Code | Codex CLI |
|---|---|---|
| Shell command | `tool_input.command` string | often an argv array `["bash","-lc","…"]` (normalized) |
| Edit tool | `Write` / `Edit` / `MultiEdit` (`file_path`) | `apply_patch` (paths parsed from the patch) |
| allow / warn | `defer` (+ `additionalContext` on warn) | emit no decision → Codex's own approval flow |
| deny / ask | `permissionDecision: deny` / `ask` | same |

Codex also has a separate `rules`/execpolicy layer (Starlark, for the
sandbox-escalation gate) and OS sandboxing — no-nuke complements those; it is the
content-aware, cross-harness layer.

## Per-project config

Drop a `.no-nuke.json` at your repo root to tune behavior. It can only **relax
high/medium** rules — **critical rules can never be disabled or downgraded**,
and agents are blocked from editing this file, so the guard can't be disarmed
from inside a session.

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
| `disabled` | Turn the guard off for this repo (non-critical rules only still can't re-enable critical bypass; `disabled` allows all — use with care). |
| `allow` | Rule IDs to downgrade to allow. |
| `tier_overrides` | Remap a rule's tier (e.g. `high` → `medium`). |
| `protected_paths` | Extra absolute/relative dirs to protect from deletion. |
| `protected_names` | Extra basename globs to protect (e.g. `*.pem`). |

## Audit log

Every non-allow event is appended to `~/.no-nuke/audit.jsonl`:

```json
{"ts":"2026-07-14T10:30:00","tool":"Bash","cwd":"/repo","command":"rm -rf /","action":"deny","tier":"critical","rule_id":"fs.rm_protected_root","reason":"..."}
```

## CLI / other frameworks

The engine is framework-agnostic. Any agent can gate on the CLI's exit code:

```
no-nuke check "<command>" [--cwd DIR] [--json]
#  exit 0 = allow/warn, 1 = ask, 2 = deny
```

Or import the engine directly:

```python
from engine import check, load_config
v = check("rm -rf build", cwd="/repo", config=load_config("/repo"))
print(v.action, v.rule_id, v.reason)
```

## Adding rules

Straightforward `command + tokens → tier` rules go in
[`rules/rules.json`](rules/rules.json). Context-sensitive checks (protected
paths, git history, SQL `WHERE`-clauses, shell unwrapping) live in
[`engine/engine.py`](engine/engine.py). Add a test to
[`tests/test_engine.py`](tests/test_engine.py) and run:

```
python3 -m unittest discover -s tests
```

## Limitations

no-nuke is a **safety net, not a sandbox**. It raises the bar against accidents
and obvious footguns; a determined adversary with shell access can still
construct payloads it doesn't recognize. Run untrusted agents in a real sandbox
(container/VM) as well. no-nuke's job is to stop the *common* catastrophes —
and it's honest about escalating to "ask" whenever it can't fully parse a
command.

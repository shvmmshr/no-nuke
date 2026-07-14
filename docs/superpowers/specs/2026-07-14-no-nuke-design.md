# no-nuke — Destructive Command Guard (Design)

Date: 2026-07-14

## Problem

AI coding agents run shell commands autonomously. A confused, mistaken, or
prompt-injected agent can run catastrophically destructive commands — `rm -rf`
on the wrong path, `git reset --hard` over uncommitted work, `DROP DATABASE`,
`terraform destroy`, `shutdown`. Advisory instructions (a plain skill) are
insufficient because the same failure that produces the bad command also
ignores the instruction.

## Goal

Hard, model-independent enforcement: intercept every command *before* execution
and block / ask / warn based on how destructive it is, with a safe alternative
offered on every block. Ship as a shareable Claude Code plugin and as a personal
`~/.claude` install, with a framework-agnostic core so other agent frameworks
can adopt it.

## Approach

A Claude Code `PreToolUse` hook (`hooks/no_nuke.py`) receives each `Bash`,
`Write`, and `Edit` event, calls a pure engine, and emits a
`hookSpecificOutput` permission decision. The engine is dependency-free Python 3
(stdlib only), independently testable, and also exposed as a CLI (`bin/no-nuke`)
for non-Claude frameworks.

### Verdict tiers

- **critical → deny** — blocked outright.
- **high → ask** — escalated to the human via a permission prompt.
- **medium → warn** — allowed, but the risk is surfaced to the model via
  `additionalContext` while normal permission flow still applies (`defer`).
- no match → silent `defer` (never auto-allow, so the user's own permission
  rules are untouched).

On any internal error, the hook emits `ask` — it never fails open.

### Engine pipeline (`engine/engine.py`)

1. `split_commands` — quote/backslash-aware split on `&&`, `||`, `;`, `|`,
   newline (keeps `2>&1` intact by not splitting a lone `&`).
2. Per sub-command: strip `env`/`VAR=`/`sudo` prefixes (flagging sudo), shlex
   into argv; unparseable + destructive-looking → escalate.
3. Checkers, highest-severity wins:
   - **shell-exec unwrapping** — `bash -c "<script>"` recursively re-checked;
     `xargs <cmd>` re-checked; pipeline into a bare shell (`curl|sh`,
     `base64 -d|bash`) → ask.
   - **obfuscation** — `eval` → ask; `$(…)`/backticks combined with a
     destructive token → ask (benign `echo $(date)` is not flagged).
   - **rm/shred/unlink** — protected-path resolution; `-rf` on protected/
     wildcard root → deny; `-rf` on an ordinary dir → ask; `-r` only → warn.
   - **overwrite** — `dd of=/dev/*` → deny; `>`/`>|` truncation of a protected
     file → ask.
   - **git** — force-push to `main`/`master`/`prod` → deny; other force-push,
     `reset --hard`, `clean -f`, `branch -D`, `filter-branch` → deny/ask;
     `stash drop`, `checkout -- .` → warn.
   - **sql** — only when a known DB client is invoked; SQL extracted from
     `-c`/`-e`/positional/heredoc; `DROP DATABASE`/`TRUNCATE`/`DELETE`-without-
     `WHERE` → deny; `UPDATE`-without-`WHERE`/`DROP TABLE` → ask.
   - **declarative ruleset** (`rules/rules.json`) — `command + tokens → tier`
     for terraform/kubectl/aws/docker/system commands.

### Protected paths (`engine/config.py`)

Absolute defaults (`/`, `~`, `~/Documents`, `~/Desktop`, `~/Downloads`,
`~/Developer`, `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config`, `~/.claude`,
`~/Library`) and basename globs (`.git`, `.env*`, `id_rsa`, `*.pem`, `*.key`,
`.npmrc`). A target is protected if it equals **or is an ancestor of** a
protected path (deleting a parent wipes it), but working *inside* a protected
top-level dir is allowed.

### Config, guardrail, audit

`.no-nuke.json` (found by walking up from cwd) can relax **high/medium** rules
only via `allow` / `tier_overrides`, add `protected_paths` / `protected_names`,
or fully `disable`. **Critical rules are immutable** — `apply_override` returns
critical verdicts unchanged. The Write/Edit hook additionally **denies agent
edits to `.no-nuke.json`** so the guard can't disarm itself. Every non-allow
event is appended to `~/.no-nuke/audit.jsonl` (best-effort, never raises).

## Packaging

- `.claude-plugin/plugin.json` + `hooks/hooks.json` (matcher
  `Bash|Write|Edit|MultiEdit`, `${CLAUDE_PLUGIN_ROOT}`-relative command).
- `skills/no-nuke/SKILL.md` — advisory companion: safe alternatives, "don't
  bypass the guard".
- `install.sh` — idempotent merge into `~/.claude/settings.json` with backup;
  `--uninstall` reverses it.

## Testing

`tests/test_engine.py` — 74 unittest cases across all four categories:
dangerous → correct tier, benign look-alikes → allow, compound/obfuscated →
caught/escalated, protected-path traversal, and config-override behavior
(including that critical can't be relaxed).

## Non-goals / limitations

Not a sandbox. It stops common catastrophes and obvious footguns and escalates
to "ask" whenever it can't fully parse a command, but a determined adversary can
craft payloads it doesn't recognize. Untrusted agents should still run in a
container/VM.

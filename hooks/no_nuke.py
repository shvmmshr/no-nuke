#!/usr/bin/env python3
"""
no-nuke PreToolUse hook adapter.

Works for BOTH Claude Code and OpenAI Codex CLI — Codex adopted the same
PreToolUse hook contract (stdin JSON event -> stdout hookSpecificOutput
decision), so a single adapter serves both. The harness differs only in a few
details this adapter absorbs:

  - Command shape: Claude passes tool_input.command as a string; Codex's shell
    tool often passes an argv array (e.g. ["bash","-lc","rm -rf /"]). Both are
    normalized to a command string before checking.
  - Edit tools: Claude uses Write/Edit/MultiEdit (tool_input.file_path); Codex
    edits via apply_patch (file paths parsed out of the patch body).
  - allow/warn dialect: `--harness codex` emits no decision on allow/warn
    (proceed via Codex's own approval flow) rather than Claude's `defer`.

Fail-safe: any internal error escalates to "ask" (never a silent allow).

Usage (wired up by install.sh / plugin hooks.json):
    python3 .../hooks/no_nuke.py [--harness claude|codex]
"""

import json
import os
import re
import sys

# Make the sibling `engine` package importable regardless of cwd.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

# Shell interpreters whose -c/-lc argument carries the real command.
_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish"}

# Tool names (across harnesses) whose tool_input carries a shell command.
_SHELL_TOOLS = {"Bash", "shell", "local_shell", "exec", "run_command"}
# Tool names that edit files.
_EDIT_TOOLS = {"Write", "Edit", "MultiEdit"}


def _normalize_command(tool_input):
    """
    Return a single command string from tool_input.command, accepting either a
    string (Claude) or an argv array (Codex). For ["bash","-lc","<script>"]
    the inner script is returned.
    """
    cmd = tool_input.get("command")
    if cmd is None:
        return None
    if isinstance(cmd, str):
        return cmd
    if isinstance(cmd, list) and cmd:
        head = os.path.basename(str(cmd[0]))
        if len(cmd) >= 3 and head in _SHELLS and cmd[1] in ("-c", "-lc", "-lic", "-ic"):
            return str(cmd[-1])
        import shlex
        try:
            return " ".join(shlex.quote(str(x)) for x in cmd)
        except Exception:
            return " ".join(str(x) for x in cmd)
    return str(cmd)


def _apply_patch_paths(tool_input):
    """Extract file paths from a Codex apply_patch payload (best-effort)."""
    patch = tool_input.get("patch") or tool_input.get("input") or ""
    if not isinstance(patch, str):
        return []
    return re.findall(r"^\*\*\*\s+(?:Add|Update|Delete)\s+File:\s+(.+)$",
                      patch, re.M)


def _emit(decision, reason=None, additional_context=None):
    if decision is None:
        # No decision: emit nothing, exit 0 -> harness proceeds with its own
        # normal permission/approval flow. Portable across Claude and Codex.
        return
    out = {"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": decision,
    }}
    if reason is not None:
        out["hookSpecificOutput"]["permissionDecisionReason"] = reason
    if additional_context is not None:
        out["hookSpecificOutput"]["additionalContext"] = additional_context
    sys.stdout.write(json.dumps(out))
    sys.stdout.flush()


def _now_iso():
    try:
        import datetime
        return datetime.datetime.now().isoformat(timespec="seconds")
    except Exception:
        return None


def _format_reason(verdict):
    msg = f"[no-nuke:{verdict.rule_id}] {verdict.reason}"
    if verdict.suggestion:
        msg += f"\nSafer alternative: {verdict.suggestion}"
    return msg


def _check_file_write(file_path, cwd, config):
    """Protected-path enforcement for Write/Edit tools."""
    from engine.engine import _is_protected_target  # internal reuse
    if not file_path:
        return None
    # Block edits to the guard's own config so an agent can't disarm it.
    if os.path.basename(file_path) == ".no-nuke.json":
        from engine.engine import Verdict
        return Verdict(
            "deny", "critical", "config.self_edit",
            "Editing .no-nuke.json would let an agent weaken its own safety "
            "guard.",
            "Changes to no-nuke's config must be made by a human.",
            file_path)
    prot, kind = _is_protected_target(file_path, cwd, config)
    if prot and kind == "name":
        from engine.engine import Verdict
        return Verdict(
            "ask", "high", "fs.write_protected",
            f"Writing to a protected file ({prot}) — this may overwrite "
            "secrets or credentials.",
            "Confirm you intend to modify this sensitive file.",
            file_path)
    return None


def _harness_from_argv(argv):
    for i, a in enumerate(argv):
        if a == "--harness" and i + 1 < len(argv):
            return argv[i + 1].lower()
        if a.startswith("--harness="):
            return a.split("=", 1)[1].lower()
    return os.environ.get("NO_NUKE_HARNESS", "claude").lower()


def _worst_verdict(verdicts):
    from engine.engine import ACTION_RANK
    worst = None
    for v in verdicts:
        if v is None:
            continue
        if worst is None or ACTION_RANK[v.action] > ACTION_RANK[worst.action]:
            worst = v
    return worst


def main():
    harness = _harness_from_argv(sys.argv[1:])
    raw = sys.stdin.read()
    try:
        event = json.loads(raw) if raw.strip() else {}
    except ValueError:
        # Can't parse the event; be safe, ask.
        _emit("ask", "[no-nuke] Could not parse the hook event; escalating to "
                     "the user for safety.")
        return

    try:
        from engine.engine import check
        from engine.config import load_config, audit

        tool = event.get("tool_name", "")
        tool_input = event.get("tool_input", {}) or {}
        cwd = event.get("cwd") or os.getcwd()
        config = load_config(cwd)

        verdict = None
        command = None

        if tool in _SHELL_TOOLS or "command" in tool_input:
            command = _normalize_command(tool_input)
            if command:
                verdict = check(command, cwd=cwd, config=config)
        elif tool in _EDIT_TOOLS:
            command = tool_input.get("file_path", "")
            verdict = _check_file_write(command, cwd, config)
        elif tool == "apply_patch" or "patch" in tool_input:
            paths = _apply_patch_paths(tool_input)
            command = ", ".join(paths) if paths else "apply_patch"
            verdict = _worst_verdict(
                [_check_file_write(p, cwd, config) for p in paths])

        if verdict is None or verdict.action == "allow":
            # Nothing to say; proceed with the harness's normal flow.
            _emit(None)
            return

        audit(command, cwd, verdict, tool=tool, ts=_now_iso())

        if verdict.action == "deny":
            _emit("deny", _format_reason(verdict))
        elif verdict.action == "ask":
            _emit("ask", _format_reason(verdict))
        elif verdict.action == "warn":
            if harness == "codex":
                # Codex: don't rely on a `defer`+context dialect; let its own
                # approval flow proceed. The risk is still recorded in the
                # audit log.
                _emit(None)
            else:
                # Claude: surface the risk to the model but keep the user's own
                # permission rules in force via `defer`.
                _emit("defer", additional_context=_format_reason(verdict))
        else:
            _emit(None)

    except Exception as exc:  # noqa: BLE001 — fail safe, never crash-allow
        _emit("ask", f"[no-nuke] Internal guard error ({exc.__class__.__name__}); "
                     "escalating to the user for safety.")


if __name__ == "__main__":
    main()

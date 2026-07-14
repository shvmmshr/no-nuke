#!/usr/bin/env python3
"""
no-nuke PreToolUse hook adapter for Claude Code.

Reads the PreToolUse JSON event on stdin, runs the no-nuke engine, and prints a
hookSpecificOutput decision on stdout (exit 0). Fail-safe: any internal error
escalates to "ask" (never a silent allow).

Wire-up (hooks/hooks.json handles this for the plugin; install.sh for personal
installs):

    PreToolUse matcher "Bash|Write|Edit|MultiEdit" -> `python3 .../hooks/no_nuke.py`
"""

import json
import os
import sys

# Make the sibling `engine` package importable regardless of cwd.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


def _emit(decision, reason=None, additional_context=None):
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


def main():
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

        if tool == "Bash":
            command = tool_input.get("command", "")
            if command:
                verdict = check(command, cwd=cwd, config=config)
        elif tool in ("Write", "Edit", "MultiEdit"):
            command = tool_input.get("file_path", "")
            verdict = _check_file_write(command, cwd, config)

        if verdict is None or verdict.action == "allow":
            # Nothing to say; let the normal permission flow proceed.
            _emit("defer")
            return

        audit(command, cwd, verdict, tool=tool, ts=_now_iso())

        if verdict.action == "deny":
            _emit("deny", _format_reason(verdict))
        elif verdict.action == "ask":
            _emit("ask", _format_reason(verdict))
        elif verdict.action == "warn":
            # Don't block, but surface the risk to the model; keep the user's
            # own permission rules in force via "defer".
            _emit("defer", additional_context=_format_reason(verdict))
        else:
            _emit("defer")

    except Exception as exc:  # noqa: BLE001 — fail safe, never crash-allow
        _emit("ask", f"[no-nuke] Internal guard error ({exc.__class__.__name__}); "
                     "escalating to the user for safety.")


if __name__ == "__main__":
    main()

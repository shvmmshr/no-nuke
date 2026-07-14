#!/usr/bin/env bash
#
# no-nuke personal installer.
#
# Wires the no-nuke PreToolUse hook into ~/.claude/settings.json so it guards
# every Claude Code session on this machine (independent of the plugin install).
# Idempotent: re-running updates the existing entry instead of duplicating it.
#
# Usage:
#   ./install.sh            # install / update
#   ./install.sh --uninstall
#
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOK="$REPO_DIR/hooks/no_nuke.py"
SETTINGS="${CLAUDE_CONFIG_DIR:-$HOME/.claude}/settings.json"

if ! command -v python3 >/dev/null 2>&1; then
  echo "error: python3 is required but not found on PATH." >&2
  exit 1
fi

MODE="install"
if [[ "${1:-}" == "--uninstall" ]]; then
  MODE="uninstall"
fi

mkdir -p "$(dirname "$SETTINGS")"
[[ -f "$SETTINGS" ]] || echo '{}' > "$SETTINGS"

# Back up before touching it.
cp "$SETTINGS" "$SETTINGS.no-nuke.bak.$(date +%Y%m%d%H%M%S)" 2>/dev/null || true

MODE="$MODE" HOOK="$HOOK" SETTINGS="$SETTINGS" python3 - <<'PY'
import json, os, sys

settings_path = os.environ["SETTINGS"]
hook = os.environ["HOOK"]
mode = os.environ["MODE"]
command = f'python3 "{hook}"'
matcher = "Bash|Write|Edit|MultiEdit"

with open(settings_path) as f:
    try:
        data = json.load(f)
    except ValueError:
        data = {}

hooks = data.setdefault("hooks", {})
pre = hooks.setdefault("PreToolUse", [])

def is_nonuke(entry):
    for h in entry.get("hooks", []):
        if "no_nuke.py" in h.get("command", ""):
            return True
    return False

# Drop any existing no-nuke entries first (clean re-install / uninstall).
pre[:] = [e for e in pre if not is_nonuke(e)]

if mode == "install":
    pre.append({
        "matcher": matcher,
        "hooks": [{"type": "command", "command": command}],
    })
    print(f"no-nuke hook installed -> {settings_path}")
else:
    print(f"no-nuke hook removed from {settings_path}")

if not pre:
    hooks.pop("PreToolUse", None)
if not hooks:
    data.pop("hooks", None)

with open(settings_path, "w") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
PY

echo
if [[ "$MODE" == "install" ]]; then
  echo "Done. Restart Claude Code (or start a new session) to activate the guard."
  echo "Test it:  $REPO_DIR/bin/no-nuke check \"rm -rf /\""
  echo "Audit log: ~/.no-nuke/audit.jsonl"
else
  echo "Uninstalled. Restart Claude Code to fully deactivate."
fi

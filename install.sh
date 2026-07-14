#!/usr/bin/env bash
#
# no-nuke personal installer for Claude Code and/or OpenAI Codex CLI.
#
# Wires the no-nuke PreToolUse hook into the harness's config so it guards every
# session on this machine. Idempotent: re-running updates the existing entry
# instead of duplicating it.
#
#   Claude Code -> ${CLAUDE_CONFIG_DIR:-~/.claude}/settings.json
#   Codex CLI   -> ${CODEX_HOME:-~/.codex}/hooks.json   (+ trust via /hooks)
#
# Usage:
#   ./install.sh                      # auto: Claude always; Codex if ~/.codex exists
#   ./install.sh --target claude      # Claude only
#   ./install.sh --target codex       # Codex only
#   ./install.sh --target both        # both, creating dirs as needed
#   ./install.sh --uninstall [--target ...]
#
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOK="$REPO_DIR/hooks/no_nuke.py"
CLAUDE_DIR="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"
CODEX_DIR="${CODEX_HOME:-$HOME/.codex}"
MATCHER="Bash|shell|local_shell|exec|apply_patch|Write|Edit|MultiEdit"

if ! command -v python3 >/dev/null 2>&1; then
  echo "error: python3 is required but not found on PATH." >&2
  exit 1
fi

MODE="install"
TARGET="auto"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --uninstall) MODE="uninstall" ;;
    --target) shift; TARGET="${1:-}" ;;
    --target=*) TARGET="${1#*=}" ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
  shift
done

if [[ "$TARGET" == "auto" ]]; then
  TARGET="claude"
  [[ -d "$CODEX_DIR" ]] && TARGET="both"
fi

# merge_hook <settings_file> <harness>
merge_hook() {
  local file="$1" harness="$2"
  mkdir -p "$(dirname "$file")"
  [[ -f "$file" ]] || echo '{}' > "$file"
  cp "$file" "$file.no-nuke.bak.$(date +%Y%m%d%H%M%S)" 2>/dev/null || true

  MODE="$MODE" HOOK="$HOOK" FILE="$file" HARNESS="$harness" MATCHER="$MATCHER" \
  python3 - <<'PY'
import json, os

path = os.environ["FILE"]
hook = os.environ["HOOK"]
mode = os.environ["MODE"]
harness = os.environ["HARNESS"]
matcher = os.environ["MATCHER"]
command = f'python3 "{hook}" --harness {harness}'

with open(path) as f:
    try:
        data = json.load(f)
    except ValueError:
        data = {}

hooks = data.setdefault("hooks", {})
pre = hooks.setdefault("PreToolUse", [])

def is_nonuke(entry):
    return any("no_nuke.py" in h.get("command", "")
               for h in entry.get("hooks", []))

pre[:] = [e for e in pre if not is_nonuke(e)]

if mode == "install":
    pre.append({
        "matcher": matcher,
        "hooks": [{"type": "command", "command": command}],
    })
    print(f"  installed -> {path}")
else:
    print(f"  removed from {path}")

if not pre:
    hooks.pop("PreToolUse", None)
if not hooks:
    data.pop("hooks", None)

with open(path, "w") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
PY
}

echo "no-nuke $MODE (target: $TARGET)"

if [[ "$TARGET" == "claude" || "$TARGET" == "both" ]]; then
  echo "Claude Code:"
  merge_hook "$CLAUDE_DIR/settings.json" "claude"
fi

if [[ "$TARGET" == "codex" || "$TARGET" == "both" ]]; then
  echo "Codex CLI:"
  merge_hook "$CODEX_DIR/hooks.json" "codex"
fi

echo
if [[ "$MODE" == "install" ]]; then
  echo "Done. Test it:  $REPO_DIR/bin/no-nuke check \"rm -rf /\""
  echo "Audit log:      ~/.no-nuke/audit.jsonl"
  if [[ "$TARGET" == "claude" || "$TARGET" == "both" ]]; then
    echo "- Claude Code: restart or start a new session to activate."
  fi
  if [[ "$TARGET" == "codex" || "$TARGET" == "both" ]]; then
    echo "- Codex CLI:   run '/hooks' in the Codex TUI and TRUST the no-nuke hook"
    echo "               (Codex won't run an untrusted hook), then start a session."
  fi
else
  echo "Uninstalled. Restart the affected agent(s) to fully deactivate."
fi

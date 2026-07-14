"""
Per-project configuration, protected-path defaults, and audit logging.

A repo can ship a `.no-nuke.json` at its root to tune behavior:

    {
      "disabled": false,
      "allow": ["fs.rm_rf", "docker.system_prune"],   // downgrade to allow
      "tier_overrides": {"git.reset_hard": "medium"},  // relax high -> medium
      "protected_paths": ["./data", "./migrations"],   // extra protected dirs
      "protected_names": ["*.pem"]                      // extra protected basenames
    }

Hard guardrail: project config may only RELAX high/medium rules. It can never
disable or downgrade a `critical` rule, and it cannot fully disable the guard
for critical rules — otherwise a compromised agent could write a config to
disarm no-nuke. Critical always wins.
"""

import json
import os

# Rules that a project config is NOT allowed to relax.
_UNRELAXABLE_TIER = "critical"

_DEFAULT_ABSOLUTE_PROTECTED = [
    "/",
    "~",
    "~/Documents",
    "~/Desktop",
    "~/Downloads",
    "~/Developer",
    "~/.ssh",
    "~/.gnupg",
    "~/.aws",
    "~/.config",
    "~/.claude",
    "~/Library",
]

_DEFAULT_NAME_PROTECTED = [
    ".git",
    ".env",
    ".env.*",
    "id_rsa",
    "id_ed25519",
    "*.pem",
    "*.key",
    ".npmrc",
]

_AUDIT_PATH = os.path.expanduser("~/.no-nuke/audit.jsonl")


class Config:
    def __init__(self, disabled=False, allow=None, tier_overrides=None,
                 absolute_protected=None, name_protected=None, source=None):
        self.disabled = disabled
        self.allow = set(allow or [])
        self.tier_overrides = dict(tier_overrides or {})
        self.absolute_protected = list(absolute_protected
                                       if absolute_protected is not None
                                       else _DEFAULT_ABSOLUTE_PROTECTED)
        self.name_protected = list(name_protected
                                   if name_protected is not None
                                   else _DEFAULT_NAME_PROTECTED)
        self.source = source  # path of the .no-nuke.json that was loaded

    @classmethod
    def default(cls):
        return cls()

    def apply_override(self, verdict):
        """
        Apply allowlist / tier_overrides to a verdict, honoring the guardrail
        that critical rules can never be relaxed.
        """
        if verdict is None or verdict.rule_id is None:
            return verdict
        if verdict.tier == _UNRELAXABLE_TIER:
            return verdict  # critical is immutable

        from .engine import Verdict, TIER_ACTION
        if verdict.rule_id in self.allow:
            return Verdict("allow", None, verdict.rule_id,
                           reason=verdict.reason, suggestion=verdict.suggestion,
                           matched=verdict.matched)
        if verdict.rule_id in self.tier_overrides:
            new_tier = self.tier_overrides[verdict.rule_id]
            if new_tier in TIER_ACTION:
                return Verdict(TIER_ACTION[new_tier], new_tier,
                               verdict.rule_id, verdict.reason,
                               verdict.suggestion, verdict.matched)
        return verdict


def _find_config_file(cwd):
    """Walk up from cwd looking for a .no-nuke.json (stop at filesystem root)."""
    d = os.path.abspath(cwd or os.getcwd())
    while True:
        candidate = os.path.join(d, ".no-nuke.json")
        if os.path.isfile(candidate):
            return candidate
        parent = os.path.dirname(d)
        if parent == d:
            return None
        d = parent


def load_config(cwd=None):
    """Load and merge a project .no-nuke.json onto the defaults."""
    cwd = cwd or os.getcwd()
    path = _find_config_file(cwd)
    if not path:
        return Config.default()
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return Config.default()

    abs_prot = list(_DEFAULT_ABSOLUTE_PROTECTED)
    for extra in data.get("protected_paths", []) or []:
        # Resolve project-relative protected paths against the config location.
        if not os.path.isabs(os.path.expanduser(extra)):
            extra = os.path.join(os.path.dirname(path), extra)
        abs_prot.append(extra)

    name_prot = list(_DEFAULT_NAME_PROTECTED)
    name_prot.extend(data.get("protected_names", []) or [])

    return Config(
        disabled=bool(data.get("disabled", False)),
        allow=data.get("allow", []),
        tier_overrides=data.get("tier_overrides", {}),
        absolute_protected=abs_prot,
        name_protected=name_prot,
        source=path,
    )


# --------------------------------------------------------------------------- #
# Audit log
# --------------------------------------------------------------------------- #

def audit(command, cwd, verdict, tool="Bash", ts=None):
    """
    Append a JSONL record for any non-plain-allow event. Best-effort: never
    raises (auditing must not break the guard).
    """
    try:
        if verdict is None or verdict.action == "allow":
            return
        os.makedirs(os.path.dirname(_AUDIT_PATH), exist_ok=True)
        record = {
            "ts": ts,
            "tool": tool,
            "cwd": cwd,
            "command": command,
            "action": verdict.action,
            "tier": verdict.tier,
            "rule_id": verdict.rule_id,
            "reason": verdict.reason,
        }
        with open(_AUDIT_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
    except Exception:
        pass


def audit_path():
    return _AUDIT_PATH

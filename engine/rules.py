"""
Loads the declarative ruleset (rules/rules.json) once and caches it.

The declarative rules cover straightforward "command + tokens -> tier" cases
(terraform destroy, kubectl delete --all, docker system prune, mkfs, ...).
The structural / context-sensitive checks (rm + protected paths, git history,
SQL WHERE-clauses, shell-exec unwrapping) live in engine.py.
"""

import json
import os

_CACHE = None

# Repo layout: engine/rules.py -> ../rules/rules.json
_RULES_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "rules", "rules.json")


def load_rules(path=None):
    """Return the list of declarative rules (cached)."""
    global _CACHE
    if path is None and _CACHE is not None:
        return _CACHE
    p = path or _RULES_PATH
    try:
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        rules = data.get("rules", data) if isinstance(data, dict) else data
    except (OSError, ValueError):
        rules = _FALLBACK_RULES
    if path is None:
        _CACHE = rules
    return rules


def clear_cache():
    global _CACHE
    _CACHE = None


# Minimal fallback so the engine still guards the worst cases if rules.json is
# missing or corrupt. Kept small on purpose; rules.json is the real source.
_FALLBACK_RULES = [
    {"id": "fs.mkfs", "category": "filesystem", "tier": "critical",
     "match": {"cmd": "mkfs*"},
     "reason": "mkfs formats a filesystem, destroying all data on the target.",
     "suggestion": "Never format a device from an agent."},
    {"id": "cloud.terraform_destroy", "category": "cloud", "tier": "critical",
     "match": {"cmd": "terraform", "subcmd": "destroy"},
     "reason": "terraform destroy tears down all managed infrastructure.",
     "suggestion": "Run `terraform plan -destroy` and get human sign-off first."},
]

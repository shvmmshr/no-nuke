"""
no-nuke core engine.

Pure, dependency-free logic that turns a shell command string into a Verdict.
No I/O here except reading the ruleset (done once via rules.py). Everything is
testable in isolation: `check(command, cwd, config) -> Verdict`.

Design:
  1. Split a command line into sub-commands on unquoted &&, ||, ;, |, newline.
  2. For each sub-command, shlex into argv and run a battery of checkers:
       - shell-exec unwrapping (bash -c, xargs, pipe-into-shell)  -> recurse / escalate
       - obfuscation detection ($(...), backticks, base64|sh, eval) -> ask
       - rm / delete + protected-path resolution                   -> deny/ask
       - git history-loss checks                                   -> deny/ask
       - sql destruction checks                                    -> deny/ask/warn
       - declarative ruleset (rules.json)                          -> deny/ask/warn
  3. The single highest-severity verdict across all sub-commands wins.

Tier -> action mapping:
    critical -> deny
    high     -> ask
    medium   -> warn   (allowed, but the agent is told why it's risky)
    (no match) -> allow
"""

import os
import re
import shlex

from .rules import load_rules

# --------------------------------------------------------------------------- #
# Verdict
# --------------------------------------------------------------------------- #

TIER_ACTION = {"critical": "deny", "high": "ask", "medium": "warn"}
ACTION_RANK = {"allow": 0, "warn": 1, "ask": 2, "deny": 3}

# Command interpreters that execute an arbitrary string / stdin.
_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish"}

# Known database client executables.
_DB_CLIENTS = {"psql", "mysql", "mariadb", "sqlite3", "mongo", "mongosh",
               "redis-cli", "cockroach", "clickhouse-client"}


class Verdict:
    """The outcome of checking a command."""

    __slots__ = ("action", "tier", "rule_id", "reason", "suggestion", "matched")

    def __init__(self, action="allow", tier=None, rule_id=None,
                 reason="", suggestion="", matched=""):
        self.action = action
        self.tier = tier
        self.rule_id = rule_id
        self.reason = reason
        self.suggestion = suggestion
        self.matched = matched  # the sub-command that triggered this verdict

    def to_dict(self):
        return {
            "action": self.action,
            "tier": self.tier,
            "rule_id": self.rule_id,
            "reason": self.reason,
            "suggestion": self.suggestion,
            "matched": self.matched,
        }

    def __repr__(self):
        return f"Verdict({self.action}, {self.rule_id}, {self.reason!r})"


def _worst(a, b):
    """Return the higher-severity verdict."""
    if a is None:
        return b
    if b is None:
        return a
    return a if ACTION_RANK[a.action] >= ACTION_RANK[b.action] else b


def _verdict_for_tier(tier, rule_id, reason, suggestion, matched):
    return Verdict(TIER_ACTION[tier], tier, rule_id, reason, suggestion, matched)


# --------------------------------------------------------------------------- #
# Command-line splitting (quote-aware, keeps operators out)
# --------------------------------------------------------------------------- #

def _group_end(command, i):
    """
    Given command[i] == "(" that opens $( ... ), <( ... ) or >( ... ), return
    the index just past its matching ")". Quote aware; unbalanced input runs to
    the end of the string.
    """
    depth = 0
    quote = None
    n = len(command)
    while i < n:
        c = command[i]
        if quote:
            if c == "\\" and quote == '"' and i + 1 < n:
                i += 2
                continue
            if c == quote:
                quote = None
        elif c in ("'", '"'):
            quote = c
        elif c == "\\" and i + 1 < n:
            i += 2
            continue
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


def split_commands(command):
    """
    Split a shell command line into sub-command strings on unquoted
    &&, ||, ;, |, newline, and the subshell parentheses ( and ). Quote and
    backslash aware. Substitutions $( ... ), <( ... ), >( ... ) and backticks
    are kept whole inside their word (their contents are checked separately).
    A lone & (background) splits too; the & inside redirections such as 2>&1
    and &>file does not.
    """
    parts = []
    buf = []
    i = 0
    n = len(command)
    quote = None
    while i < n:
        c = command[i]
        if c == "$" and quote != "'" and command[i + 1:i + 2] == "(":
            end = _group_end(command, i + 1)
            buf.append(command[i:end])
            i = end
            continue
        if quote:
            buf.append(c)
            if c == quote:
                quote = None
            i += 1
            continue
        if c in ("'", '"'):
            quote = c
            buf.append(c)
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            buf.append(c)
            buf.append(command[i + 1])
            i += 2
            continue
        if c == "`":
            end = command.find("`", i + 1)
            end = n if end == -1 else end + 1
            buf.append(command[i:end])
            i = end
            continue
        if c in ("<", ">") and command[i + 1:i + 2] == "(":
            end = _group_end(command, i + 1)
            buf.append(command[i:end])
            i = end
            continue
        two = command[i:i + 2]
        if two in ("&&", "||"):
            parts.append("".join(buf))
            buf = []
            i += 2
            continue
        # A lone & backgrounds the command before it; the next one still runs.
        # Keep it when it is part of a redirection: 2>&1, >&2, <&3, &>file.
        if c == "&" and not (i > 0 and command[i - 1] in "<>") \
                and command[i + 1:i + 2] != ">":
            parts.append("".join(buf))
            buf = []
            i += 1
            continue
        if c in (";", "|", "\n", "(", ")"):
            parts.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(c)
        i += 1
    if buf:
        parts.append("".join(buf))
    return [p.strip() for p in parts if p.strip()]


def _substitutions(command):
    """
    Return the command strings inside $( ... ), backticks, <( ... ) and
    >( ... ). They execute even when nested in double quotes, so each one is
    checked as a command in its own right. Single-quoted text is literal.
    """
    found = []
    i = 0
    n = len(command)
    quote = None
    while i < n:
        c = command[i]
        if c == "\\" and quote != "'" and i + 1 < n:
            i += 2
            continue
        if quote == "'":
            if c == "'":
                quote = None
            i += 1
            continue
        if c == "'" and quote is None:
            quote = "'"
        elif c == '"':
            quote = None if quote == '"' else '"'
        elif c == "$" and command[i + 1:i + 2] == "(":
            end = _group_end(command, i + 1)
            found.append(command[i + 2:end - 1])
            i = end
            continue
        elif c in ("<", ">") and quote is None and command[i + 1:i + 2] == "(":
            end = _group_end(command, i + 1)
            found.append(command[i + 2:end - 1])
            i = end
            continue
        elif c == "`":
            end = command.find("`", i + 1)
            end = n if end == -1 else end
            found.append(command[i + 1:end])
            i = end + 1
            continue
        i += 1
    return [s for s in found if s.strip()]


def _parse_argv(subcmd):
    """shlex a sub-command into argv. Return None if it cannot be parsed."""
    try:
        argv = shlex.split(subcmd, posix=True)
    except ValueError:
        return None
    # Drop leading inline VAR=x assignments; wrappers are removed by _unwrap.
    while argv and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", argv[0]):
        argv = argv[1:]
    return argv


# Shell reserved words that can start a sub-command without being the command
# itself (after splitting `if x; then rm -rf /; fi` on `;`).
_SHELL_KEYWORDS = {"!", "{", "}", "if", "then", "else", "elif", "while",
                   "until", "do", "done", "fi", "esac"}

# Commands that run another command. Value: the options that take a separate
# value argument, so the value is not mistaken for the wrapped command.
_WRAPPERS = {
    "nohup": set(),
    "time": set(),
    "command": set(),
    "builtin": set(),
    "exec": {"-a"},
    "setsid": set(),
    "nice": {"-n", "--adjustment"},
    "timeout": {"-s", "--signal", "-k", "--kill-after"},
    "env": {"-u", "--unset", "-C", "--chdir"},
    "stdbuf": {"-i", "-o", "-e"},
    "ionice": {"-c", "-n", "-p", "-t"},
    "caffeinate": {"-t", "-w"},
    "sudo": {"-u", "-g", "-h", "-p", "-C", "-D", "-r", "-t", "-U", "-T", "-R"},
    "doas": {"-u", "-C"},
}
_PRIVILEGE_WRAPPERS = {"sudo", "doas"}
# Wrappers whose first positional argument is not the command (timeout DURATION).
_WRAPPER_POSITIONAL_SKIP = {"timeout": 1}
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def _strip_wrapper(argv):
    """
    Remove one wrapper (and its options) from the front of argv. Returns the
    wrapped argv, or None when argv[0] is not a wrapper we can see through.
    """
    name = _basename(argv[0])
    if name not in _WRAPPERS:
        return None
    # `command -v rm` looks a command up; it does not run it.
    if name == "command" and len(argv) > 1 and argv[1] in ("-v", "-V"):
        return None
    value_opts = _WRAPPERS[name]
    positional_skip = _WRAPPER_POSITIONAL_SKIP.get(name, 0)
    i = 1
    while i < len(argv):
        tok = argv[i]
        if tok == "--":
            i += 1
            break
        if name == "env" and tok in ("-S", "--split-string") and i + 1 < len(argv):
            # env -S "cmd args" runs the split string as the command.
            try:
                return shlex.split(argv[i + 1]) + argv[i + 2:]
            except ValueError:
                return argv[i + 1:]
        if tok in value_opts:
            i += 2
            continue
        if tok.startswith("-") and len(tok) > 1:
            i += 1
            continue
        if name == "env" and _ASSIGNMENT.match(tok):
            i += 1
            continue
        if positional_skip:
            positional_skip -= 1
            i += 1
            continue
        break
    return argv[i:]


def _unwrap(argv):
    """
    Peel shell keywords and command wrappers off the front of argv so checkers
    see the command that actually runs: `nohup timeout 5 sudo -u root rm -rf /`
    -> `rm -rf /`. Returns (argv, had_privilege_wrapper).
    """
    had_sudo = False
    while argv:
        if argv[0] in _SHELL_KEYWORDS:
            argv = argv[1:]
            continue
        if _ASSIGNMENT.match(argv[0]):
            argv = argv[1:]
            continue
        inner = _strip_wrapper(argv)
        if inner is None:
            break
        if _basename(argv[0]) in _PRIVILEGE_WRAPPERS:
            had_sudo = True
        argv = inner
    return argv, had_sudo


def _basename(cmd):
    return os.path.basename(cmd) if cmd else cmd


def _flag_sets(argv):
    """Return (short_flags:set[str], long_flags:set[str]) from argv[1:]."""
    shorts, longs = set(), set()
    for tok in argv[1:]:
        if tok == "--":
            break
        if tok.startswith("--") and len(tok) > 2:
            longs.add(tok[2:].split("=", 1)[0])
        elif tok.startswith("-") and len(tok) > 1 and not _looks_like_negative_number(tok):
            for ch in tok[1:]:
                shorts.add(ch)
    return shorts, longs


def _looks_like_negative_number(tok):
    return bool(re.match(r"^-\d", tok))


def _positional_args(argv):
    """Non-flag arguments after the command name."""
    out = []
    seen_ddash = False
    for tok in argv[1:]:
        if seen_ddash:
            out.append(tok)
            continue
        if tok == "--":
            seen_ddash = True
            continue
        if tok.startswith("-") and len(tok) > 1 and not _looks_like_negative_number(tok):
            continue
        out.append(tok)
    return out


# --------------------------------------------------------------------------- #
# Protected-path resolution
# --------------------------------------------------------------------------- #

def _resolve(path, cwd):
    """Expand ~ and env-free relative paths to a normalized absolute path."""
    p = os.path.expanduser(path)
    if not os.path.isabs(p):
        p = os.path.join(cwd or os.getcwd(), p)
    return os.path.normpath(p)


_TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist")

_HOME_VAR = re.compile(r"^(\$HOME|\$\{HOME\})(?=/|$)")
_PWD_VAR = re.compile(r"^(\$PWD|\$\{PWD\})(?=/|$)")


def _normalize_target(path):
    """
    Canonical spelling for protected-path checks: $HOME and ${HOME} become ~,
    $PWD and ${PWD} become ., and trailing slashes go (`~/` is `~`, `../` is
    `..`). Only these two variables are expanded; anything else stays literal.
    """
    p = path.strip()
    p = _HOME_VAR.sub("~", p)
    p = _PWD_VAR.sub(".", p)
    if len(p) > 1:
        p = p.rstrip("/") or "/"
    return p


def _is_protected_target(path, cwd, config):
    """
    Return (protected_path, kind) if deleting/overwriting `path` would hit a
    protected location, else (None, None).

    kind is "absolute" (matched an absolute protected dir) or "name" (matched a
    protected basename like .git / .env).
    """
    raw = _normalize_target(path)

    # Bare dangerous tokens.
    if raw in ("/", "~", "$HOME", "${HOME}", "*", ".", "..", "./*", "~/*"):
        return (raw, "wildcard")

    # `dir/*` and `dir/.*` empty the whole directory: judge them as `dir`.
    head, tail = os.path.split(raw)
    if tail in ("*", ".*") and head:
        prot, kind = _is_protected_target(head, cwd, config)
        if prot is not None:
            return (prot, kind)

    # Basename-pattern protection (.git, .env, .env.*, id_rsa ...). Committed
    # templates like .env.example hold no secrets, so they are exempt.
    base = os.path.basename(raw.rstrip("/"))
    if not base.endswith(_TEMPLATE_SUFFIXES):
        for pat in config.name_protected:
            if _fnmatch_name(base, pat):
                return (pat, "name")

    resolved = _resolve(raw, cwd)
    for prot in config.absolute_protected:
        prot_n = _resolve(prot, cwd)
        # Deny if target IS a protected path or an ANCESTOR of one (deleting a
        # parent wipes the protected dir). Deleting a child is allowed.
        if resolved == prot_n:
            return (prot, "absolute")
        if _is_ancestor(resolved, prot_n):
            return (prot, "absolute")
    return (None, None)


def _is_ancestor(ancestor, descendant):
    a = ancestor.rstrip("/") or "/"
    d = descendant.rstrip("/") or "/"
    if a == "/":
        return d != "/"
    return d.startswith(a + "/")


def _fnmatch_name(name, pattern):
    import fnmatch
    return fnmatch.fnmatch(name, pattern)


# --------------------------------------------------------------------------- #
# Checkers
# --------------------------------------------------------------------------- #

_DESTRUCTIVE_TOKENS = re.compile(
    r"\b(rm|rmdir|shred|mkfs\w*|dd|unlink|find|fdisk|wipefs|"
    r"reset|clean|drop|truncate|delete|destroy)\b", re.I)


def _check_shell_exec(argv, subcmd, cwd, config, depth):
    """
    Unwrap shell interpreters and xargs so we can inspect what they execute.
    Returns a Verdict or None.
    """
    if not argv:
        return None
    cmd = _basename(argv[0])

    # bash -c "<script>"  /  sh -c '<script>'
    if cmd in _SHELLS:
        # find the -c argument
        for i, tok in enumerate(argv[1:], start=1):
            if tok == "-c" and i + 1 < len(argv):
                inner = argv[i + 1]
                v = check(inner, cwd, config, _depth=depth + 1)
                if v.action != "allow":
                    return v
                # Non-trivial but unrecognized inline script: mild escalation
                # only if it references destructive tokens.
                if _DESTRUCTIVE_TOKENS.search(inner):
                    return _verdict_for_tier(
                        "high", "exec.shell_c",
                        "Command runs a shell script via -c that references "
                        "destructive operations.",
                        "Run the exact command directly so it can be inspected.",
                        subcmd)
                return None
        # bare `sh` / `bash` with no -c: reads a script from stdin/file — opaque.
        # Handled at the pipeline level (_check_pipe_to_shell).
        return None

    # xargs <cmd ...>: the real command is what follows xargs' own options.
    if cmd == "xargs":
        inner = _xargs_command(argv)
        if not inner:
            return None
        v = check(" ".join(shlex.quote(t) for t in inner), cwd, config,
                  _depth=depth + 1)
        if v.action != "allow":
            return v
        # The paths come from stdin, so an unscoped-looking delete is still one.
        if _basename(inner[0]) in _DELETE_COMMANDS:
            shorts, longs = _flag_sets(inner)
            if "r" in shorts or "R" in shorts or "recursive" in longs:
                return _verdict_for_tier(
                    "high", "fs.xargs_rm_recursive",
                    "xargs recursively deletes whatever paths arrive on stdin; "
                    "the targets cannot be inspected.",
                    "List the paths first, then delete them explicitly.",
                    subcmd)
            return _verdict_for_tier(
                "medium", "fs.xargs_rm",
                "xargs deletes whatever files arrive on stdin.",
                "Check the list of paths before piping it into rm.",
                subcmd)
    return None


_DELETE_COMMANDS = {"rm", "rmdir", "unlink", "shred"}
_XARGS_VALUE_OPTS = {"-I", "-n", "-P", "-d", "-E", "-s", "-L", "-a",
                     "--arg-file", "--delimiter", "--max-args", "--max-procs",
                     "--max-lines", "--max-chars", "--eof", "--replace"}


def _xargs_command(argv):
    """The command xargs will run: everything after xargs' own options."""
    i = 1
    while i < len(argv):
        tok = argv[i]
        if tok == "--":
            return argv[i + 1:]
        if tok in _XARGS_VALUE_OPTS:
            i += 2
            continue
        if tok.startswith("-") and len(tok) > 1:
            i += 1
            continue
        return argv[i:]
    return []


def _check_pipe_to_shell(command, subcmds):
    """
    Detect a pipeline feeding a bare shell interpreter or decode-then-exec,
    e.g. `curl x | sh`, `echo base64 | base64 -d | bash`. Escalate to ask.
    """
    if len(subcmds) < 2:
        return None
    last = _parse_argv(subcmds[-1]) or []
    last_cmd = _basename(last[0]) if last else ""
    has_c = "-c" in last
    if last_cmd in _SHELLS and not has_c:
        return _verdict_for_tier(
            "high", "exec.pipe_to_shell",
            "A pipeline feeds arbitrary/opaque input into a shell interpreter "
            "(e.g. `curl ... | sh` or `base64 -d | bash`).",
            "Download to a file, read it, then run it deliberately.",
            command)
    return None


def _check_obfuscation(subcmd, argv):
    """
    Command substitution / eval / encoded payloads that hide the real command.
    Only escalates when combined with a destructive-looking token, to avoid
    flagging benign `echo $(date)`.
    """
    has_subst = ("$(" in subcmd) or ("`" in subcmd)
    is_eval = bool(argv) and _basename(argv[0]) == "eval"
    if is_eval:
        return _verdict_for_tier(
            "high", "exec.eval",
            "`eval` executes a dynamically-built command that cannot be "
            "statically inspected.",
            "Construct and run the concrete command directly instead of eval.",
            subcmd)
    if has_subst and _DESTRUCTIVE_TOKENS.search(subcmd):
        return _verdict_for_tier(
            "high", "exec.command_substitution",
            "Command substitution ($(...) or backticks) is combined with a "
            "destructive operation, hiding the real target.",
            "Expand the substitution yourself and run the explicit command.",
            subcmd)
    return None


def _check_rm(argv, subcmd, cwd, config):
    """rm / rmdir / unlink / shred with protected-path awareness."""
    cmd = _basename(argv[0])
    if cmd not in _DELETE_COMMANDS:
        return None

    shorts, longs = _flag_sets(argv)
    recursive = ("r" in shorts) or ("R" in shorts) or ("recursive" in longs)
    force = ("f" in shorts) or ("force" in longs)
    no_preserve = "no-preserve-root" in longs
    targets = _positional_args(argv)

    worst = None
    for t in targets:
        prot, kind = _is_protected_target(t, cwd, config)
        if prot is not None:
            if kind == "wildcard" or prot in ("/", "~", "$HOME"):
                worst = _worst(worst, _verdict_for_tier(
                    "critical", "fs.rm_protected_root",
                    f"`{cmd}` targets a protected/wildcard location "
                    f"({prot}) — this can wipe your home or filesystem.",
                    "Delete a specific named path, or move items to the trash "
                    "(e.g. `trash <path>`) instead.",
                    subcmd))
            else:
                worst = _worst(worst, _verdict_for_tier(
                    "critical", "fs.rm_protected_path",
                    f"`{cmd}` would delete a protected path ({prot}).",
                    "This path is on the protected list. If you truly need to "
                    "remove it, ask the human to do it manually.",
                    subcmd))

    if no_preserve:
        worst = _worst(worst, _verdict_for_tier(
            "critical", "fs.rm_no_preserve_root",
            "`rm --no-preserve-root` disables the last safeguard against "
            "deleting the entire filesystem.",
            "Never use --no-preserve-root from an agent.",
            subcmd))

    if worst is not None:
        return worst

    # Recursive-force delete of an ordinary directory: destructive but scoped.
    if recursive and force and targets:
        return _verdict_for_tier(
            "high", "fs.rm_rf",
            f"Recursive force delete (`{cmd} -rf`) permanently removes "
            f"{', '.join(targets)} with no recovery.",
            "Confirm the path is correct, or move it to the trash instead of "
            "permanent deletion.",
            subcmd)
    if recursive and targets:
        return _verdict_for_tier(
            "medium", "fs.rm_recursive",
            f"`{cmd} -r` recursively deletes {', '.join(targets)}.",
            "Double-check the target directory before deleting.",
            subcmd)
    return None


def _check_overwrite(argv, subcmd, cwd, config):
    """mv/cp overwriting, dd of=, and > truncation of protected files."""
    cmd = _basename(argv[0]) if argv else ""

    # dd of=<target>
    if cmd == "dd":
        for tok in argv[1:]:
            if tok.startswith("of="):
                target = tok[3:]
                if target.startswith("/dev/"):
                    return _verdict_for_tier(
                        "critical", "fs.dd_device",
                        f"`dd` writes raw bytes directly to a device "
                        f"({target}), which can destroy a disk.",
                        "Never dd to a block device from an agent.",
                        subcmd)
                prot, _ = _is_protected_target(target, cwd, config)
                if prot:
                    return _verdict_for_tier(
                        "critical", "fs.dd_protected",
                        f"`dd` would overwrite a protected path ({prot}).",
                        "Choose a non-protected output path.",
                        subcmd)
    # redirection truncation: `> file` / `>| file`
    m = re.search(r"(?<![0-9>])>\|?\s*([^\s;&|<>]+)", subcmd)
    if m:
        target = m.group(1).strip("'\"")
        prot, kind = _is_protected_target(target, cwd, config)
        if prot and kind == "name":
            return _verdict_for_tier(
                "high", "fs.truncate_protected",
                f"Output redirection would overwrite a protected file "
                f"({target}).",
                "Append with >> or write to a different file; back up secrets "
                "first.",
                subcmd)
    return None


# Options of mv / cp / truncate that take a separate value argument.
_MOVE_VALUE_OPTS = {"-t", "--target-directory", "-S", "--suffix",
                    "-s", "--size", "-r", "--reference"}
_NO_CLOBBER = {"-n", "--no-clobber", "-i", "--interactive"}


def _operands(argv):
    """Positional operands of mv/cp/truncate, skipping option values."""
    out = []
    skip_next = False
    for tok in argv[1:]:
        if skip_next:
            skip_next = False
            continue
        if tok in _MOVE_VALUE_OPTS:
            skip_next = True
            continue
        if tok.startswith("-") and len(tok) > 1:
            continue
        out.append(tok)
    return out


def _check_move_copy(argv, subcmd, cwd, config):
    """
    mv of a protected path moves it out of place; mv/cp onto a protected file
    (or truncate of one) destroys its contents. Both need a human.
    """
    cmd = _basename(argv[0]) if argv else ""
    if cmd not in ("mv", "cp", "truncate"):
        return None
    operands = _operands(argv)

    if cmd == "truncate":
        for target in operands:
            prot, kind = _is_protected_target(target, cwd, config)
            if prot and kind == "name":
                return _verdict_for_tier(
                    "high", "fs.truncate_protected",
                    f"`truncate` would wipe a protected file ({target}).",
                    "Back up the file first, or truncate a different file.",
                    subcmd)
        return None

    if len(operands) < 2:
        return None
    sources, dest = operands[:-1], operands[-1]
    if cmd == "mv":
        for src in sources:
            prot, _ = _is_protected_target(src, cwd, config)
            if prot:
                return _verdict_for_tier(
                    "high", "fs.mv_protected",
                    f"`mv` would move a protected path ({src}) out of place.",
                    "Copy it instead, or ask the human to move it.",
                    subcmd)
    if not any(tok in _NO_CLOBBER for tok in argv[1:]):
        prot, kind = _is_protected_target(dest, cwd, config)
        if prot and kind == "name":
            return _verdict_for_tier(
                "high", "fs.overwrite_protected",
                f"`{cmd}` would overwrite a protected file ({dest}).",
                f"Use `{cmd} -n` so an existing file is never replaced, or back "
                "it up first.",
                subcmd)
    return None


_PROTECTED_BRANCHES = {"main", "master", "release", "production", "prod"}

# git global options that appear BEFORE the subcommand. Some consume the next
# token as a value (e.g. `git -C <dir> push`, `git -c x=y commit`).
_GIT_GLOBAL_VALUE_OPTS = {"-C", "-c", "--git-dir", "--work-tree", "--namespace",
                         "--super-prefix", "--config-env"}


def _git_subcommand(args):
    """
    Skip git global options and return (subcommand, remaining_args). Handles
    `git -C <dir> push …`, `git -c a=b reset …`, `git --git-dir=… clean …` so
    global options can't hide the real subcommand.
    """
    i = 0
    while i < len(args):
        a = args[i]
        if a in _GIT_GLOBAL_VALUE_OPTS:
            i += 2                      # option + its value
            continue
        if a.startswith("-"):
            i += 1                      # value-less global flag (--paginate, …)
            continue
        return a, args[i + 1:]          # first bareword is the subcommand
    return None, []


_PUSH_VALUE_OPTS = {"-o", "--push-option", "--repo", "--receive-pack", "--exec"}


class _Push:
    """What a `git push` does to which branches, from its flags and refspecs."""

    __slots__ = ("forced", "lease", "hits_protected", "deletes",
                 "deletes_protected")

    def __init__(self, forced, lease, hits_protected, deletes,
                 deletes_protected):
        self.forced = forced
        self.lease = lease
        self.hits_protected = hits_protected
        self.deletes = deletes
        self.deletes_protected = deletes_protected


def _branch_name(ref):
    return ref[len("refs/heads/"):] if ref.startswith("refs/heads/") else ref


def _parse_push(args):
    """
    Parse `git push` arguments. A refspec is [+]src[:dst]; + forces that ref,
    an empty src (`:main`) deletes dst, and dst defaults to src. Flags may be
    clustered (`-fu`).
    """
    shorts, longs, positional = set(), set(), []
    skip_next = False
    for tok in args:
        if skip_next:
            skip_next = False
            continue
        if tok in _PUSH_VALUE_OPTS:
            skip_next = True
        elif tok.startswith("--"):
            longs.add(tok[2:].split("=", 1)[0])
        elif tok.startswith("-") and len(tok) > 1:
            shorts.update(tok[1:])
        else:
            positional.append(tok)

    delete_flag = "d" in shorts or "delete" in longs
    forced = "f" in shorts or "force" in longs
    hits_protected = deletes = deletes_protected = False
    for spec in positional[1:]:                  # positional[0] is the remote
        if spec.startswith("+"):
            forced = True
            spec = spec[1:]
        src, sep, dst = spec.partition(":")
        dst = _branch_name(dst if sep else src)
        is_delete = delete_flag or (sep and not src)
        protected = dst in _PROTECTED_BRANCHES
        if is_delete:
            deletes = True
            deletes_protected = deletes_protected or protected
        else:
            hits_protected = hits_protected or protected
    lease = any(name.startswith("force-with-lease") for name in longs)
    return _Push(forced, lease, hits_protected, deletes, deletes_protected)


def _check_git(argv, subcmd):
    if not argv or _basename(argv[0]) != "git":
        return None
    sub, rest = _git_subcommand(argv[1:])
    if sub is None:
        return None
    text = " ".join([sub] + rest)

    if sub == "push":
        push = _parse_push(rest)
        if push.deletes_protected:
            return _verdict_for_tier(
                "critical", "git.delete_protected_branch",
                "Deleting a protected branch (main/master/production) on the "
                "remote removes shared history for everyone.",
                "Never delete a protected remote branch from an agent; ask the "
                "human.",
                subcmd)
        if push.forced and not push.lease:
            if push.hits_protected:
                return _verdict_for_tier(
                    "critical", "git.force_push_protected",
                    "Force-pushing to a protected branch (main/master/"
                    "production) rewrites shared history and can destroy "
                    "teammates' work.",
                    "Use --force-with-lease, and never force-push shared "
                    "branches without explicit human approval.",
                    subcmd)
            return _verdict_for_tier(
                "high", "git.force_push",
                "Force-push overwrites remote history and can discard commits.",
                "Prefer `git push --force-with-lease` which refuses to clobber "
                "unexpected remote changes.",
                subcmd)
        if push.deletes:
            return _verdict_for_tier(
                "medium", "git.delete_remote_branch",
                "This deletes a branch on the remote; unmerged commits on it "
                "are only recoverable from someone's local copy.",
                "Check the branch is merged (`git branch -r --merged`) first.",
                subcmd)

    if sub == "reset" and ("--hard" in rest):
        return _verdict_for_tier(
            "high", "git.reset_hard",
            "`git reset --hard` throws away all uncommitted changes with no "
            "recovery.",
            "Use `git stash` to save changes first, or `git reset --soft` to "
            "keep them staged.",
            subcmd)

    if sub == "clean" and any(("f" in t and t.startswith("-") and not t.startswith("--"))
                              or t == "--force" for t in rest):
        return _verdict_for_tier(
            "high", "git.clean",
            "`git clean -f` permanently deletes untracked files and "
            "directories.",
            "Run `git clean -n` (dry run) first to see exactly what would be "
            "removed.",
            subcmd)

    if sub == "branch" and any(t == "-D" or t == "--delete" and "--force" in rest for t in rest):
        return _verdict_for_tier(
            "high", "git.branch_force_delete",
            "`git branch -D` force-deletes a branch even if it has unmerged "
            "commits.",
            "Use `git branch -d` (lowercase) so merged-only branches are "
            "deleted safely.",
            subcmd)

    if sub in ("filter-branch", "filter-repo"):
        return _verdict_for_tier(
            "critical", "git.filter_history",
            f"`git {sub}` rewrites the entire repository history "
            "irreversibly.",
            "Make a full backup clone before rewriting history, and confirm "
            "with the human.",
            subcmd)

    if sub == "stash" and rest and rest[0] in ("drop", "clear"):
        return _verdict_for_tier(
            "medium", "git.stash_drop",
            f"`git stash {rest[0]}` permanently discards stashed changes.",
            "Verify with `git stash list` / `git stash show -p` before "
            "dropping.",
            subcmd)

    if sub in ("checkout", "restore") and re.search(r"(^|\s)(--\s+\.|\.$|\s\.\s|--\s|\brestore\s+\.)", text):
        # checkout -- .   /   restore .
        if "." in rest or "--" in rest:
            return _verdict_for_tier(
                "medium", "git.discard_worktree",
                f"`git {sub}` here discards local uncommitted changes in the "
                "working tree.",
                "Use `git stash` if you might want the changes back.",
                subcmd)
    return None


_SQL_DROP_DB = re.compile(r"\bdrop\s+(database|schema)\b", re.I)
_SQL_DROP_TABLE = re.compile(r"\bdrop\s+table\b", re.I)
_SQL_TRUNCATE = re.compile(r"\btruncate\b", re.I)


def _extract_sql(command, argv):
    """
    Pull the SQL text a DB client will run: from -c/-e/--command/--execute
    arguments, a positional query (sqlite3), and any heredoc body.
    """
    chunks = []
    flags_with_value = {"-c", "-e", "--command", "--execute", "-q", "--query"}
    i = 1
    while i < len(argv):
        tok = argv[i]
        if tok in flags_with_value and i + 1 < len(argv):
            chunks.append(argv[i + 1])
            i += 2
            continue
        for pref in ("--command=", "--execute=", "--query="):
            if tok.startswith(pref):
                chunks.append(tok[len(pref):])
        i += 1
    # sqlite3 <db> "<sql>" — trailing positional that looks like SQL.
    for tok in argv[1:]:
        if re.search(r"(?i)\b(drop|delete|truncate|update|insert|alter)\b", tok):
            chunks.append(tok)
    # Heredoc body from the raw command.
    for m in re.finditer(r"<<-?\s*['\"]?(\w+)['\"]?\s*\n(.*?)\n\s*\1",
                         command, re.S):
        chunks.append(m.group(2))
    return "\n".join(dict.fromkeys(chunks)) or command


def _check_sql(command, argv):
    """
    Scan for destructive SQL. Only fires when a known DB client is invoked
    somewhere in the command (avoids flagging `echo "DROP TABLE"`).
    """
    if not argv:
        return None
    cmd = _basename(argv[0])
    if cmd not in _DB_CLIENTS:
        return None

    text = _extract_sql(command, argv)
    if _SQL_DROP_DB.search(text):
        return _verdict_for_tier(
            "critical", "db.drop_database",
            "This drops an entire database/schema and all of its data.",
            "Back up first (pg_dump/mysqldump); confirm the target name.",
            command)
    if _SQL_TRUNCATE.search(text):
        return _verdict_for_tier(
            "critical", "db.truncate",
            "TRUNCATE removes every row in the table(s), usually "
            "non-transactionally and irreversibly.",
            "Use DELETE with a WHERE clause inside a transaction if you need to "
            "review/rollback.",
            command)
    # DELETE / UPDATE without WHERE — check each statement.
    for stmt in re.split(r";", text):
        s = stmt.strip()
        if re.match(r"(?i)^\s*delete\s+from\b", s) and not re.search(r"(?i)\bwhere\b", s):
            return _verdict_for_tier(
                "critical", "db.delete_no_where",
                "DELETE without a WHERE clause removes every row in the table.",
                "Add a WHERE clause, or run inside a transaction so you can "
                "ROLLBACK.",
                command)
        if re.match(r"(?i)^\s*update\s+\S+\s+set\b", s) and not re.search(r"(?i)\bwhere\b", s):
            return _verdict_for_tier(
                "high", "db.update_no_where",
                "UPDATE without a WHERE clause rewrites every row in the table.",
                "Add a WHERE clause, or run inside a transaction so you can "
                "ROLLBACK.",
                command)
    if _SQL_DROP_TABLE.search(text):
        return _verdict_for_tier(
            "high", "db.drop_table",
            "DROP TABLE permanently removes a table and all its rows.",
            "Confirm the table name; back up first if the data matters.",
            command)
    return None


def _check_declarative(argv, subcmd, rules):
    """Match the loaded rules.json entries against argv."""
    if not argv:
        return None
    cmd = _basename(argv[0])
    tokens = argv[1:]
    tokenset = set(tokens)
    worst = None
    for r in rules:
        m = r.get("match", {})
        rcmd = m.get("cmd")
        if rcmd:
            if isinstance(rcmd, str) and rcmd.endswith("*"):
                if not cmd.startswith(rcmd[:-1]):
                    continue
            elif cmd != rcmd:
                continue
        if "subcmd" in m:
            if not tokens or tokens[0] != m["subcmd"]:
                continue
        if "contains_all" in m:
            if not all(tok in tokenset for tok in m["contains_all"]):
                continue
        if "contains_any" in m:
            if not any(tok in tokenset for tok in m["contains_any"]):
                continue
        if "arg_regex" in m:
            if not re.search(m["arg_regex"], subcmd, re.I):
                continue
        worst = _worst(worst, _verdict_for_tier(
            r["tier"], r["id"], r.get("reason", ""), r.get("suggestion", ""),
            subcmd))
    return worst


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #

_MAX_DEPTH = 4


def check(command, cwd=None, config=None, _depth=0):
    """
    Evaluate a shell command string and return the highest-severity Verdict.
    """
    from .config import Config
    if config is None:
        config = Config.default()
    if cwd is None:
        cwd = os.getcwd()
    if _depth > _MAX_DEPTH:
        return Verdict("ask", "high", "exec.too_nested",
                       "Command nests shell execution too deeply to inspect "
                       "safely.",
                       "Flatten the command so it can be reviewed.", command)

    if config.disabled:
        return Verdict("allow")

    rules = load_rules()
    subcmds = split_commands(command)
    worst = None

    # Pipeline-level: piping into a bare shell.
    worst = _worst(worst, _check_pipe_to_shell(command, subcmds))

    # Commands inside $( ), backticks and <( ) run too.
    for inner in _substitutions(command):
        v = check(inner, cwd, config, _depth=_depth + 1)
        if v.action != "allow":
            worst = _worst(worst, v)

    for sub in subcmds:
        argv = _parse_argv(sub)
        if argv is None:
            # Unbalanced quotes / unparseable while containing destructive
            # tokens -> escalate; otherwise ignore.
            if _DESTRUCTIVE_TOKENS.search(sub):
                worst = _worst(worst, _verdict_for_tier(
                    "high", "parse.unparseable",
                    "A destructive-looking sub-command could not be parsed "
                    "(unbalanced quotes / obfuscation).",
                    "Rewrite the command so it parses cleanly.", sub))
            continue
        if not argv:
            continue

        # See through keywords and wrappers (flagging sudo/doas).
        unwrapped, had_sudo = _unwrap(argv)
        if unwrapped != argv:
            # Downstream regexes match on text; give them the real command.
            sub = " ".join(unwrapped)
        argv = unwrapped
        if not argv:
            if had_sudo:
                worst = _worst(worst, _verdict_for_tier(
                    "high", "sys.sudo", "Bare privileged escalation.",
                    "Avoid sudo from an agent.", sub))
            continue

        for checker in (
            lambda: _check_shell_exec(argv, sub, cwd, config, _depth),
            lambda: _check_obfuscation(sub, argv),
            lambda: _check_rm(argv, sub, cwd, config),
            lambda: _check_overwrite(argv, sub, cwd, config),
            lambda: _check_move_copy(argv, sub, cwd, config),
            lambda: _check_git(argv, sub),
            lambda: _check_sql(command, argv),
            lambda: _check_declarative(argv, sub, rules),
        ):
            worst = _worst(worst, checker())

        if had_sudo:
            worst = _worst(worst, _verdict_for_tier(
                "high", "sys.sudo",
                "Command runs with elevated privileges (sudo/doas); mistakes "
                "affect the whole system.",
                "Run without sudo if possible, or have the human review the "
                "privileged command.",
                sub))

    if worst is None:
        return Verdict("allow")

    # Apply config overrides (cannot relax critical rules).
    return config.apply_override(worst)

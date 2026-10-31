"""Shared helpers for the guardrails hooks.

Python 3.9+, standard library only. Every hook imports this module.

Design rules that all hooks follow:
  * fail open: an internal error never blocks legitimate work (exit 0, no output)
  * no network, no LLM calls, no external dependencies
  * configuration is JSON, merged from several layers (see load_config)
  * decisions are returned as Claude Code hook JSON on stdout
"""
import fnmatch
import json
import os
import re
import shlex
import sys
import time
from pathlib import Path

HOOK_DIR = Path(__file__).resolve().parent
PLUGIN_ROOT = Path(os.environ.get("CLAUDE_PLUGIN_ROOT") or HOOK_DIR.parent)

MODES = ("deny", "ask", "warn", "off")

# Command prefixes that merely wrap another command (the real command follows).
WRAPPERS = {"nice", "env", "time", "nohup", "command", "builtin", "exec", "stdbuf",
            "timeout", "ionice", "caffeinate"}
SEPARATORS = {";", "&&", "||", "|", "&", "(", ")", "|&", ";;"}


# --------------------------------------------------------------------------- input

def read_payload():
    """Parse the hook payload from stdin. Returns {} on any problem."""
    try:
        raw = sys.stdin.read()
        return json.loads(raw) if raw.strip() else {}
    except Exception:
        return {}


def tool_input(payload):
    ti = payload.get("tool_input")
    return ti if isinstance(ti, dict) else {}


# --------------------------------------------------------------------------- config

def _load_json(path):
    try:
        p = Path(path).expanduser()
        if p.is_file():
            data = json.loads(p.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
    except Exception:
        pass
    return {}


def merge(base, override):
    """Deep-merge dicts; lists and scalars in `override` replace the base value."""
    out = dict(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = merge(out[key], value)
        else:
            out[key] = value
    return out


def load_config(payload=None):
    """Configuration layers, later layers win:
      1. <plugin root>/guardrails.json            (shipped defaults)
      2. ~/.claude/guardrails.json                (user)
      3. <project>/.claude/guardrails.json        (project; CLAUDE_PROJECT_DIR or payload cwd)
      4. $GUARDRAILS_CONFIG                       (explicit file, e.g. for tests)
    """
    cfg = _load_json(PLUGIN_ROOT / "guardrails.json")
    cfg = merge(cfg, _load_json(Path.home() / ".claude" / "guardrails.json"))
    project = os.environ.get("CLAUDE_PROJECT_DIR") or (payload or {}).get("cwd")
    if project:
        cfg = merge(cfg, _load_json(Path(project) / ".claude" / "guardrails.json"))
    explicit = os.environ.get("GUARDRAILS_CONFIG")
    if explicit:
        cfg = merge(cfg, _load_json(explicit))
    return cfg


def hook_config(cfg, hook_name, defaults):
    """Per-hook section merged over the hook's built-in defaults."""
    section = cfg.get(hook_name)
    return merge(defaults, section if isinstance(section, dict) else {})


def is_disabled(cfg, hook_name, hcfg):
    """Global kill switch (GUARDRAILS_DISABLE=1 or a comma list of hook names) or enabled=false."""
    env = os.environ.get("GUARDRAILS_DISABLE", "").strip()
    if env:
        if env in ("1", "true", "all", "*"):
            return True
        if hook_name in [x.strip() for x in env.split(",")]:
            return True
    return not hcfg.get("enabled", True)


def lang(cfg):
    value = str(cfg.get("lang", "en")).lower()
    return "de" if value.startswith("de") else "en"


def text(cfg, messages, key, **kwargs):
    """Pick a message in the configured language (falls back to English)."""
    table = messages.get(lang(cfg)) or messages["en"]
    template = table.get(key) or messages["en"].get(key) or key
    try:
        return template.format(**kwargs)
    except Exception:
        return template


# --------------------------------------------------------------------------- state / log

def state_dir():
    base = (os.environ.get("GUARDRAILS_STATE_DIR")
            or os.environ.get("CLAUDE_PLUGIN_DATA")
            or str(Path.home() / ".claude" / "guardrails-state"))
    p = Path(base).expanduser()
    try:
        p.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    return p


def load_state(name):
    return _load_json(state_dir() / (name + ".json"))


def save_state(name, data):
    try:
        (state_dir() / (name + ".json")).write_text(json.dumps(data), encoding="utf-8")
    except Exception:
        pass


def log_event(cfg, hook_name, decision, detail):
    """Optional JSONL log for measuring false alarms. Off unless `log_file` is set."""
    path = cfg.get("log_file")
    if not path:
        return
    try:
        p = Path(str(path).replace("${CLAUDE_PLUGIN_DATA}", str(state_dir()))).expanduser()
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "hook": hook_name,
                                 "decision": decision, "detail": str(detail)[:300]}) + "\n")
    except Exception:
        pass


# --------------------------------------------------------------------------- output

def emit(event, decision=None, reason=None, context=None):
    """Print one Claude Code hook JSON object on stdout."""
    out = {"hookEventName": event}
    if decision in ("allow", "deny", "ask"):
        out["permissionDecision"] = decision
        if reason:
            out["permissionDecisionReason"] = reason
    if context:
        out["additionalContext"] = context
    print(json.dumps({"hookSpecificOutput": out}))


def finish(cfg, hook_name, mode, reason, event="PreToolUse"):
    """Apply a configured mode (deny | ask | warn | off) and return the exit code."""
    mode = str(mode or "warn").lower()
    if mode not in MODES:
        mode = "warn"
    log_event(cfg, hook_name, mode, reason)
    if mode == "off":
        return 0
    if mode == "warn":
        emit(event, context=reason)
        return 0
    emit(event, decision=mode, reason=reason)
    return 0


def run(main):
    """Entry wrapper: fail open on any exception."""
    try:
        code = main()
        sys.exit(code or 0)
    except SystemExit:
        raise
    except Exception:
        sys.exit(0)


# --------------------------------------------------------------------------- shell parsing

def strip_heredocs(command):
    """Remove here-document bodies: they are data, not commands."""
    out, marker = [], None
    for line in command.splitlines():
        if marker is not None:
            if line.strip() == marker:
                marker = None
            continue
        out.append(line)
        m = re.search(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1", line)
        if m:
            marker = m.group(2)
    return "\n".join(out)


def _tokens(chunk):
    lex = shlex.shlex(chunk, posix=True, punctuation_chars=";&|()")
    lex.whitespace_split = True
    lex.commenters = "#"
    return list(lex)


def split_commands(command):
    """Split a shell command line into simple commands (lists of argv tokens).

    Line breaks separate commands. A line with an unterminated quote is joined
    with the following lines until the quote closes (multi-line `python -c "..."`).
    Operators ; && || | & ( ) split simple commands. Heredoc bodies are skipped.
    """
    commands, current, buffer = [], [], ""
    for line in strip_heredocs(command).splitlines():
        buffer = line if not buffer else buffer + "\n" + line
        try:
            toks = _tokens(buffer)
        except ValueError:
            continue  # unterminated quote: wait for the next line
        buffer = ""
        for tok in toks:
            if tok in SEPARATORS or (tok and set(tok) <= set(";&|()")):
                if current:
                    commands.append(current)
                current = []
            else:
                current.append(tok)
        if current:
            commands.append(current)
        current = []
    return commands


def strip_wrappers(argv, extra=()):
    """Drop leading wrappers (nice -n 15, env X=1, time, sudo ...) and VAR=value assignments."""
    wrappers = WRAPPERS | set(extra)
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in wrappers:
            i += 1
            while i < len(argv) and (argv[i].startswith("-") or re.fullmatch(r"\d+[smhd]?", argv[i])
                                     or re.match(r"[A-Za-z_][A-Za-z0-9_]*=", argv[i])):
                i += 1
            continue
        if re.match(r"[A-Za-z_][A-Za-z0-9_]*=", a):
            i += 1
            continue
        break
    return argv[i:]


def command_name(argv):
    return Path(argv[0]).name if argv else ""


# --------------------------------------------------------------------------- paths

def path_matches(path, pattern):
    """Glob match for file paths.

    * pattern without "/"  -> matched against the file name only (".env*", "MEMORY.md")
    * "**/x/y.md"          -> y.md inside any x directory at any depth
    * other patterns       -> matched against the full path (and with a "*/" prefix)
    """
    path = str(path).replace("\\", "/")
    pattern = str(pattern).replace("\\", "/")
    if "/" not in pattern:
        return fnmatch.fnmatchcase(Path(path).name, pattern)
    if pattern.startswith("**/"):
        tail = pattern[3:]
        return fnmatch.fnmatchcase(path, "*/" + tail) or fnmatch.fnmatchcase(path, tail)
    return fnmatch.fnmatchcase(path, pattern) or fnmatch.fnmatchcase(path, "*/" + pattern)


def resolve(path, cwd=None):
    p = Path(os.path.expandvars(os.path.expanduser(str(path))))
    if not p.is_absolute():
        p = Path(cwd or os.getcwd()) / p
    try:
        return p.resolve()
    except Exception:
        return p.absolute()


def is_under(path, parent):
    try:
        Path(path).relative_to(Path(parent))
        return True
    except Exception:
        return False

#!/usr/bin/env python3
"""no-destructive-rm (PreToolUse, Bash)

Stops recursive or wildcard `rm`, `rm` on protected roots (/, ~, ., *) and other
destructive one-liners (force push, hard reset, git clean, find -delete ...).

Why: an agent that "cleans up" with `rm -rf` or `rm *` cannot be undone. Many
sandboxes and permission layers also turn these commands into a confirmation
prompt that stalls the whole run. Deleting named files one by one, or with a
scripting language, is both safer and prompt-free.

Config key: "no_destructive_rm"
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _lib as lib  # noqa: E402

HOOK = "no_destructive_rm"
DEFAULTS = {
    "enabled": True,
    "mode": "deny",                 # for recursive / wildcard rm
    "recursive": True,
    "wildcards": True,
    "protected_targets": ["/", "~", "$HOME", ".", "..", "*", "/*", "~/", "~/*", "./", "./*", "../"],
    "allow_under": [],              # directories where recursive/wildcard rm is fine (absolute or ~)
    "allow_scratchpad": True,       # the session scratchpad_dir and $TMPDIR are always fine
    "extra_mode": "ask",            # for extra_patterns
    "extra_patterns": [
        {"name": "git push --force", "pattern": r"\bgit\s+push\b[^\n;|&]*\s(--force|-f|--force-with-lease)\b"},
        {"name": "git reset --hard", "pattern": r"\bgit\s+reset\s+--hard\b"},
        {"name": "git clean -f", "pattern": r"\bgit\s+clean\b[^\n;|&]*\s-[a-zA-Z]*f"},
        {"name": "git checkout -- .", "pattern": r"\bgit\s+(checkout|restore)\s+(--\s+)?\.(\s|$)"},
        {"name": "find -delete", "pattern": r"\bfind\b[^\n;|&]*\s-delete\b"},
        {"name": "disk wipe", "pattern": r"\b(shred|mkfs(\.\w+)?|dd\s+if=|wipefs)\b"},
    ],
}
MESSAGES = {
    "en": {
        "protected": "rm on a protected target ({target}) is not allowed.",
        "recursive": "`rm -r` deletes whole trees and cannot be undone.",
        "wildcard": "`rm` with a wildcard ({target}) deletes whatever happens to match.",
        "extra": "Destructive command pattern: {name}.",
        "advice": "Delete named files one by one (full path), or use `os.remove` / `shutil.rmtree` "
                  "in a script on a path you verified. Directories under allow_under are exempt.",
    },
    "de": {
        "protected": "rm auf ein geschuetztes Ziel ({target}) ist nicht erlaubt.",
        "recursive": "`rm -r` loescht ganze Baeume und ist nicht rueckgaengig zu machen.",
        "wildcard": "`rm` mit Platzhalter ({target}) loescht alles, was zufaellig passt.",
        "extra": "Destruktives Befehlsmuster: {name}.",
        "advice": "Einzelne Dateien mit vollem Pfad loeschen oder `os.remove` / `shutil.rmtree` in einem "
                  "Skript auf einen geprueften Pfad anwenden. Verzeichnisse unter allow_under sind frei.",
    },
}
WILD = re.compile(r"[*?\[]")


def rm_argv_parts(argv):
    """Split rm argv into (flags, targets)."""
    flags, targets, only_targets = [], [], False
    for a in argv[1:]:
        if only_targets:
            targets.append(a)
        elif a == "--":
            only_targets = True
        elif a.startswith("-") and len(a) > 1:
            flags.append(a)
        else:
            targets.append(a)
    return flags, targets


def is_recursive(flags):
    for f in flags:
        if f in ("--recursive", "-R") or (not f.startswith("--") and re.search(r"[rR]", f)):
            return True
    return False


def is_protected(target, protected, home):
    if target in protected:
        return True
    expanded = target.replace("$HOME", home).replace("${HOME}", home)
    if expanded.startswith("~"):
        expanded = home + expanded[1:]
    stripped = expanded.rstrip("/") or "/"
    return stripped in ("/", home.rstrip("/"))


def allowed_dirs(hcfg, payload):
    dirs = [lib.resolve(d, payload.get("cwd")) for d in hcfg.get("allow_under") or []]
    if hcfg.get("allow_scratchpad", True):
        for key in ("scratchpad_dir",):
            if payload.get(key):
                dirs.append(lib.resolve(payload[key]))
        import os
        if os.environ.get("TMPDIR"):
            dirs.append(lib.resolve(os.environ["TMPDIR"]))
    return dirs


def targets_allowed(targets, dirs, cwd):
    if not dirs or not targets:
        return False
    for t in targets:
        base = re.split(r"[*?\[]", t, 1)[0]  # the literal prefix before the first wildcard
        if not base or base.endswith("/") and len(base) == 1:
            return False
        p = lib.resolve(base, cwd)
        if not any(lib.is_under(p, d) for d in dirs):
            return False
    return True


def check(command, hcfg, payload, cfg=None):
    """Return (severity, reason) or None. severity: 'protected' | 'main' | 'extra'."""
    import os
    home = os.path.expanduser("~")
    cfg_lang = cfg or {}
    dirs = allowed_dirs(hcfg, payload)
    for argv in lib.split_commands(command):
        argv = lib.strip_wrappers(argv, extra=("sudo", "doas", "xargs"))
        if lib.command_name(argv) != "rm":
            continue
        flags, targets = rm_argv_parts(argv)
        for t in targets:
            if is_protected(t, hcfg["protected_targets"], home):
                return "protected", lib.text(cfg_lang, MESSAGES, "protected", target=t)
        if targets_allowed(targets, dirs, payload.get("cwd")):
            continue
        if hcfg.get("recursive", True) and is_recursive(flags):
            return "main", lib.text(cfg_lang, MESSAGES, "recursive")
        if hcfg.get("wildcards", True):
            for t in targets:
                if WILD.search(t):
                    return "main", lib.text(cfg_lang, MESSAGES, "wildcard", target=t)
    flat = lib.strip_heredocs(command)
    for rule in hcfg.get("extra_patterns") or []:
        try:
            if re.search(rule["pattern"], flat):
                return "extra", lib.text(cfg_lang, MESSAGES, "extra", name=rule.get("name", rule["pattern"]))
        except Exception:
            continue
    return None


def main():
    payload = lib.read_payload()
    if payload.get("tool_name") != "Bash":
        return 0
    cfg = lib.load_config(payload)
    hcfg = lib.hook_config(cfg, HOOK, DEFAULTS)
    if lib.is_disabled(cfg, HOOK, hcfg):
        return 0
    command = str(lib.tool_input(payload).get("command", ""))
    hit = check(command, hcfg, payload, cfg)
    if not hit:
        return 0
    severity, reason = hit
    reason = "[no-destructive-rm] " + reason + " " + lib.text(cfg, MESSAGES, "advice")
    if severity == "protected":
        mode = "deny"
    elif severity == "extra":
        mode = hcfg.get("extra_mode", "ask")
    else:
        mode = hcfg.get("mode", "deny")
    return lib.finish(cfg, HOOK, mode, reason)


if __name__ == "__main__":
    lib.run(main)

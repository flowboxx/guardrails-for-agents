#!/usr/bin/env python3
"""protect-files (PreToolUse: Write | Edit | MultiEdit | Bash)

Protects configured files from being overwritten. Default policy "edit":
the Write tool (whole-file replace) is blocked on an existing protected file,
targeted Edits stay allowed. Policy "none" blocks Edits too. Bash truncation
(`> file`, `tee file`, `cp x file`, `mv x file`, `rm file`) is caught as well.

Why: long-lived files such as CLAUDE.md, a memory index or settings.json are
rewritten from memory by an agent far too easily, and a Write silently drops
everything the agent did not have in its context. Edits are reviewable and
additive; whole-file rewrites are not.

Config key: "protect_files"
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _lib as lib  # noqa: E402

HOOK = "protect_files"
DEFAULTS = {
    "enabled": True,
    "mode": "deny",
    "allow_create": True,            # Write may create a protected file that does not exist yet
    "watch_bash": True,
    "protected": [
        {"glob": "CLAUDE.md", "allow": "edit"},
        {"glob": "AGENTS.md", "allow": "edit"},
        {"glob": "MEMORY.md", "allow": "edit"},
        {"glob": "**/.claude/settings.json", "allow": "edit"},
        {"glob": "**/.claude/settings.local.json", "allow": "edit"},
        {"glob": ".env", "allow": "none"},
        {"glob": ".env.*", "allow": "none"},
    ],
}
MESSAGES = {
    "en": {
        "write": "{path} is protected (policy '{policy}'): no whole-file Write. Use Edit for targeted changes.",
        "edit": "{path} is protected (policy 'none'): no edits by the agent at all.",
        "bash": "{path} is protected: the shell command would overwrite or remove it ({how}).",
    },
    "de": {
        "write": "{path} ist geschuetzt (Regel '{policy}'): kein Write der ganzen Datei. Edit fuer gezielte Aenderungen nutzen.",
        "edit": "{path} ist geschuetzt (Regel 'none'): keine Aenderung durch den Agenten.",
        "bash": "{path} ist geschuetzt: der Shell-Befehl wuerde die Datei ueberschreiben oder loeschen ({how}).",
    },
}


def policy_for(path, hcfg):
    for rule in hcfg.get("protected") or []:
        if lib.path_matches(path, rule.get("glob", "")):
            return str(rule.get("allow", "edit")).lower()
    return None


def check_file_tool(tool, path, hcfg, cwd):
    policy = policy_for(path, hcfg)
    if policy is None:
        return None
    exists = lib.resolve(path, cwd).exists()
    if tool == "Write":
        if not exists and hcfg.get("allow_create", True) and policy != "none":
            return None
        return "write", policy
    if tool in ("Edit", "MultiEdit") and policy == "none":
        return "edit", policy
    return None


def check_bash(command, hcfg, cwd):
    """Detect truncating redirects and overwriting commands aimed at a protected file."""
    for argv in lib.split_commands(command):
        argv = lib.strip_wrappers(argv, extra=("sudo",))
        if not argv:
            continue
        # redirects: tokens like ">" "file" or ">file" (but not ">>")
        for i, tok in enumerate(argv):
            target = None
            if tok in (">", "1>", "2>", "&>"):
                target = argv[i + 1] if i + 1 < len(argv) else None
            elif re.match(r"^(1|2|&)?>(?!>)", tok) and len(tok) > 1 and not tok.startswith(">>"):
                target = re.sub(r"^(1|2|&)?>", "", tok)
            if target and policy_for(target, hcfg) is not None:
                return target, "redirect >"
        name = lib.command_name(argv)
        if name == "tee" and "-a" not in argv and "--append" not in argv:
            for t in argv[1:]:
                if not t.startswith("-") and policy_for(t, hcfg) is not None:
                    return t, "tee"
        if name in ("cp", "mv", "install", "rsync") and len(argv) >= 3:
            t = argv[-1]
            if policy_for(t, hcfg) is not None:
                return t, name
        if name in ("rm", "truncate", "shred", "unlink"):
            for t in argv[1:]:
                if not t.startswith("-") and policy_for(t, hcfg) is not None:
                    return t, name
        if name == "sed" and any(a.startswith("-i") for a in argv[1:]):
            for t in argv[1:]:
                if not t.startswith("-") and policy_for(t, hcfg) is not None and policy_for(t, hcfg) == "none":
                    return t, "sed -i"
    return None


def main():
    payload = lib.read_payload()
    cfg = lib.load_config(payload)
    hcfg = lib.hook_config(cfg, HOOK, DEFAULTS)
    if lib.is_disabled(cfg, HOOK, hcfg):
        return 0
    tool = payload.get("tool_name")
    ti = lib.tool_input(payload)
    cwd = payload.get("cwd")
    if tool in ("Write", "Edit", "MultiEdit"):
        path = str(ti.get("file_path", ""))
        hit = check_file_tool(tool, path, hcfg, cwd)
        if not hit:
            return 0
        kind, policy = hit
        reason = "[protect-files] " + lib.text(cfg, MESSAGES, kind, path=path, policy=policy)
        return lib.finish(cfg, HOOK, hcfg.get("mode", "deny"), reason)
    if tool == "Bash" and hcfg.get("watch_bash", True):
        hit = check_bash(str(ti.get("command", "")), hcfg, cwd)
        if not hit:
            return 0
        path, how = hit
        reason = "[protect-files] " + lib.text(cfg, MESSAGES, "bash", path=path, how=how)
        return lib.finish(cfg, HOOK, hcfg.get("mode", "deny"), reason)
    return 0


if __name__ == "__main__":
    lib.run(main)

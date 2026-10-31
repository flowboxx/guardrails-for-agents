#!/usr/bin/env python3
"""ask-before-sudo (PreToolUse, Bash)

Turns every `sudo` / `doas` / `pkexec` / `su` into a permission prompt (or a
block), including `sudo` hidden inside an `ssh host "sudo ..."` one-liner.

Why: privilege escalation is the one thing an agent should never do silently.
On top of that, an interactive `sudo` password prompt inside a tool call hangs
the whole session. `sudo -n` (non-interactive) is allowed by default because
it either works without a prompt or fails fast.

Config key: "ask_before_sudo"
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _lib as lib  # noqa: E402

HOOK = "ask_before_sudo"
DEFAULTS = {
    "enabled": True,
    "mode": "ask",
    "commands": ["sudo", "doas", "pkexec", "su"],
    "allow_non_interactive": True,      # `sudo -n ...` passes
    "allowed": [],                       # regexes on the escalated command, e.g. "^systemctl status"
    "check_ssh": True,                   # also look inside ssh remote command strings
}
MESSAGES = {
    "en": {
        "local": "`{cmd}` escalates privileges ({what}). Confirm, or run it without escalation.",
        "ssh": "`sudo` inside an ssh one-liner ({what}) escalates privileges on the remote host "
               "and may hang on a password prompt. Confirm, or use `sudo -n` / a non-root path.",
    },
    "de": {
        "local": "`{cmd}` erhoeht die Rechte ({what}). Bestaetigen oder ohne Rechteerhoehung ausfuehren.",
        "ssh": "`sudo` in einem ssh-Einzeiler ({what}) erhoeht die Rechte auf dem Zielrechner und kann "
               "an einer Passwortabfrage haengen. Bestaetigen oder `sudo -n` / einen Weg ohne root nutzen.",
    },
}
SUDO_IN_TEXT = re.compile(r"(^|[;&|(`\s])(sudo|doas)(?!\s+-n(\s|$))(\s|$)")


def escalated_command(argv):
    """The command that follows sudo and its options, as one string."""
    rest = argv[1:]
    i = 0
    while i < len(rest) and rest[i].startswith("-"):
        if rest[i] in ("-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U", "-T", "-c"):
            i += 2
        else:
            i += 1
    return " ".join(rest[i:])


def check(command, hcfg):
    """Return (kind, what) or None."""
    commands = set(hcfg.get("commands") or [])
    allowed = [re.compile(p) for p in hcfg.get("allowed") or []]
    for argv in lib.split_commands(command):
        argv = lib.strip_wrappers(argv, extra=("xargs",))
        name = lib.command_name(argv)
        if name in commands:
            if hcfg.get("allow_non_interactive", True) and name in ("sudo", "doas") and "-n" in argv[1:3]:
                continue
            what = escalated_command(argv) or name
            if any(p.search(what) for p in allowed):
                continue
            return "local", (name + " " + what).strip()
        if hcfg.get("check_ssh", True) and name == "ssh":
            remote = " ".join(argv[1:])
            if SUDO_IN_TEXT.search(remote):
                if any(p.search(remote) for p in allowed):
                    continue
                return "ssh", remote[:80]
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
    hit = check(command, hcfg)
    if not hit:
        return 0
    kind, what = hit
    cmd = what.split(" ", 1)[0]
    reason = "[ask-before-sudo] " + lib.text(cfg, MESSAGES, kind, cmd=cmd, what=what[:80])
    return lib.finish(cfg, HOOK, hcfg.get("mode", "ask"), reason)


if __name__ == "__main__":
    lib.run(main)

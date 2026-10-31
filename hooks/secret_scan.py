#!/usr/bin/env python3
"""secret-scan (PreToolUse: Write | Edit | MultiEdit | Bash)

Blocks tool calls that would write a credential into a file, paste one into a
shell command, or commit one (`git commit` is checked against the staged diff).

Why: a token that lands in a file or a transcript is already leaked. Catching
it before the write is cheaper than rotating it afterwards. The reason text
never echoes the secret itself, only the pattern name and a masked prefix.

Also usable as a plain git pre-commit hook: `scripts/pre-commit`.

Config key: "secret_scan"
"""
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _lib as lib  # noqa: E402

HOOK = "secret_scan"
DEFAULTS = {
    "enabled": True,
    "mode": "deny",
    "scan_writes": True,
    "scan_bash_commands": True,
    "scan_git_commit": True,
    "ignore_paths": ["*.lock", "package-lock.json", "yarn.lock", "*.min.js", "*.map", "*.svg"],
    "allow_patterns": [                     # a match here disarms the finding (placeholders)
        r"(?i)example|changeme|change-me|placeholder|your[-_ ]?(api[-_ ]?)?(key|token|secret)",
        r"(?i)dummy|redacted|xxxx|0000000|<[^>]*(key|token|secret)[^>]*>|\$\{[^}]+\}|\{\{[^}]+\}\}",
    ],
    "allow_marker": "guardrails: allow-secret",   # put this on the line to accept it knowingly
    "extra_patterns": [],                  # [{"name": "...", "pattern": "..."}]
    "max_findings": 5,
}
PATTERNS = [
    ("private key block", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY"),
    ("AWS access key id", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("AWS secret key", r"(?i)aws[^\n]{0,30}?(?:secret|key)[^\n]{0,8}['\"][0-9A-Za-z/+]{40}['\"]"),
    ("GitHub token", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b"),
    ("GitLab token", r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
    ("Slack token", r"\bxox[abpres]-[0-9A-Za-z-]{10,}\b"),
    ("Slack webhook", r"hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]{20,}"),
    ("OpenAI/Anthropic-style key", r"\bsk-(?:ant-|proj-|live-)?[A-Za-z0-9_-]{20,}\b"),
    ("Google API key", r"\bAIza[0-9A-Za-z_-]{35}\b"),
    ("Stripe key", r"\b(?:sk|rk|pk)_(?:live|test)_[0-9A-Za-z]{20,}\b"),
    ("Telegram bot token", r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b"),
    ("SendGrid key", r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"),
    ("JWT", r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ("Basic-auth URL", r"[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s:@]{6,}@[^\s/]+"),
    ("Bearer header", r"(?i)authorization:\s*bearer\s+[A-Za-z0-9._~+/=-]{20,}"),
    ("generic assignment", r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret"
                           r"|passwd|password|secret|token)\b\s*[:=]\s*['\"][^'\"\s]{12,}['\"]"),
]
MESSAGES = {
    "en": {
        "head": "Possible secret(s) found, call blocked:",
        "line": "{name} in {where} line {line} ({masked})",
        "advice": "Use an environment variable or a secrets store, keep placeholders like <YOUR_TOKEN>, "
                  "or add `{marker}` to the line if it is a known false alarm.",
    },
    "de": {
        "head": "Moegliche Geheimnisse gefunden, Aufruf geblockt:",
        "line": "{name} in {where} Zeile {line} ({masked})",
        "advice": "Umgebungsvariable oder Tresor nutzen, Platzhalter wie <YOUR_TOKEN> stehen lassen, "
                  "oder `{marker}` an die Zeile schreiben, wenn es ein bekannter Fehlalarm ist.",
    },
}


def compiled_patterns(hcfg):
    pats = [(n, re.compile(p)) for n, p in PATTERNS]
    for rule in hcfg.get("extra_patterns") or []:
        try:
            pats.append((rule.get("name", "custom"), re.compile(rule["pattern"])))
        except Exception:
            continue
    return pats


def mask(value):
    value = value.strip("'\"")
    return value[:4] + "..." + "(" + str(len(value)) + " chars)"


def scan_text(txt, hcfg, where="content"):
    """Return a list of findings (name, where, line_no, masked)."""
    findings = []
    allow = [re.compile(p) for p in hcfg.get("allow_patterns") or []]
    marker = hcfg.get("allow_marker") or ""
    pats = compiled_patterns(hcfg)
    for no, line in enumerate(str(txt).splitlines(), 1):
        if marker and marker in line:
            continue
        for name, rx in pats:
            m = rx.search(line)
            if not m:
                continue
            if any(a.search(m.group(0)) for a in allow):
                continue
            findings.append((name, where, no, mask(m.group(0))))
            break
        if len(findings) >= int(hcfg.get("max_findings", 5)):
            break
    return findings


def ignored(path, hcfg):
    return any(lib.path_matches(path, g) for g in hcfg.get("ignore_paths") or [])


def staged_diff(cwd):
    try:
        out = subprocess.run(["git", "diff", "--cached", "-U0", "--no-color", "--diff-filter=ACMR"],
                             cwd=cwd or None, capture_output=True, text=True, timeout=15)
        return out.stdout if out.returncode == 0 else ""
    except Exception:
        return ""


def scan_diff(diff, hcfg):
    findings, current = [], "staged diff"
    chunk = []

    def flush():
        if chunk and not ignored(current, hcfg):
            findings.extend(scan_text("\n".join(chunk), hcfg, current))
        chunk.clear()

    for line in diff.splitlines():
        if line.startswith("+++ "):
            flush()
            current = line[4:].strip()
            if current.startswith("b/"):
                current = current[2:]
        elif line.startswith("+") and not line.startswith("+++"):
            chunk.append(line[1:])
    flush()
    return findings[: int(hcfg.get("max_findings", 5))]


def collect(payload, hcfg):
    tool = payload.get("tool_name")
    ti = lib.tool_input(payload)
    if tool in ("Write", "Edit", "MultiEdit") and hcfg.get("scan_writes", True):
        path = str(ti.get("file_path", ""))
        if ignored(path, hcfg):
            return []
        if tool == "Write":
            return scan_text(ti.get("content", ""), hcfg, path or "content")
        if tool == "Edit":
            return scan_text(ti.get("new_string", ""), hcfg, path or "edit")
        out = []
        for e in ti.get("edits") or []:
            out.extend(scan_text((e or {}).get("new_string", ""), hcfg, path or "edit"))
        return out
    if tool == "Bash":
        command = str(ti.get("command", ""))
        out = []
        if hcfg.get("scan_bash_commands", True):
            out.extend(scan_text(command, hcfg, "command"))
        if hcfg.get("scan_git_commit", True) and re.search(r"\bgit\b[^\n;|&]*\bcommit\b", lib.strip_heredocs(command)):
            out.extend(scan_diff(staged_diff(payload.get("cwd")), hcfg))
        return out
    return []


def main():
    payload = lib.read_payload()
    cfg = lib.load_config(payload)
    hcfg = lib.hook_config(cfg, HOOK, DEFAULTS)
    if lib.is_disabled(cfg, HOOK, hcfg):
        return 0
    findings = collect(payload, hcfg)
    if not findings:
        return 0
    lines = [lib.text(cfg, MESSAGES, "line", name=n, where=w, line=l, masked=m) for n, w, l, m in findings]
    reason = ("[secret-scan] " + lib.text(cfg, MESSAGES, "head") + " " + "; ".join(lines) + ". "
              + lib.text(cfg, MESSAGES, "advice", marker=hcfg.get("allow_marker")))
    return lib.finish(cfg, HOOK, hcfg.get("mode", "deny"), reason)


if __name__ == "__main__":
    lib.run(main)

"""Package hygiene: the repository must not leak anything from the environment it was built in.

No absolute home paths, no internal host names, no e-mail addresses or ssh targets
(except example.com / noreply), no IP addresses, no vendor-specific words. The forbidden
words are stored base64-encoded so that this file does not itself contain them.
"""
import base64
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEXT_EXT = {".py", ".md", ".json", ".txt", ".toml", ".cfg", ".ini", ".yml", ".yaml", ".sh", ""}
SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", "node_modules"}

# base64 of lower-case words that must never appear (case-insensitive)
_FORBIDDEN_B64 = [
    "c2VudGluYWw=", "c2VydmVyYg==", "c2VydmVyYQ==", "dGFmZWxwcnVlZmVy", "cHJ1ZWZhcHA=",
    "ZW5yaWNv", "b3BwZWw=", "bWFzY2hh", "ZWRkYQ==", "b2xoYQ==", "ZG9yYQ==", "ZHBpYXBw", "a2ltaQ==",
    "a3VuZGVucG9ydGFs", "cmVsZWFzZV9rZXR0ZQ==", "L29wdC90YWZlbA==",
]
FORBIDDEN = [base64.b64decode(x).decode() for x in _FORBIDDEN_B64]
HOME_PATH = re.compile(r"(/" + "Users" + "/|/" + "home" + "/[a-z])")
EMAIL_OR_SSH = re.compile(r"\b[\w.+-]+@([\w-]+\.)+[a-z]{2,}\b", re.I)
IPV4 = re.compile(r"\b(\d{1,3}\.){3}\d{1,3}\b")
HOST = re.compile(r"\b([a-z0-9-]+\.)+(de|com|net|org|io|dev|app|ai)\b", re.I)
ALLOWED_HOSTS = {"example.com", "api.example.com", "github.com", "code.claude.com", "docs.claude.com",
                 "hooks.slack.com", "registry.npmjs.org", "pypi.org", "claude.com", "anthropic.com",
                 "keepachangelog.com", "users.noreply.github.com"}
ALLOWED_IPS = {"127.0.0.1", "0.0.0.0"}


def repo_files():
    out = []
    for p in ROOT.rglob("*"):
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if p.is_file() and p.suffix.lower() in TEXT_EXT:
            out.append(p)
    return out


def test_repo_has_files():
    assert len(repo_files()) > 10


def test_no_forbidden_words():
    hits = []
    for p in repo_files():
        low = p.read_text(encoding="utf-8", errors="replace").lower()
        for word in FORBIDDEN:
            if word in low:
                hits.append("%s: %s" % (p.relative_to(ROOT), word[:3] + "*"))
    assert not hits, hits


def test_no_home_paths():
    hits = [str(p.relative_to(ROOT)) for p in repo_files() if HOME_PATH.search(p.read_text(encoding="utf-8", errors="replace"))]
    assert not hits, hits


def test_no_emails_or_ssh_targets():
    hits = []
    for p in repo_files():
        for m in EMAIL_OR_SSH.finditer(p.read_text(encoding="utf-8", errors="replace")):
            domain = m.group(0).split("@", 1)[1].lower()
            if domain not in ("example.com", "users.noreply.github.com"):
                hits.append("%s: %s" % (p.relative_to(ROOT), m.group(0)))
    assert not hits, hits


def test_no_ip_addresses():
    hits = []
    for p in repo_files():
        for m in IPV4.finditer(p.read_text(encoding="utf-8", errors="replace")):
            parts = [int(x) for x in m.group(0).split(".")]
            if all(x <= 255 for x in parts) and m.group(0) not in ALLOWED_IPS:
                hits.append("%s: %s" % (p.relative_to(ROOT), m.group(0)))
    assert not hits, hits


def test_no_unknown_hosts():
    hits = []
    for p in repo_files():
        for m in HOST.finditer(p.read_text(encoding="utf-8", errors="replace")):
            host = m.group(0).lower()
            if host not in ALLOWED_HOSTS and not host.endswith(".example.com"):
                hits.append("%s: %s" % (p.relative_to(ROOT), host))
    assert not hits, hits


def test_hook_scripts_are_stdlib_only_and_py39_syntax():
    import ast
    stdlib_ok = set(sys.stdlib_module_names) if hasattr(sys, "stdlib_module_names") else None
    for p in (ROOT / "hooks").glob("*.py"):
        tree = ast.parse(p.read_text(encoding="utf-8"), filename=str(p), feature_version=(3, 9))
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module.split(".")[0]]
            for n in names:
                if n.startswith("_lib") or n in ("secret_scan",):
                    continue
                if stdlib_ok is not None:
                    assert n in stdlib_ok, "%s imports non-stdlib module %s" % (p.name, n)


def test_plugin_manifest_and_hooks_json_are_consistent():
    manifest = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text())
    assert manifest["name"] and "claude" not in manifest["name"].lower() and "anthropic" not in manifest["name"].lower()
    assert manifest["license"] == "MIT"
    hooks = json.loads((ROOT / "hooks" / "hooks.json").read_text())["hooks"]
    referenced = set()
    for event, groups in hooks.items():
        for g in groups:
            for h in g["hooks"]:
                m = re.search(r"/hooks/([a-z_]+\.py)", h["command"])
                assert m, h["command"]
                referenced.add(m.group(1))
                assert (ROOT / "hooks" / m.group(1)).is_file()
                assert '"${CLAUDE_PLUGIN_ROOT}"' in h["command"]
    shipped = {p.name for p in (ROOT / "hooks").glob("*.py") if not p.name.startswith("_")}
    assert referenced == shipped, (referenced ^ shipped)


def test_readme_covers_every_hook_and_has_disclaimer():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for name in ("no-destructive-rm", "ask-before-sudo", "secret-scan", "protect-files",
                 "time-check", "tab-guard", "mechanic-or-judgement"):
        assert name in readme, name
    assert "not affiliated with Anthropic" in readme
    assert (ROOT / "LICENSE").read_text().startswith("MIT License")
    assert (ROOT / "CHANGELOG.md").is_file()


def test_print_defaults_runs(tmp_path):
    env = {"HOME": str(tmp_path), "PATH": "/usr/bin:/bin"}
    proc = subprocess.run([sys.executable, str(ROOT / "scripts" / "print-defaults.py"), "--defaults"],
                          capture_output=True, text=True, env=env)
    assert proc.returncode == 0
    data = json.loads(proc.stdout)
    assert set(data) >= {"no_destructive_rm", "ask_before_sudo", "secret_scan", "protect_files",
                         "time_check", "tab_guard", "mechanic_or_judgement"}

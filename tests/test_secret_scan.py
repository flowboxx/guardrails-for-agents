import subprocess

from conftest import decision, reason

HOOK = "secret_scan.py"
FAKE_AWS = "AKIA" + "ABCDEFGHIJKLMNOP"            # pattern-shaped test value, not a credential
FAKE_GH = "ghp_" + "a" * 36
FAKE_SK = "sk-" + "x" * 30


def write(path, content):
    return {"tool_name": "Write", "tool_input": {"file_path": path, "content": content}}


def test_clean_content_passes(run_hook):
    rc, data, _ = run_hook(HOOK, write("notes.md", "token = os.environ['API_TOKEN']\nnothing here"))
    assert data is None


def test_aws_key_in_write_denied_and_masked(run_hook):
    rc, data, _ = run_hook(HOOK, write("config.py", "KEY = '%s'" % FAKE_AWS))
    assert decision(data) == "deny"
    r = reason(data)
    assert "AWS access key id" in r and "config.py" in r and "line 1" in r
    assert FAKE_AWS not in r  # never echo the secret


def test_github_token_in_edit_denied(run_hook):
    payload = {"tool_name": "Edit", "tool_input": {"file_path": "a.sh", "old_string": "x", "new_string": "export T=%s" % FAKE_GH}}
    rc, data, _ = run_hook(HOOK, payload)
    assert decision(data) == "deny"


def test_private_key_block_denied(run_hook):
    rc, data, _ = run_hook(HOOK, write("id_rsa", "-----BEGIN OPENSSH PRIVATE KEY-----\nabc"))
    assert decision(data) == "deny"


def test_generic_assignment_with_placeholder_passes(run_hook):
    rc, data, _ = run_hook(HOOK, write("settings.example.json", '{"api_key": "<YOUR_API_KEY_HERE>"}'))
    assert data is None
    rc, data, _ = run_hook(HOOK, write("x.py", 'password = "changeme-please-now"'))
    assert data is None


def test_generic_assignment_real_looking_denied(run_hook):
    rc, data, _ = run_hook(HOOK, write("x.py", 'password = "q8Zt3vP0mL2xR9kW"'))
    assert decision(data) == "deny"


def test_allow_marker_disarms(run_hook):
    rc, data, _ = run_hook(HOOK, write("x.py", "KEY = '%s'  # guardrails: allow-secret" % FAKE_AWS))
    assert data is None


def test_ignore_paths(run_hook):
    rc, data, _ = run_hook(HOOK, write("package-lock.json", '"integrity": "%s"' % FAKE_GH))
    assert data is None


def test_bash_command_with_bearer_token_denied(run_hook):
    cmd = "curl -H 'Authorization: Bearer %s' https://api.example.com" % ("A1b2" * 8)
    rc, data, _ = run_hook(HOOK, {"tool_name": "Bash", "tool_input": {"command": cmd}})
    assert decision(data) == "deny"


def test_bash_scan_can_be_switched_off(run_hook):
    cmd = "echo %s" % FAKE_SK
    rc, data, _ = run_hook(HOOK, {"tool_name": "Bash", "tool_input": {"command": cmd}},
                           config={"secret_scan": {"scan_bash_commands": False}})
    assert data is None


def test_git_commit_scans_staged_diff(run_hook, env, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", repo], check=True)
    (repo / "app.env").write_text("TOKEN=%s\n" % FAKE_GH)
    subprocess.run(["git", "-C", str(repo), "add", "app.env"], check=True)
    payload = {"tool_name": "Bash", "tool_input": {"command": "git commit -m 'add env'"}, "cwd": str(repo)}
    rc, data, _ = run_hook(HOOK, payload)
    assert decision(data) == "deny"
    assert "app.env" in reason(data)


def test_git_commit_clean_diff_passes(run_hook, tmp_path):
    repo = tmp_path / "repo2"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", repo], check=True)
    (repo / "README.md").write_text("hello\n")
    subprocess.run(["git", "-C", str(repo), "add", "README.md"], check=True)
    payload = {"tool_name": "Bash", "tool_input": {"command": "git commit -m 'docs'"}, "cwd": str(repo)}
    rc, data, _ = run_hook(HOOK, payload)
    assert data is None


def test_extra_pattern(run_hook):
    cfg = {"secret_scan": {"extra_patterns": [{"name": "internal id", "pattern": r"INT-[0-9]{8}"}]}}
    rc, data, _ = run_hook(HOOK, write("x.txt", "ref INT-12345678"), config=cfg)
    assert decision(data) == "deny" and "internal id" in reason(data)


def test_pre_commit_script_blocks(tmp_path, env):
    import sys
    from conftest import ROOT
    repo = tmp_path / "repo3"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", repo], check=True)
    (repo / "k.txt").write_text("key: %s\n" % FAKE_AWS)
    subprocess.run(["git", "-C", str(repo), "add", "k.txt"], check=True)
    proc = subprocess.run([sys.executable, str(ROOT / "scripts" / "pre-commit")], cwd=repo, capture_output=True, text=True, env=env)
    assert proc.returncode == 1 and "k.txt" in proc.stderr and FAKE_AWS not in proc.stderr

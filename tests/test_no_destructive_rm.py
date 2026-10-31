from conftest import decision, reason

HOOK = "no_destructive_rm.py"


def bash(cmd):
    return {"tool_name": "Bash", "tool_input": {"command": cmd}}


def test_plain_rm_single_file_passes(run_hook):
    rc, data, _ = run_hook(HOOK, bash("rm build/output.txt"))
    assert rc == 0 and data is None


def test_recursive_rm_denied(run_hook):
    rc, data, _ = run_hook(HOOK, bash("rm -rf build"))
    assert rc == 0 and decision(data) == "deny"
    assert "no-destructive-rm" in reason(data)


def test_wildcard_rm_denied(run_hook):
    rc, data, _ = run_hook(HOOK, bash("rm logs/*.log"))
    assert decision(data) == "deny"
    assert "*.log" in reason(data)


def test_protected_root_always_denied_even_in_warn_mode(run_hook):
    rc, data, _ = run_hook(HOOK, bash("rm -rf ~"), config={"no_destructive_rm": {"mode": "warn"}})
    assert decision(data) == "deny"


def test_mode_warn_gives_context_only(run_hook):
    rc, data, _ = run_hook(HOOK, bash("rm -r tmpdir"), config={"no_destructive_rm": {"mode": "warn"}})
    assert decision(data) == "warn"


def test_allow_under_exempts_directory(run_hook, tmp_path):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    cfg = {"no_destructive_rm": {"allow_under": [str(scratch)]}}
    rc, data, _ = run_hook(HOOK, bash("rm -rf %s/cache" % scratch), config=cfg)
    assert data is None
    rc, data, _ = run_hook(HOOK, bash("rm -rf %s/other" % tmp_path), config=cfg)
    assert decision(data) == "deny"


def test_scratchpad_dir_from_payload_is_exempt(run_hook, tmp_path):
    pad = tmp_path / "pad"
    pad.mkdir()
    payload = dict(bash("rm -rf %s/x" % pad), scratchpad_dir=str(pad))
    rc, data, _ = run_hook(HOOK, payload)
    assert data is None


def test_heredoc_and_python_string_do_not_trigger(run_hook):
    cmd = 'cat > notes.md <<EOF\nnever run rm -rf /\nEOF\npython3 -c "print(\'rm -rf *\')"'
    rc, data, _ = run_hook(HOOK, bash(cmd))
    assert data is None


def test_sudo_and_xargs_wrappers_are_seen_through(run_hook):
    rc, data, _ = run_hook(HOOK, bash("find . -name '*.pyc' | xargs rm -r"))
    assert decision(data) == "deny"
    rc, data, _ = run_hook(HOOK, bash("sudo rm -rf /var/cache/x"))
    assert decision(data) == "deny"


def test_force_push_asks(run_hook):
    rc, data, _ = run_hook(HOOK, bash("git push --force origin main"))
    assert decision(data) == "ask"
    assert "git push --force" in reason(data)


def test_extra_pattern_can_be_customised(run_hook):
    cfg = {"no_destructive_rm": {"extra_patterns": [{"name": "drop table", "pattern": r"(?i)drop\s+table"}],
                                 "extra_mode": "deny"}}
    rc, data, _ = run_hook(HOOK, bash("psql -c 'DROP TABLE users'"), config=cfg)
    assert decision(data) == "deny"
    rc, data, _ = run_hook(HOOK, bash("git push --force"), config=cfg)
    assert data is None  # default list replaced


def test_disabled_by_env(run_hook):
    rc, data, _ = run_hook(HOOK, bash("rm -rf build"), extra_env={"GUARDRAILS_DISABLE": "no_destructive_rm"})
    assert data is None


def test_other_tools_ignored(run_hook):
    rc, data, _ = run_hook(HOOK, {"tool_name": "Write", "tool_input": {"file_path": "a", "content": "rm -rf /"}})
    assert data is None


def test_garbage_stdin_fails_open(run_hook, env):
    import subprocess, sys
    from conftest import HOOKS
    proc = subprocess.run([sys.executable, str(HOOKS / HOOK)], input="not json", capture_output=True, text=True, env=env)
    assert proc.returncode == 0 and proc.stdout.strip() == ""

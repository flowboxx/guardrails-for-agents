from conftest import decision, reason

HOOK = "protect_files.py"


def write(path, content="x"):
    return {"tool_name": "Write", "tool_input": {"file_path": path, "content": content}}


def edit(path):
    return {"tool_name": "Edit", "tool_input": {"file_path": path, "old_string": "a", "new_string": "b"}}


def bash(cmd):
    return {"tool_name": "Bash", "tool_input": {"command": cmd}}


def test_write_existing_protected_file_denied(run_hook, tmp_path):
    f = tmp_path / "project" / "CLAUDE.md"
    f.write_text("rules")
    rc, data, _ = run_hook(HOOK, write(str(f)))
    assert decision(data) == "deny"
    assert "Edit" in reason(data)


def test_edit_protected_file_allowed(run_hook, tmp_path):
    f = tmp_path / "project" / "CLAUDE.md"
    f.write_text("rules")
    rc, data, _ = run_hook(HOOK, edit(str(f)))
    assert data is None


def test_write_creates_new_protected_file_allowed(run_hook, tmp_path):
    rc, data, _ = run_hook(HOOK, write(str(tmp_path / "project" / "MEMORY.md")))
    assert data is None


def test_allow_create_false(run_hook, tmp_path):
    cfg = {"protect_files": {"allow_create": False}}
    rc, data, _ = run_hook(HOOK, write(str(tmp_path / "project" / "MEMORY.md")), config=cfg)
    assert decision(data) == "deny"


def test_policy_none_blocks_edit_too(run_hook, tmp_path):
    f = tmp_path / "project" / ".env"
    f.write_text("A=1")
    rc, data, _ = run_hook(HOOK, edit(str(f)))
    assert decision(data) == "deny"
    rc, data, _ = run_hook(HOOK, write(str(tmp_path / "project" / ".env.local")))
    assert decision(data) == "deny"  # policy none: not even creation


def test_unprotected_file_passes(run_hook, tmp_path):
    f = tmp_path / "project" / "notes.md"
    f.write_text("x")
    rc, data, _ = run_hook(HOOK, write(str(f)))
    assert data is None


def test_custom_glob_with_directory(run_hook, tmp_path):
    cfg = {"protect_files": {"protected": [{"glob": "**/memory/INDEX.md", "allow": "edit"}]}}
    f = tmp_path / "project" / "memory" / "INDEX.md"
    f.parent.mkdir()
    f.write_text("x")
    rc, data, _ = run_hook(HOOK, write(str(f)), config=cfg)
    assert decision(data) == "deny"
    g = tmp_path / "project" / "CLAUDE.md"
    g.write_text("x")
    rc, data, _ = run_hook(HOOK, write(str(g)), config=cfg)
    assert data is None  # default list replaced by the custom one


def test_bash_redirect_truncation_denied(run_hook):
    rc, data, _ = run_hook(HOOK, bash("echo new > CLAUDE.md"))
    assert decision(data) == "deny"
    rc, data, _ = run_hook(HOOK, bash("echo more >> CLAUDE.md"))
    assert data is None  # append is an edit


def test_bash_cp_mv_rm_on_protected(run_hook):
    assert decision(run_hook(HOOK, bash("cp draft.md CLAUDE.md"))[1]) == "deny"
    assert decision(run_hook(HOOK, bash("mv x.json .claude/settings.json"))[1]) == "deny"
    assert decision(run_hook(HOOK, bash("rm .env"))[1]) == "deny"
    assert run_hook(HOOK, bash("cat CLAUDE.md | head"))[1] is None


def test_watch_bash_off(run_hook):
    rc, data, _ = run_hook(HOOK, bash("echo new > CLAUDE.md"), config={"protect_files": {"watch_bash": False}})
    assert data is None

from conftest import decision, reason

HOOK = "ask_before_sudo.py"


def bash(cmd):
    return {"tool_name": "Bash", "tool_input": {"command": cmd}}


def test_sudo_asks(run_hook):
    rc, data, _ = run_hook(HOOK, bash("sudo systemctl restart nginx"))
    assert decision(data) == "ask"
    assert "ask-before-sudo" in reason(data)


def test_sudo_non_interactive_passes(run_hook):
    rc, data, _ = run_hook(HOOK, bash("sudo -n systemctl status nginx"))
    assert data is None


def test_non_interactive_can_be_disallowed(run_hook):
    cfg = {"ask_before_sudo": {"allow_non_interactive": False}}
    rc, data, _ = run_hook(HOOK, bash("sudo -n ls"), config=cfg)
    assert decision(data) == "ask"


def test_allowed_regex(run_hook):
    cfg = {"ask_before_sudo": {"allowed": [r"^systemctl status"]}}
    rc, data, _ = run_hook(HOOK, bash("sudo systemctl status nginx"), config=cfg)
    assert data is None
    rc, data, _ = run_hook(HOOK, bash("sudo systemctl restart nginx"), config=cfg)
    assert decision(data) == "ask"


def test_sudo_inside_ssh_one_liner(run_hook):
    rc, data, _ = run_hook(HOOK, bash('ssh host "sudo tar czf /tmp/x.tgz /etc"'))
    assert decision(data) == "ask"
    assert "ssh" in reason(data)


def test_sudo_n_inside_ssh_passes(run_hook):
    rc, data, _ = run_hook(HOOK, bash('ssh host "sudo -n systemctl status app"'))
    assert data is None


def test_sudo_after_pipe_or_and(run_hook):
    rc, data, _ = run_hook(HOOK, bash("echo x && sudo apt-get install -y curl"))
    assert decision(data) == "ask"


def test_word_sudo_in_text_does_not_trigger(run_hook):
    rc, data, _ = run_hook(HOOK, bash("grep -r 'sudo' docs/ ; echo 'use sudo carefully'"))
    assert data is None


def test_mode_deny(run_hook):
    rc, data, _ = run_hook(HOOK, bash("doas reboot"), config={"ask_before_sudo": {"mode": "deny"}})
    assert decision(data) == "deny"

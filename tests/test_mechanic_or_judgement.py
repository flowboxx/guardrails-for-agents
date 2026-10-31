from conftest import decision, reason

HOOK = "mechanic_or_judgement.py"


def agent(prompt, subagent_type="general-purpose"):
    return {"tool_name": "Agent", "tool_input": {"prompt": prompt, "subagent_type": subagent_type, "description": "task"}}


def test_wait_until_green_denied(run_hook):
    rc, data, _ = run_hook(HOOK, agent("Start the pipeline and wait until it is green, then report."))
    assert decision(data) == "deny"
    assert "mechanic-or-judgement" in reason(data)


def test_polling_denied(run_hook):
    rc, data, _ = run_hook(HOOK, agent("Keep polling the deployment status every minute."))
    assert decision(data) == "deny"


def test_negated_wait_passes(run_hook):
    rc, data, _ = run_hook(HOOK, agent("Kick off the build. Do not wait for it; come back immediately and review the diff."))
    assert data is None


def test_exempt_subagent_type(run_hook):
    cfg = {"mechanic_or_judgement": {"exempt_subagent_types": ["ci-watcher"]}}
    rc, data, _ = run_hook(HOOK, agent("Wait until the job finishes.", "ci-watcher"), config=cfg)
    assert data is None


def test_run_the_tests_warns(run_hook):
    rc, data, _ = run_hook(HOOK, agent("Run the test suite and tell me the numbers."))
    assert decision(data) == "warn"
    assert "scripted task" in reason(data)


def test_hint_included(run_hook):
    cfg = {"mechanic_or_judgement": {"hints": {"run the test": "pytest -q"}}}
    rc, data, _ = run_hook(HOOK, agent("Run the tests."), config=cfg)
    assert "pytest -q" in reason(data)


def test_judgement_marker_suppresses_mechanic_warning(run_hook):
    rc, data, _ = run_hook(HOOK, agent("Run the tests and investigate why the three failures happen."))
    assert data is None


def test_pure_judgement_passes(run_hook):
    rc, data, _ = run_hook(HOOK, agent("Review the pull request for security issues and recommend changes."))
    assert data is None


def test_wait_wins_over_judgement(run_hook):
    rc, data, _ = run_hook(HOOK, agent("Review the PR, then wait until CI is done and summarise."))
    assert decision(data) == "deny"


def test_german_patterns(run_hook):
    rc, data, _ = run_hook(HOOK, agent("Fahr die Kette und warte bis sie fertig ist."))
    assert decision(data) == "deny"
    rc, data, _ = run_hook(HOOK, agent("Starte die Suite und melde die Zahl."))
    assert decision(data) == "warn"


def test_modes_configurable(run_hook):
    cfg = {"mechanic_or_judgement": {"wait_mode": "warn", "mechanic_mode": "off"}}
    rc, data, _ = run_hook(HOOK, agent("Wait for the build."), config=cfg)
    assert decision(data) == "warn"
    rc, data, _ = run_hook(HOOK, agent("Run the linter."), config=cfg)
    assert data is None


def test_non_agent_tool_ignored(run_hook):
    rc, data, _ = run_hook(HOOK, {"tool_name": "Bash", "tool_input": {"command": "sleep 60"}})
    assert data is None

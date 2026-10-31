import datetime as dt
import json
from pathlib import Path

from conftest import decision, reason

HOOK = "time_check.py"


def write(path, content):
    return {"tool_name": "Write", "tool_input": {"file_path": path, "content": content}}


def now_str(delta_minutes=0):
    return (dt.datetime.now() + dt.timedelta(minutes=delta_minutes)).strftime("%Y-%m-%d %H:%M")


def test_inject_on_prompt_outputs_time(run_hook):
    rc, data, _ = run_hook(HOOK, {"hook_event_name": "UserPromptSubmit", "prompt": "hi"}, args=("inject",))
    ctx = data["hookSpecificOutput"]["additionalContext"]
    assert data["hookSpecificOutput"]["hookEventName"] == "UserPromptSubmit"
    assert "Current local time" in ctx and dt.datetime.now().strftime("%Y-%m-%d") in ctx


def test_inject_respects_config(run_hook):
    rc, data, _ = run_hook(HOOK, {"hook_event_name": "UserPromptSubmit"}, args=("inject",),
                           config={"time_check": {"inject_on_prompt": False}})
    assert data is None


def test_inject_german(run_hook):
    rc, data, _ = run_hook(HOOK, {"hook_event_name": "SessionStart"}, args=("inject",), config={"lang": "de"})
    assert "Ortszeit" in data["hookSpecificOutput"]["additionalContext"]


def test_no_timestamp_no_output(run_hook):
    rc, data, _ = run_hook(HOOK, write("notes.md", "nothing dated here, version 2.1.3"), args=("check",))
    assert data is None


def test_timestamp_without_clock_reading_warns(run_hook):
    rc, data, _ = run_hook(HOOK, write("log.md", "Entry %s: did things" % now_str()), args=("check",))
    assert decision(data) == "warn"
    assert "no clock command" in reason(data)


def test_record_then_check_is_silent(run_hook):
    run_hook(HOOK, {"tool_name": "Bash", "tool_input": {"command": "TZ=UTC date"}, "hook_event_name": "PostToolUse"}, args=("record",))
    rc, data, _ = run_hook(HOOK, write("log.md", "Entry %s" % now_str()), args=("check",))
    assert data is None


def test_inject_counts_as_clock_reading(run_hook):
    run_hook(HOOK, {"hook_event_name": "UserPromptSubmit"}, args=("inject",))
    rc, data, _ = run_hook(HOOK, write("log.md", "Entry %s" % now_str(-5)), args=("check",))
    assert data is None


def test_future_timestamp_warns_even_after_clock(run_hook):
    run_hook(HOOK, {"hook_event_name": "UserPromptSubmit"}, args=("inject",))
    rc, data, _ = run_hook(HOOK, write("log.md", "Entry %s" % now_str(120)), args=("check",))
    assert decision(data) == "warn" and "future" in reason(data)


def test_german_date_format_detected(run_hook):
    stamp = (dt.datetime.now() + dt.timedelta(hours=3)).strftime("%d.%m.%Y %H:%M")
    run_hook(HOOK, {"hook_event_name": "UserPromptSubmit"}, args=("inject",))
    rc, data, _ = run_hook(HOOK, write("log.md", "Stand %s" % stamp), args=("check",))
    assert decision(data) == "warn"


def test_code_files_skipped_by_default(run_hook):
    rc, data, _ = run_hook(HOOK, write("app.py", "CREATED = '%s'" % now_str(500)), args=("check",))
    assert data is None


def test_mode_deny(run_hook):
    rc, data, _ = run_hook(HOOK, write("log.md", "Entry %s" % now_str(500)), args=("check",),
                           config={"time_check": {"mode": "deny"}})
    assert decision(data) == "deny"


def test_stale_reading_older_than_max_age(run_hook, env):
    state = Path(env["GUARDRAILS_STATE_DIR"])
    state.mkdir(parents=True, exist_ok=True)
    import time
    (state / "time_check.json").write_text(json.dumps({"test-session": time.time() - 3600}))
    rc, data, _ = run_hook(HOOK, write("log.md", "Entry %s" % now_str()), args=("check",))
    assert decision(data) == "warn" and "last reading" in reason(data)

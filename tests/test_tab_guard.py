from conftest import decision, reason

HOOK = "tab_guard.py"


def tool(name, inp, response=None, event="PreToolUse"):
    p = {"tool_name": name, "tool_input": inp, "hook_event_name": event}
    if response is not None:
        p["tool_response"] = response
    return p


def test_close_unknown_page_asks(run_hook):
    rc, data, _ = run_hook(HOOK, tool("mcp__chrome-devtools__close_page", {"pageId": "7"}), args=("close",))
    assert decision(data) == "ask"
    assert "tab-guard" in reason(data) and "7" in reason(data)


def test_close_page_opened_this_session_passes(run_hook):
    run_hook(HOOK, tool("mcp__chrome-devtools__new_page", {"url": "https://example.com"},
                        response='Opened page: {"pageId": "42"}', event="PostToolUse"), args=("track",))
    rc, data, _ = run_hook(HOOK, tool("mcp__chrome-devtools__close_page", {"pageId": "42"}), args=("close",))
    assert data is None
    rc, data, _ = run_hook(HOOK, tool("mcp__chrome-devtools__close_page", {"pageId": "43"}), args=("close",))
    assert decision(data) == "ask"


def test_playwright_tabs_action_close(run_hook):
    rc, data, _ = run_hook(HOOK, tool("mcp__playwright__browser_tabs", {"action": "close", "index": 2}), args=("close",))
    assert decision(data) == "ask"
    rc, data, _ = run_hook(HOOK, tool("mcp__playwright__browser_tabs", {"action": "list"}), args=("close",))
    assert data is None


def test_playwright_tabs_action_new_is_tracked(run_hook):
    run_hook(HOOK, tool("mcp__playwright__browser_tabs", {"action": "new"},
                        response=[{"type": "text", "text": "tab index: 3 opened"}], event="PostToolUse"), args=("track",))
    run_hook(HOOK, tool("mcp__playwright__browser_tabs", {"action": "new", "index": 3}, event="PostToolUse"), args=("track",))
    rc, data, _ = run_hook(HOOK, tool("mcp__playwright__browser_tabs", {"action": "close", "index": 3}), args=("close",))
    assert data is None


def test_unrelated_mcp_tool_ignored(run_hook):
    rc, data, _ = run_hook(HOOK, tool("mcp__chrome-devtools__take_screenshot", {}), args=("close",))
    assert data is None


def test_tracking_off(run_hook):
    cfg = {"tab_guard": {"allow_if_opened_this_session": False}}
    run_hook(HOOK, tool("mcp__x__new_page", {"url": "u"}, response='{"pageId": "1"}', event="PostToolUse"), args=("track",), config=cfg)
    rc, data, _ = run_hook(HOOK, tool("mcp__x__close_page", {"pageId": "1"}), args=("close",), config=cfg)
    assert decision(data) == "ask"


def test_agent_prompt_close_all_tabs_warns(run_hook):
    p = {"tool_name": "Agent", "tool_input": {"prompt": "When you are done, close all the browser tabs."}}
    rc, data, _ = run_hook(HOOK, p, args=("prompt",))
    assert decision(data) == "warn" and "only the tabs you opened" in reason(data)


def test_agent_prompt_german(run_hook):
    p = {"tool_name": "Agent", "tool_input": {"prompt": "Danach bitte alle Reiter schliessen."}}
    rc, data, _ = run_hook(HOOK, p, args=("prompt",))
    assert decision(data) == "warn"


def test_agent_prompt_self_limited_or_negated_passes(run_hook):
    for text in ("Close the tabs you opened yourself when finished.",
                 "Never close tabs; leave the browser as it is.",
                 "Nur selbst geoeffnete Reiter schliessen.",
                 "Open the page and take a screenshot."):
        rc, data, _ = run_hook(HOOK, {"tool_name": "Agent", "tool_input": {"prompt": text}}, args=("prompt",))
        assert data is None, text


def test_agent_prompt_mode_deny(run_hook):
    cfg = {"tab_guard": {"agent_prompt_mode": "deny"}}
    p = {"tool_name": "Agent", "tool_input": {"prompt": "close every tab except the first"}}
    rc, data, _ = run_hook(HOOK, p, args=("prompt",), config=cfg)
    assert decision(data) == "deny"

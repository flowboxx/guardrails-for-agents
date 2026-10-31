#!/usr/bin/env python3
"""tab-guard (three entry points, chosen by argv[1])

  close    PreToolUse  mcp__*   : a browser-automation "close tab/page" call is turned into a
                                  permission prompt unless the tab was opened in this session
  track    PostToolUse mcp__*   : remembers tab/page ids that this session opened itself
  prompt   PreToolUse  Agent    : warns when a sub-agent is told to close "all tabs" without the
                                  restriction "only the ones you opened"

Why: a browser the user shares with the agent may hold tabs with a one-time
code, an unsaved form or a login the user left open on purpose. "Clean up the
tabs" then destroys something that cannot be reopened. The safe rule is simple:
close only what you opened.

Works with any MCP browser server (Chrome DevTools, Playwright, ...); the tool
names are regexes in the config. Id tracking is best-effort: it reads common id
fields from the tool input and the tool result.

Config key: "tab_guard"
"""
import json
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _lib as lib  # noqa: E402

HOOK = "tab_guard"
DEFAULTS = {
    "enabled": True,
    "mode": "ask",
    "close_tools": r"(close_page|closePage|browser_close|close_tab|closeTab|tabs_close|close_window)",
    "open_tools": r"(new_page|newPage|new_tab|newTab|open_tab|create_page|create_tab)",
    "action_tools": r"(browser_tabs|tabs)$",     # tools with an "action" argument
    "close_actions": ["close"],
    "open_actions": ["new", "create", "open"],
    "id_fields": ["pageId", "page_id", "tabId", "tab_id", "targetId", "target_id", "index", "id"],
    "allow_if_opened_this_session": True,
    "agent_prompt_check": True,
    "agent_prompt_mode": "warn",
}
MESSAGES = {
    "en": {
        "close": "Closing tab/page {ident} via {tool}: this session did not open it. A tab the user left "
                 "open may hold a one-time code, unsaved work or a login. Close only tabs you opened yourself.",
        "prompt": "This agent prompt asks to close tabs/pages without limiting it to the agent's own. "
                  "Add: close only the tabs you opened yourself (keep a list of their ids); never 'all' or "
                  "'all except'; tabs the user left open stay open; save one-time codes before closing anything.",
    },
    "de": {
        "close": "Reiter/Seite {ident} ueber {tool} schliessen: diese Sitzung hat ihn nicht geoeffnet. Ein vom "
                 "Nutzer offen gelassener Reiter kann einen Einmal-Code, ungesicherte Arbeit oder einen Login "
                 "enthalten. Nur selbst geoeffnete Reiter schliessen.",
        "prompt": "Dieser Agenten-Auftrag verlangt Reiter zu schliessen, ohne es auf die eigenen zu begrenzen. "
                  "Ergaenzen: nur selbst geoeffnete Reiter schliessen (eigene Liste der IDs); nie 'alle' oder "
                  "'alle ausser'; vom Nutzer offen gelassene Reiter bleiben offen; Einmal-Codes vorher sichern.",
    },
}
ID_IN_TEXT = re.compile(r"[\"']?(pageId|page_id|tabId|tab_id|targetId|target_id|id)[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9_-]{1,64})")
EN_CLOSE = re.compile(r"\b(close|shut|kill|clean\s*up|tidy)\w*\b.{0,40}\b(all|every|remaining|other|rest of|any)\b.{0,25}\b(tabs?|pages?|windows?|browser)\b"
                      r"|\b(all|every)\b.{0,25}\b(tabs?|pages?|windows?)\b.{0,40}\b(close|shut)\w*", re.I | re.S)
DE_CLOSE = re.compile(r"\b(alle|s[aä]mtliche|saemtliche|[uü]brige|restliche)\w*\b.{0,30}\b(reiter|tabs?|fenster|seiten)\b.{0,40}schlie(ß|ss)"
                      r"|schlie(ß|ss)\w*.{0,40}\b(alle|s[aä]mtliche|saemtliche|[uü]brige)\w*\b.{0,25}\b(reiter|tabs?|fenster)\b"
                      r"|\b(reiter|tabs?)\b.{0,30}\b(au(ß|ss)er|ausser)\b", re.I | re.S)
NEGATED = re.compile(r"\b(never|do not|don't|dont|nie|niemals|nicht|kein\w*)\b.{0,30}\b(clos|shut|schlie)", re.I | re.S)
SELF_LIMITED = re.compile(r"(you (have )?opened|opened (by )?yourself|your own tabs|tabs you open|only (the )?tabs? (that )?you"
                          r"|selbst ge[oö]ffnet|eigene\w* (reiter|tabs)|die du (selbst )?(ge[oö]ffnet|[oö]ffnest))", re.I)


def ids_from(obj, fields):
    out = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in fields and isinstance(v, (str, int)):
                out.add(str(v))
            else:
                out |= ids_from(v, fields)
    elif isinstance(obj, list):
        for v in obj:
            out |= ids_from(v, fields)
    elif isinstance(obj, str):
        for m in ID_IN_TEXT.finditer(obj):
            out.add(m.group(2))
    return out


def classify(tool_name, ti, hcfg):
    """'close' | 'open' | None"""
    action = str(ti.get("action", "")).lower()
    if re.search(hcfg["close_tools"], tool_name):
        return "close"
    if re.search(hcfg["open_tools"], tool_name):
        return "open"
    if re.search(hcfg["action_tools"], tool_name):
        if action in [a.lower() for a in hcfg.get("close_actions") or []]:
            return "close"
        if action in [a.lower() for a in hcfg.get("open_actions") or []]:
            return "open"
    return None


def session_key(payload):
    return str(payload.get("session_id") or "default")


def do_track(payload, hcfg):
    tool = str(payload.get("tool_name", ""))
    ti = lib.tool_input(payload)
    if classify(tool, ti, hcfg) != "open":
        return 0
    found = ids_from(ti, hcfg["id_fields"]) | ids_from(payload.get("tool_response"), hcfg["id_fields"])
    if not found:
        return 0
    state = lib.load_state(HOOK)
    entry = state.get(session_key(payload)) or {"ids": [], "ts": 0}
    entry["ids"] = sorted(set(entry.get("ids", [])) | found)[:500]
    entry["ts"] = time.time()
    state[session_key(payload)] = entry
    cutoff = time.time() - 3 * 86400
    state = {k: v for k, v in state.items() if isinstance(v, dict) and v.get("ts", 0) > cutoff}
    lib.save_state(HOOK, state)
    return 0


def do_close(payload, cfg, hcfg):
    tool = str(payload.get("tool_name", ""))
    ti = lib.tool_input(payload)
    if classify(tool, ti, hcfg) != "close":
        return 0
    wanted = ids_from(ti, hcfg["id_fields"])
    if hcfg.get("allow_if_opened_this_session", True) and wanted:
        known = set((lib.load_state(HOOK).get(session_key(payload)) or {}).get("ids", []))
        if wanted <= known:
            return 0
    ident = ",".join(sorted(wanted)) or "(current)"
    reason = "[tab-guard] " + lib.text(cfg, MESSAGES, "close", ident=ident, tool=tool)
    return lib.finish(cfg, HOOK, hcfg.get("mode", "ask"), reason)


def prompt_is_risky(prompt):
    if not prompt or SELF_LIMITED.search(prompt):
        return False
    for rx in (EN_CLOSE, DE_CLOSE):
        for m in rx.finditer(prompt):
            window = prompt[max(0, m.start() - 40):m.end()]
            if not NEGATED.search(window):
                return True
    return False


def do_prompt(payload, cfg, hcfg):
    if payload.get("tool_name") not in ("Agent", "Task") or not hcfg.get("agent_prompt_check", True):
        return 0
    ti = lib.tool_input(payload)
    prompt = " ".join(str(ti.get(k, "")) for k in ("prompt", "description"))
    if not prompt_is_risky(prompt):
        return 0
    reason = "[tab-guard] " + lib.text(cfg, MESSAGES, "prompt")
    return lib.finish(cfg, HOOK, hcfg.get("agent_prompt_mode", "warn"), reason)


def main():
    action = sys.argv[1] if len(sys.argv) > 1 else "close"
    payload = lib.read_payload()
    cfg = lib.load_config(payload)
    hcfg = lib.hook_config(cfg, HOOK, DEFAULTS)
    if lib.is_disabled(cfg, HOOK, hcfg):
        return 0
    if action == "track":
        return do_track(payload, hcfg)
    if action == "prompt":
        return do_prompt(payload, cfg, hcfg)
    return do_close(payload, cfg, hcfg)


if __name__ == "__main__":
    lib.run(main)

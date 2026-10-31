#!/usr/bin/env python3
"""time-check (three entry points, chosen by argv[1])

  inject   UserPromptSubmit / SessionStart : adds the current local time as context
  record   PostToolUse Bash                 : remembers that a clock command (`date`) ran
  check    PreToolUse Write | Edit          : finds timestamps in the text being written and
                                              warns when no clock was consulted recently or
                                              when a timestamp lies in the future

Why: language models do not have a clock. Left alone they extrapolate the time
from the last value they saw and write log entries, changelogs and reports with
times that drift by hours. The cure is cheap: tell the model the time on every
prompt and complain when it writes a timestamp without having looked.

Config key: "time_check"
"""
import datetime as dt
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _lib as lib  # noqa: E402

HOOK = "time_check"
DEFAULTS = {
    "enabled": True,
    "mode": "warn",
    "inject_on_prompt": True,
    "inject_on_session_start": True,
    "inject_counts_as_check": True,
    "max_age_minutes": 30,            # a clock reading older than this counts as "not checked"
    "future_tolerance_minutes": 20,   # timestamps further ahead than this are flagged
    "clock_commands": ["date", "timedatectl", "hwclock"],
    "only_extensions": [".md", ".txt", ".rst", ".adoc", ".log", ".csv", ".json", ".yaml", ".yml"],
    "timezone": None,                 # IANA name, e.g. "Europe/Berlin"; default: system local time
}
MESSAGES = {
    "en": {
        "inject": "Current local time: {now}. Use this (or run `date`) for any timestamp you write; never extrapolate.",
        "stale": "The text contains {n} timestamp(s) but no clock command ran in the last {age} min "
                 "(last reading: {last}). Run `date` before writing times.",
        "future": "Timestamp {stamp} lies {minutes} min in the future (now: {now}). Check the clock.",
    },
    "de": {
        "inject": "Aktuelle Ortszeit: {now}. Fuer jeden Zeitstempel diese Zeit (oder `date`) nutzen, nie fortschreiben.",
        "stale": "Der Text enthaelt {n} Zeitstempel, aber in den letzten {age} Min lief kein Uhr-Befehl "
                 "(letzte Lesung: {last}). Vor dem Schreiben `date` ausfuehren.",
        "future": "Zeitstempel {stamp} liegt {minutes} Min in der Zukunft (jetzt: {now}). Uhr pruefen.",
    },
}
STAMPS = [
    re.compile(r"\b(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})"),                  # ISO
    re.compile(r"\b(\d{1,2})\.(\d{1,2})\.(\d{4}),?\s+(\d{1,2}):(\d{2})\b"),        # DD.MM.YYYY HH:MM
    re.compile(r"\b(\d{1,2})/(\d{1,2})/(\d{4}),?\s+(\d{1,2}):(\d{2})\b"),         # MM/DD/YYYY HH:MM
]


def tzinfo(hcfg):
    name = hcfg.get("timezone")
    if name:
        try:
            from zoneinfo import ZoneInfo
            return ZoneInfo(name)
        except Exception:
            pass
    return dt.datetime.now().astimezone().tzinfo


def now(hcfg):
    return dt.datetime.now(tzinfo(hcfg))


def fmt(d):
    return d.strftime("%Y-%m-%d %H:%M %Z")


def find_stamps(txt):
    out = []
    for i, rx in enumerate(STAMPS):
        for m in rx.finditer(txt):
            g = [int(x) for x in m.groups()]
            try:
                if i == 0:
                    d = dt.datetime(g[0], g[1], g[2], g[3], g[4])
                elif i == 1:
                    d = dt.datetime(g[2], g[1], g[0], g[3], g[4])
                else:
                    d = dt.datetime(g[2], g[0], g[1], g[3], g[4])
            except ValueError:
                continue
            out.append((m.group(0), d))
    return out


def ran_clock(command, hcfg):
    names = set(hcfg.get("clock_commands") or [])
    for argv in lib.split_commands(command):
        argv = lib.strip_wrappers(argv)
        if lib.command_name(argv) in names:
            return True
    return False


def session_key(payload):
    return str(payload.get("session_id") or "default")


def record(payload):
    state = lib.load_state(HOOK)
    state[session_key(payload)] = time.time()
    # keep the state file small
    cutoff = time.time() - 7 * 86400
    state = {k: v for k, v in state.items() if isinstance(v, (int, float)) and v > cutoff}
    lib.save_state(HOOK, state)


def do_inject(payload, cfg, hcfg):
    event = payload.get("hook_event_name") or "UserPromptSubmit"
    if event == "SessionStart" and not hcfg.get("inject_on_session_start", True):
        return 0
    if event != "SessionStart" and not hcfg.get("inject_on_prompt", True):
        return 0
    if hcfg.get("inject_counts_as_check", True):
        record(payload)
    lib.emit(event, context=lib.text(cfg, MESSAGES, "inject", now=fmt(now(hcfg))))
    return 0


def do_record(payload, hcfg):
    if payload.get("tool_name") != "Bash":
        return 0
    if ran_clock(str(lib.tool_input(payload).get("command", "")), hcfg):
        record(payload)
    return 0


def written_text(payload):
    ti = lib.tool_input(payload)
    tool = payload.get("tool_name")
    if tool == "Write":
        return str(ti.get("content", ""))
    if tool == "Edit":
        return str(ti.get("new_string", ""))
    if tool == "MultiEdit":
        return "\n".join(str((e or {}).get("new_string", "")) for e in ti.get("edits") or [])
    return ""


def do_check(payload, cfg, hcfg):
    path = str(lib.tool_input(payload).get("file_path", ""))
    exts = hcfg.get("only_extensions") or []
    if exts and Path(path).suffix.lower() not in [e.lower() for e in exts]:
        return 0
    stamps = find_stamps(written_text(payload))
    if not stamps:
        return 0
    current = now(hcfg)
    problems = []
    tol = int(hcfg.get("future_tolerance_minutes", 20))
    for raw, d in stamps:
        ahead = (d.replace(tzinfo=current.tzinfo) - current).total_seconds() / 60
        if ahead > tol:
            problems.append(lib.text(cfg, MESSAGES, "future", stamp=raw, minutes=int(ahead), now=fmt(current)))
            break
    last = lib.load_state(HOOK).get(session_key(payload))
    age = int(hcfg.get("max_age_minutes", 30))
    if not last or time.time() - float(last) > age * 60:
        last_txt = "never" if not last else fmt(dt.datetime.fromtimestamp(float(last), current.tzinfo))
        problems.append(lib.text(cfg, MESSAGES, "stale", n=len(stamps), age=age, last=last_txt))
    if not problems:
        return 0
    return lib.finish(cfg, HOOK, hcfg.get("mode", "warn"), "[time-check] " + " ".join(problems))


def main():
    action = sys.argv[1] if len(sys.argv) > 1 else "check"
    payload = lib.read_payload()
    cfg = lib.load_config(payload)
    hcfg = lib.hook_config(cfg, HOOK, DEFAULTS)
    if lib.is_disabled(cfg, HOOK, hcfg):
        return 0
    if action == "inject":
        return do_inject(payload, cfg, hcfg)
    if action == "record":
        return do_record(payload, hcfg)
    return do_check(payload, cfg, hcfg)


if __name__ == "__main__":
    lib.run(main)

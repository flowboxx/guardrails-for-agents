#!/usr/bin/env python3
"""mechanic-or-judgement (PreToolUse, Agent)

Asks one question before every sub-agent is spawned: is this judgement or
mechanics? Two checks on the agent prompt:

  1. waiting   - "wait until the build is green", "poll the pipeline", "keep checking":
                 an agent that blocks and polls burns tokens on every poll turn.
                 Default: deny. Run the command yourself, or let a script wait.
  2. mechanics - "run the tests", "deploy to staging", "bump the version", "format
                 the code": tasks with a deterministic command do not need a model.
                 Default: warn, with a hint to run the command directly. Suppressed
                 when the prompt also contains a judgement marker (review, decide,
                 investigate, why, ...).

Config key: "mechanic_or_judgement"
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _lib as lib  # noqa: E402

HOOK = "mechanic_or_judgement"
DEFAULTS = {
    "enabled": True,
    "wait_mode": "deny",
    "mechanic_mode": "warn",
    "exempt_subagent_types": [],       # e.g. ["ci-watcher"] if one agent type is meant to wait
    "wait_patterns": [
        r"\bwait(s|ing)? (for|until|till)\b",
        r"\buntil (it|they|the \w+|this|that|everything)( is| are| has| have| gets| goes)? ?(done|finished|complete[sd]?|green|pass(es|ed)?|succeed\w*|ready)",
        r"\bpoll(s|ing|ed)?\b",
        r"\bkeep (checking|polling|watching|monitoring|re-?running)\b",
        r"\b(watch|monitor|follow|babysit)\b.{0,40}\b(until|till|while)\b",
        r"\bblock(s|ing)? until\b",
        r"\bsleep \d+",
        r"\bwarte\w* (bis|auf|solange)\b",
        r"\bbis\b.{0,40}\b(fertig|gr[uü]n|gruen|durch|erledigt|abgeschlossen)\b",
        r"\babwarten\b",
    ],
    "mechanic_patterns": [
        r"\brun (the |all |our )?(unit |integration |e2e |full |whole )?(tests?|test ?suite|build|lint(er)?|formatter|type ?check(er)?|ci)\b",
        r"\b(deploy|release|publish|ship)\b.{0,20}\b(to|the|it|now)\b",
        r"\bbump (the )?(version|release)\b",
        r"\bformat (the |all )?(code|files|sources)\b",
        r"\b(merge|rebase|push|tag)\b.{0,40}\b(and|then)\b.{0,30}\b(bump|tag|push|deploy|release|merge)\b",
        r"\b(fahr|fahre|starte|f[uü]hr\w*|fuehr\w*) .{0,25}\b(tests?|suite|build|deploy|pipeline|kette)\b",
        r"\bversion (hoch|bump|erh[oö]h)",
        r"\b(deploy|ausrollen|ver[oö]ffentlich\w*)\b",
    ],
    "judgement_markers": [
        r"\b(review|assess|investigat|diagnos|decid|judg|evaluat|analy[sz]|design|debug|explain|why|root cause|compare|recommend|audit|refactor|implement|fix|write|create|add|change)\w*",
        r"\b(pr[uü]f|bewert|untersuch|entscheid|analys|begr[uü]nd|warum|ursache|vergleich|empfehl|baue|bau|schreib|erg[aä]nz|[aä]nder|repar|behebe)\w*",
    ],
    "negations": [
        r"\b(do not|don't|dont|never|without|no need to|nicht|nie|niemals|ohne zu|kein)\b.{0,20}\b(wait|poll|watch|monitor|warte|pollen|abwarten)",
    ],
    "hints": {},                       # {"run the tests": "pytest -q"} shown with the warning
}
MESSAGES = {
    "en": {
        "wait": "This agent prompt asks the sub-agent to wait/poll ({match}). A model that polls burns a full "
                "context window per poll turn. Run the command yourself, or let a script wait and report back; "
                "if a dedicated waiter agent exists, add it to exempt_subagent_types.",
        "mechanic": "This looks like a scripted task ({match}). A deterministic command does the same for zero "
                    "tokens: run it directly{hint}. Spawn an agent only for judgement (review, investigate, decide).",
    },
    "de": {
        "wait": "Dieser Agenten-Auftrag verlangt Warten/Pollen ({match}). Ein Modell, das pollt, verbrennt je "
                "Poll-Runde ein ganzes Kontextfenster. Befehl selbst ausfuehren oder ein Skript warten lassen; "
                "gibt es einen eigenen Warte-Agenten, in exempt_subagent_types eintragen.",
        "mechanic": "Das sieht nach Mechanik aus ({match}). Ein deterministischer Befehl erledigt das fuer null "
                    "Tokens: direkt ausfuehren{hint}. Agent nur fuer Urteil (Review, Untersuchung, Entscheidung).",
    },
}


def _compile(patterns):
    out = []
    for p in patterns or []:
        try:
            out.append(re.compile(p, re.I | re.S))
        except re.error:
            continue
    return out


def first_match(prompt, patterns, negations):
    for rx in _compile(patterns):
        for m in rx.finditer(prompt):
            window = prompt[max(0, m.start() - 30):m.end()]
            if any(n.search(window) for n in _compile(negations)):
                continue
            return m.group(0).strip()[:60]
    return None


def hint_for(match, hcfg):
    for key, value in (hcfg.get("hints") or {}).items():
        if key.lower() in match.lower():
            return ", e.g. `" + str(value) + "`"
    return ""


def main():
    payload = lib.read_payload()
    if payload.get("tool_name") not in ("Agent", "Task"):
        return 0
    cfg = lib.load_config(payload)
    hcfg = lib.hook_config(cfg, HOOK, DEFAULTS)
    if lib.is_disabled(cfg, HOOK, hcfg):
        return 0
    ti = lib.tool_input(payload)
    if str(ti.get("subagent_type", "")) in (hcfg.get("exempt_subagent_types") or []):
        return 0
    prompt = " ".join(str(ti.get(k, "")) for k in ("description", "prompt"))
    if not prompt.strip():
        return 0
    negations = hcfg.get("negations") or []
    wait = first_match(prompt, hcfg.get("wait_patterns"), negations)
    if wait:
        reason = "[mechanic-or-judgement] " + lib.text(cfg, MESSAGES, "wait", match=wait)
        return lib.finish(cfg, HOOK, hcfg.get("wait_mode", "deny"), reason)
    mech = first_match(prompt, hcfg.get("mechanic_patterns"), [])
    if mech and not first_match(prompt, hcfg.get("judgement_markers"), []):
        reason = "[mechanic-or-judgement] " + lib.text(cfg, MESSAGES, "mechanic", match=mech, hint=hint_for(mech, hcfg))
        return lib.finish(cfg, HOOK, hcfg.get("mechanic_mode", "warn"), reason)
    return 0


if __name__ == "__main__":
    lib.run(main)

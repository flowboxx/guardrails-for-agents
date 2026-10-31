import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
HOOKS = ROOT / "hooks"
sys.path.insert(0, str(HOOKS))


@pytest.fixture
def env(tmp_path):
    """Isolated environment: no user/project config, fresh state dir, explicit config file."""
    cfg_path = tmp_path / "guardrails.json"
    cfg_path.write_text("{}", encoding="utf-8")
    e = dict(os.environ)
    e.update({
        "HOME": str(tmp_path / "home"),
        "GUARDRAILS_CONFIG": str(cfg_path),
        "GUARDRAILS_STATE_DIR": str(tmp_path / "state"),
        "CLAUDE_PLUGIN_ROOT": str(ROOT),
        "CLAUDE_PROJECT_DIR": str(tmp_path / "project"),
    })
    e.pop("GUARDRAILS_DISABLE", None)
    e.pop("TMPDIR", None)
    (tmp_path / "home").mkdir()
    (tmp_path / "project").mkdir()
    e["_cfg_path"] = str(cfg_path)
    return e


@pytest.fixture
def run_hook(env):
    def _run(script, payload, config=None, args=(), extra_env=None):
        if config is not None:
            Path(env["_cfg_path"]).write_text(json.dumps(config), encoding="utf-8")
        e = dict(env)
        e.update(extra_env or {})
        payload = dict({"session_id": "test-session", "cwd": env["CLAUDE_PROJECT_DIR"],
                        "hook_event_name": "PreToolUse"}, **payload)
        proc = subprocess.run([sys.executable, str(HOOKS / script), *args], input=json.dumps(payload),
                              capture_output=True, text=True, env=e, timeout=30)
        out = proc.stdout.strip()
        data = json.loads(out) if out.startswith("{") else None
        return proc.returncode, data, proc.stderr
    return _run


def decision(data):
    """permissionDecision from hook JSON, 'warn' for context-only output, None for silence."""
    if not data:
        return None
    hso = data.get("hookSpecificOutput", {})
    if hso.get("permissionDecision"):
        return hso["permissionDecision"]
    if hso.get("additionalContext"):
        return "warn"
    return None


def reason(data):
    hso = (data or {}).get("hookSpecificOutput", {})
    return hso.get("permissionDecisionReason") or hso.get("additionalContext") or ""

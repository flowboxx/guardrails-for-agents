#!/usr/bin/env python3
"""Print the effective configuration (built-in defaults merged with your config files) as JSON.

    python3 scripts/print-defaults.py            # effective config
    python3 scripts/print-defaults.py --defaults # built-in defaults only
"""
import importlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "hooks"))
import _lib as lib  # noqa: E402

HOOKS = ["no_destructive_rm", "ask_before_sudo", "secret_scan", "protect_files",
         "time_check", "tab_guard", "mechanic_or_judgement"]


def main():
    defaults_only = "--defaults" in sys.argv
    cfg = {} if defaults_only else lib.load_config()
    out = {"lang": cfg.get("lang", "en"), "log_file": cfg.get("log_file")}
    for name in HOOKS:
        mod = importlib.import_module(name)
        out[name] = mod.DEFAULTS if defaults_only else lib.hook_config(cfg, name, mod.DEFAULTS)
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()

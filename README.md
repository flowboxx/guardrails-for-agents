# Guardrails for Agents

Seven small, deterministic safety hooks for [Claude Code](https://code.claude.com) and other
coding agents that speak the same hook protocol. Pure Python 3.9+, no dependencies, no network,
no model calls. Everything is configurable with one JSON file.

> Community project, **not affiliated with Anthropic**. "Claude" and "Claude Code" are trademarks
> of their respective owner; this plugin only uses the public hook interface.

## The problem

Coding agents are fast and literal. The failure modes are always the same, and they are not
model problems, they are missing guardrails:

| What happens | What it costs |
| --- | --- |
| `rm -rf build` or `rm *.log` "to clean up" | a directory you cannot get back |
| `sudo` in a tool call | a hung session on a password prompt, or a root change nobody reviewed |
| an API key pasted into a config file or a `curl` line | a rotated credential and a leaked transcript |
| `Write` on `CLAUDE.md` or a memory index from memory | everything that was not in the context window is gone |
| timestamps written without looking at the clock | log entries that drift by hours |
| "close all tabs" in a shared browser | the one tab with the one-time code you still needed |
| a sub-agent told to "wait until CI is green" | a full context window burned per poll |

Permission prompts do not fix this: people click them through. A hook that **sees the exact
tool call** and says no (or asks, or warns) does.

## Installation

From a marketplace (recommended):

```bash
claude plugin marketplace add flowboxx/guardrails-for-agents && claude plugin install guardrails-for-agents@flowboxx-plugins
```

Or load the checkout directly for one session:

```bash
claude --plugin-dir /path/to/guardrails-for-agents
```

Requirements: `python3` on `PATH` (3.9 or newer). Nothing else.

Check that it works: ask the agent to run `rm -rf /tmp/does-not-matter`. The tool call is denied
with a `[no-destructive-rm]` reason.

## Modes

Every hook has a `mode`:

| mode | effect |
| --- | --- |
| `deny` | the tool call is blocked; the agent sees the reason and can choose another way |
| `ask` | a permission prompt with the reason; you decide |
| `warn` | the call runs; the reason is added as context so the agent can self-correct |
| `off` | hook is loaded but silent |

Kill switch for an emergency: `GUARDRAILS_DISABLE=1` (all hooks) or
`GUARDRAILS_DISABLE=secret_scan,time_check` (named hooks). Per hook: `"enabled": false`.

All hooks **fail open**: an internal error never blocks legitimate work.

## Configuration

JSON, merged in this order (later wins, lists replace, objects merge):

1. `guardrails.json` in the plugin (shipped defaults)
2. `~/.claude/guardrails.json` (you)
3. `<project>/.claude/guardrails.json` (this repository)
4. the file named in `$GUARDRAILS_CONFIG`

Top-level keys: `lang` (`en` or `de`, message language), `log_file` (optional JSONL log of every
trigger, useful for measuring false alarms; `${CLAUDE_PLUGIN_DATA}` is expanded). Each hook has its
own section, named like the script without `.py`. See every key with its default:

```bash
python3 scripts/print-defaults.py --defaults
```

Example `~/.claude/guardrails.json`:

```json
{
  "lang": "en",
  "no_destructive_rm": { "allow_under": ["~/scratch", "/tmp/agent"] },
  "ask_before_sudo": { "allowed": ["^systemctl status", "^journalctl"] },
  "protect_files": { "protected": [
    { "glob": "CLAUDE.md", "allow": "edit" },
    { "glob": "**/memory/INDEX.md", "allow": "edit" },
    { "glob": ".env*", "allow": "none" }
  ] },
  "mechanic_or_judgement": { "hints": { "run the test": "make test" } }
}
```

## The hooks

### no-destructive-rm

**What:** blocks `rm -r`, `rm` with wildcards, `rm` on `/`, `~`, `.`, `*`; asks before
`git push --force`, `git reset --hard`, `git clean -f`, `git checkout -- .`, `find -delete`,
disk-wiping commands. Looks through `sudo`, `xargs`, `nice`, `env`. Heredoc bodies and
`python -c "..."` strings do not count.

**Why:** a recursive or wildcard delete is the one shell command with no undo. Deleting named
files (full path) or using `shutil.rmtree` in a script on a verified path is just as fast and
cannot surprise you.

**Example:**

```
> rm -rf build/
[no-destructive-rm] `rm -r` deletes whole trees and cannot be undone. Delete named files one by
one (full path), or use `os.remove` / `shutil.rmtree` in a script on a path you verified.
```

**Config (`no_destructive_rm`):** `mode` (`deny`), `recursive`, `wildcards`, `protected_targets`,
`allow_under` (directories where recursive/wildcard rm is fine; the session scratchpad and
`$TMPDIR` are exempt when `allow_scratchpad` is true), `extra_patterns` (`[{name, pattern}]`),
`extra_mode` (`ask`). Protected targets are always denied, whatever the mode.

### ask-before-sudo

**What:** `sudo`, `doas`, `pkexec`, `su` become a permission prompt, including inside
`ssh host "sudo ..."`. `sudo -n` (non-interactive) passes by default: it either works without a
prompt or fails fast.

**Why:** privilege escalation should never be silent, and an interactive password prompt inside a
tool call hangs the session.

**Example:**

```
> ssh web01 "sudo tar czf /tmp/etc.tgz /etc"
[ask-before-sudo] `sudo` inside an ssh one-liner escalates privileges on the remote host and may
hang on a password prompt. Confirm, or use `sudo -n` / a non-root path.
```

**Config (`ask_before_sudo`):** `mode` (`ask`), `commands`, `allow_non_interactive`, `allowed`
(regexes on the escalated command), `check_ssh`.

### secret-scan

**What:** scans the content of every `Write`/`Edit`, every Bash command line, and the staged
diff when the command is `git commit`. Patterns: private key blocks, AWS, GitHub, GitLab, Slack,
OpenAI/Anthropic-style keys, Google, Stripe, Telegram, SendGrid, JWTs, basic-auth URLs, bearer
headers, and generic `password = "..."` assignments. Placeholders (`<YOUR_TOKEN>`, `changeme`,
`example`, `${VAR}`) are ignored. The reason never echoes the secret, only a masked prefix.

**Why:** a credential that reached a file or a transcript is already leaked. Catching it before
the write is cheaper than rotating it afterwards.

**Example:**

```
> Write config.py: KEY = "AKIA................"
[secret-scan] Possible secret(s) found, call blocked: AWS access key id in config.py line 1
(AKIA...(20 chars)). Use an environment variable or a secrets store ...
```

**Config (`secret_scan`):** `mode` (`deny`), `scan_writes`, `scan_bash_commands`,
`scan_git_commit`, `ignore_paths` (globs), `allow_patterns`, `allow_marker`
(`guardrails: allow-secret` on the line accepts it knowingly), `extra_patterns`, `max_findings`.

**Bonus:** `scripts/pre-commit` is a plain git pre-commit hook with the same scanner, for
commits made outside the agent. See the file header for installation.

### protect-files

**What:** protected files cannot be replaced wholesale. Policy `edit`: `Write` (whole-file
replace) is denied on an existing file, `Edit` stays allowed, creating the file is allowed. Policy
`none`: no change at all. Shell truncation (`> file`, `tee`, `cp`/`mv` onto, `rm`) is caught too;
`>>` append is treated as an edit. Defaults: `CLAUDE.md`, `AGENTS.md`, `MEMORY.md`,
`.claude/settings*.json` (edit), `.env*` (none).

**Why:** a `Write` from memory silently drops every line the agent did not have in its context.
Edits are reviewable and additive; rewrites are not.

**Example:**

```
> Write CLAUDE.md
[protect-files] CLAUDE.md is protected (policy 'edit'): no whole-file Write. Use Edit for
targeted changes.
```

**Config (`protect_files`):** `mode` (`deny`), `allow_create`, `watch_bash`, `protected`
(`[{glob, allow}]`; a glob without `/` matches the file name, `**/dir/file` matches at any depth).

### time-check

**What:** three parts. (1) On every prompt and at session start the current local time is added
as context. (2) When the agent runs `date` the reading is remembered. (3) When text with a
timestamp (`2026-01-31 14:05`, `31.01.2026 14:05`, `01/31/2026 14:05`) is written to a document
(`.md`, `.txt`, `.json`, `.yaml`, `.log` ... not code), the hook warns if no clock was consulted
in the last 30 minutes or if a timestamp lies more than 20 minutes in the future.

**Why:** models have no clock. Left alone they extrapolate from the last time they saw and
write logs, changelogs and reports that drift by hours.

**Example:**

```
> Write worklog.md: "2026-01-31 17:30 deployed v2"
[time-check] Timestamp 2026-01-31 17:30 lies 142 min in the future (now: 2026-01-31 15:08 CET).
Check the clock.
```

**Config (`time_check`):** `mode` (`warn`), `inject_on_prompt`, `inject_on_session_start`,
`inject_counts_as_check`, `max_age_minutes`, `future_tolerance_minutes`, `clock_commands`,
`only_extensions`, `timezone` (IANA name; default system local time).

### tab-guard

**What:** for browser-automation MCP servers (Chrome DevTools, Playwright, ...). Closing a
tab/page becomes a permission prompt unless this session opened that tab itself (ids are tracked
from the open calls, best effort). Also checks sub-agent prompts: "close all tabs" without "only
the ones you opened" gets a warning with the safe wording.

**Why:** a browser shared with the user holds tabs the user left open on purpose: a one-time
code, an unsaved form, a login. "Clean up the tabs" destroys something that cannot be reopened.
The safe rule is: close only what you opened.

**Example:**

```
> mcp__chrome-devtools__close_page {"pageId": "7"}
[tab-guard] Closing tab/page 7 via mcp__chrome-devtools__close_page: this session did not open
it. ... Close only tabs you opened yourself.
```

**Config (`tab_guard`):** `mode` (`ask`), `close_tools` / `open_tools` / `action_tools` (regexes
on the tool name), `close_actions`, `open_actions`, `id_fields`, `allow_if_opened_this_session`,
`agent_prompt_check`, `agent_prompt_mode` (`warn`).

### mechanic-or-judgement

**What:** runs on every sub-agent spawn and asks: is this judgement or mechanics? Prompts that
tell the agent to **wait or poll** ("wait until it is green", "keep checking", "poll") are denied.
Prompts that describe a **scripted task** ("run the tests", "deploy to staging", "bump the
version", "format the code") get a warning with a hint to run the command directly, unless the
prompt also contains a judgement marker (review, investigate, decide, why, ...). English and
German patterns included.

**Why:** a model that polls burns a full context window per poll turn; a model that runs a
deterministic command adds nothing a shell line would not. Agents are for judgement.

**Example:**

```
> Agent: "Run the test suite and wait until it finishes, then report."
[mechanic-or-judgement] This agent prompt asks the sub-agent to wait/poll (wait until it
finishes). ... Run the command yourself, or let a script wait and report back.
```

**Config (`mechanic_or_judgement`):** `wait_mode` (`deny`), `mechanic_mode` (`warn`),
`exempt_subagent_types`, `wait_patterns`, `mechanic_patterns`, `judgement_markers`, `negations`,
`hints` (`{"run the test": "make test"}`).

## How it is wired

`hooks/hooks.json` maps events to scripts; every script reads the hook payload on stdin and
prints the decision as JSON (`hookSpecificOutput.permissionDecision` or `additionalContext`).
Exit code is always 0, so a crashing hook can never block you.

| event | matcher | scripts |
| --- | --- | --- |
| SessionStart, UserPromptSubmit | | time_check inject |
| PreToolUse | Bash | no_destructive_rm, ask_before_sudo, secret_scan, protect_files |
| PreToolUse | Write, Edit, MultiEdit | secret_scan, protect_files, time_check check |
| PreToolUse | Agent, Task | mechanic_or_judgement, tab_guard prompt |
| PreToolUse | mcp__* | tab_guard close |
| PostToolUse | Bash | time_check record |
| PostToolUse | mcp__* | tab_guard track |

State (clock readings, opened tab ids) lives in `$CLAUDE_PLUGIN_DATA` when the plugin runs
under Claude Code, otherwise in `~/.claude/guardrails-state/`.

## Using the hooks without the plugin system

The scripts are plain executables. Add them to `settings.json` yourself:

```json
{ "hooks": { "PreToolUse": [ { "matcher": "Bash", "hooks": [
  { "type": "command", "command": "python3 /path/to/hooks/no_destructive_rm.py" } ] } ] } }
```

Any agent runtime that sends the same JSON on stdin can use them.

## Development

```bash
python3 -m pytest -q          # ~80 tests, a few seconds, no network
python3 scripts/print-defaults.py
claude plugin validate .      # manifest check
```

Design rules for contributions: standard library only, Python 3.9 syntax, fail open, no secrets
or local paths in the repository (`tests/test_package_hygiene.py` enforces this), every rule
configurable, every message available in English (German optional).

## License

MIT, see `LICENSE`.

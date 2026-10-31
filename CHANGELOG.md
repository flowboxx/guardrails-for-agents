# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow semantic versioning.

## [Unreleased]

## [0.1.0-beta] - 2026-10-31

First public version. Beta: the hooks are tested against the documented hook protocol, but
false-alarm rates in daily use are not measured yet. Feedback welcome.

### Added

- `no-destructive-rm`: deny recursive/wildcard `rm` and protected roots, ask before force push,
  hard reset, git clean, `find -delete`, disk wipes; `allow_under` exemptions.
- `ask-before-sudo`: permission prompt for `sudo`/`doas`/`pkexec`/`su`, also inside ssh
  one-liners; `sudo -n` passes.
- `secret-scan`: 16 credential patterns on Write/Edit content, Bash command lines and the staged
  diff of `git commit`; masked reasons; allow marker; git `pre-commit` script.
- `protect-files`: policies `edit`/`none` per glob; Write-vs-Edit distinction; shell truncation
  detection.
- `time-check`: current time injected per prompt; clock readings remembered; warnings for
  timestamps without a clock reading or in the future.
- `tab-guard`: ask before closing browser tabs not opened by this session; agent-prompt check for
  "close all tabs".
- `mechanic-or-judgement`: deny wait/poll agent prompts, warn on scripted tasks, judgement
  markers, EN/DE patterns.
- JSON configuration in four layers, `lang` en/de, optional trigger log, `GUARDRAILS_DISABLE`.
- pytest suite incl. package hygiene test (no paths, hosts, e-mails, IPs or vendor words).

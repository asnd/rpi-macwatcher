# AGENTS.md — AI Agent Conventions for rpi-macwatcher

This file describes how AI coding agents (Claude Code, Copilot, etc.)
should behave when working in this repository.

## Project purpose

`rpi-macwatcher` is a **single-file Python daemon** for Raspberry Pi.
Keep it simple. Avoid framework bloat, unnecessary abstractions, or
dependencies that are hard to install on ARM Debian.

## Language & runtime

- **Python 3.10+** only — use modern syntax (`match`, `|` union types,
  `dict | None`, etc.)
- All production code lives in `macwatcher.py` — do not split into a
  package without a compelling reason
- Dependencies must install cleanly via `pip` on Raspberry Pi OS
  (Debian bookworm, ARM64/ARMv7)

## Style rules

- Follow **PEP 8** — enforced by `ruff` in CI
- Max line length: **99 characters**
- Use `f-strings` for formatting; avoid `%` or `.format()` in new code
- Type hints on all new public functions and methods
- No `print()` — use the module logger everywhere

## Architecture constraints

### Scan modes are mutually exclusive
The `scan_mode` config key selects **either** `arp-scan` or `arpwatch`.
Never run both simultaneously. Mode dispatch lives in `MacWatcher.run()`.

### Vendor lookup
Always go through `VendorLookup.lookup()` — never call `mac_vendor_lookup`
directly in scan logic. This keeps the fallback chain in one place.

### DB writes
All database writes go through `insert_event()`. Do not call
`db.insert()` anywhere else — keep the TinyFlux schema consistent.

### Signal handling
Shutdown is driven by `SIGTERM` / `SIGINT` setting `_running = False`.
Never call `sys.exit()` inside the scan loop; always let the `finally`
block in `MacWatcher.run()` clean up child processes.

## Testing

Run tests and linter locally before pushing:

```bash
pip install ruff pytest
ruff check macwatcher.py
python -m pytest tests/ -v
```

CI runs on every push and pull request.

## What agents should NOT do

- Do not add a web UI, REST API, or MQTT layer without a GitHub issue
  tracking the feature
- Do not change the TinyFlux schema (column names / tag names) without
  updating `insert_event()` and documenting the migration
- Do not auto-commit or auto-push — leave that to the user
- Do not install packages outside the venv created by `install.sh`
- Do not replace `tinyflux` with another DB without discussion — the
  append-only CSV is intentional for SD-card wear levelling

## Adding a new scan mode

1. Add a new class following the `ArpWatchMonitor` pattern
2. Add the mode name to `VALID_SCAN_MODES`
3. Add config defaults to `DEFAULTS`
4. Add a `_cycle_<mode>()` method to `MacWatcher`
5. Dispatch it in `MacWatcher.run()`
6. Update `config.ini`, `README.md`, and this file

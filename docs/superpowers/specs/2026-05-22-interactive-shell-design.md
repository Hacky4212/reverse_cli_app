# Interactive Shell Design

## Goal

Add a persistent command shell for `zriv`.

## Scope

- `zriv shell` enters an interactive REPL.
- Top-level shortcut commands still work, e.g. `zriv -analyze file sample.bin`.
- `gui` opens the window UI.
- The shell is flat, not nested.

## Command Model

### Shell

- `analyze file <path>`
- `analyze code --text "..."`
- `analyze evidence --text "..."`
- `live start [--pid ...] [--process-name ...] [--window-title ...] [--duration ...]`
- `memory read --pid ... --address ... [--size ...]`
- `gui`
- `help`
- `exit`
- `clear`

### Top Level

- `zriv shell`
- `zriv -analyze ...`
- `zriv -live ...`
- `zriv -memory ...`
- `zriv -gui`

## Architecture

- Keep `reverse_framework/api.py` as the backend execution layer.
- Add a shell dispatcher layer for parsing and routing commands.
- Keep `reverse_framework/gui.py` as the window entry.
- Keep existing analyzers unchanged unless routing requires small adapter changes.

## Behavior

- Shell prompt is `zriv>`.
- Unknown commands print a short error and the nearest valid command.
- Missing arguments print concise usage help.
- `Ctrl+C` stops `live` output without closing the shell.
- Long analysis output goes to report files; terminal shows status and paths.

## Errors

- Command parse errors do not crash the session.
- Backend failures return a short error summary.
- Stack traces stay hidden by default.

## Testing

- Shell command parsing.
- Shell command dispatch.
- Top-level shortcut routing.
- `gui` entry invocation.
- `live` interruption behavior.

## Open Items

- Packaging form for the launcher is not fixed yet.

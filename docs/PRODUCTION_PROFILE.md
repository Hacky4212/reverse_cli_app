# Production Profile

## Layer Split

- `C`: low-level process, memory, and system-adjacent collection.
- `C++`: performance-critical file scanning and heavy parsing.
- `Python`: orchestration, CLI, GUI, reporting.

## Runtime Rules

- Keep privilege-sensitive code out of the UI layer.
- Keep performance hot paths out of Python when a native path exists.
- Keep all native tools defensive-only.

## Current Native Pieces

- `native/native_probe`: defensive executable metadata probe.
- `native/process_memory_reader`: defensive live process memory reader.
- `native/perf_scan`: fast file strings and entropy scanner.

## Launch Goal

- CLI must work without GUI.
- GUI must work without blocking the analysis pipeline.
- Missing native tools must degrade cleanly, not crash the app.

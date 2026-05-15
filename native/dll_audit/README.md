# dll_audit

`dll_audit` is a defensive DLL triage helper.

It parses a DLL from disk and emits JSON with PE metadata, sections, exports, imports, and basic risk hints.

It does not inject a DLL into another process.
It does not open a target process.
It does not execute the analyzed DLL.

## Build

```powershell
cmake -S native\dll_audit -B native\dll_audit\build
cmake --build native\dll_audit\build --config Release
```

## Run

```powershell
native\dll_audit\build\Release\dll_audit.exe path\to\sample.dll
```

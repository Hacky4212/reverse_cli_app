# native_probe

`native_probe` is a small C file header probe used by the Python pipeline.

It keeps low-level parsing outside the orchestration layer.
The output is JSON on stdout.

Current PE output includes subsystem and certificate-table metadata.
This supports defensive driver triage.

## Build

```powershell
cmake -S native\native_probe -B native\native_probe\build
cmake --build native\native_probe\build --config Release
```

## Run

```powershell
native\native_probe\build\Release\native_probe.exe samples\demo.bin
```

On non-MSVC generators, the executable may be under:

```text
native/native_probe/build/native_probe
```

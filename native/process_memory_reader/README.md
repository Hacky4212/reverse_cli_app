# process_memory_reader

`process_memory_reader` is a Windows C helper that reads live process memory at a given PID and address.

It is used by the Python pipeline as a low-level reader.
The output is JSON on stdout.

## Build

```powershell
cmake -S native\process_memory_reader -B native\process_memory_reader\build
cmake --build native\process_memory_reader\build --config Release
```

## Run

```powershell
native\process_memory_reader\build\Release\process_memory_reader.exe --pid 1234 --address 0x7FF00000 --size 64
```

The helper reports:

- requested size
- bytes actually read
- memory region metadata when available
- hex and ASCII previews
- read errors

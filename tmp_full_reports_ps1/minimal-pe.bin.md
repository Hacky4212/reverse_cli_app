# Reverse Analysis Report

- Target: `C:\Users\yangxu\Desktop\tools\reverse-tools\main\native\native_probe\build\minimal-pe.bin`
- Generated: `2026-05-14T03:06:29.0692153+00:00`
- Issues: `0`
- Indicators: `0`

## Issues

No issues detected by enabled analyzers.

## Findings

### file_profile

```json
{
    "name":  "minimal-pe.bin",
    "size":  256,
    "sha256":  "e0c7390bd31f399210e5dd28dab2003af0e360c1b3363e927dc4fbc2aedd967f",
    "md5":  "71bf603797dee0d2f42c23f2c641ee5e",
    "entropy":  0.3311,
    "magic":  "4d 5a 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
}
```

### strings

```json
{
    "min_length":  4,
    "count":  0,
    "items":  [

              ]
}
```

### native_probe

```json
{
    "tool":  "native_probe",
    "version":  "0.1.0",
    "target":  "C:\\Users\\yangxu\\Desktop\\tools\\reverse-tools\\main\\native\\native_probe\\build\\minimal-pe.bin",
    "file_size":  256,
    "magic":  "4d 5a 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
    "format":  "PE",
    "valid":  true,
    "headers":  {
                    "pe_offset":  128,
                    "machine":  "x64",
                    "sections":  0,
                    "timestamp":  0,
                    "optional_header_size":  0,
                    "optional_header_magic":  "0x0",
                    "subsystem":  "0",
                    "subsystem_value":  0,
                    "characteristics":  "0x2022",
                    "dll_characteristics":  "0x0",
                    "certificate_table_size":  0,
                    "certificate_table_present":  false
                },
    "sections":  [

                 ],
    "section_list_truncated":  false
}
```

### pe_header

```json
{
    "sections":  0,
    "pe_offset":  128,
    "timestamp":  0,
    "optional_header_magic":  "0x0",
    "machine":  "0x8664",
    "characteristics":  "0x2022",
    "optional_header_size":  0
}
```

### indicators

```json
{
    "indicator_count":  0,
    "indicators":  [

                   ],
    "capabilities":  {

                     }
}
```

### kernel_security

```json
{
    "driver_like":  false,
    "risk_score":  0,
    "pe":  {
               "format":  "PE",
               "valid":  false,
               "error":  "Optional header is truncated."
           },
    "capabilities":  {

                     },
    "device_names":  [

                     ]
}
```

### entropy_regions

```json
{
    "window":  4096,
    "threshold":  7.2,
    "region_count":  0,
    "regions":  [

                ]
}
```


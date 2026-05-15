# Reverse Analysis Report

- Target: `C:\Users\yangxu\Desktop\tools\reverse-tools\main\tmp_perf_scan_utf16.bin`
- Generated: `2026-05-14T02:28:21.2997663+00:00`
- Issues: `0`
- Indicators: `0`

## Issues

No issues detected by enabled analyzers.

## Findings

### file_profile

```json
{
    "name":  "tmp_perf_scan_utf16.bin",
    "size":  14,
    "sha256":  "db34232b3c637763cce098f77cd177d9a411b7593fb2dfb00d5834896b37182b",
    "md5":  "6b71ee84301ecf7712e9f3de5e33b300",
    "entropy":  2.6995,
    "magic":  "41 00 42 00 43 00 44 00 00 00 57 58 59 5a"
}
```

### strings

```json
{
    "min_length":  4,
    "count":  1,
    "items":  [
                  "WXYZ"
              ]
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
               "format":  "not_pe"
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


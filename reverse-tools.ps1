param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Target,

    [string]$Out = "reports",

    [ValidateSet("all", "json", "markdown")]
    [string]$Format = "all",

    [int]$MinString = 4,

    [int]$MaxStrings = 300,

    [int]$EntropyWindow = 4096,

    [double]$EntropyThreshold = 7.2,

    [string]$NativeProbePath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Test-PythonRuntimeAvailable {
    foreach ($candidate in @("python", "py", "python3")) {
        if (Get-Command $candidate -ErrorAction SilentlyContinue) {
            return $true
        }
    }

    return $false
}

function Write-PythonRuntimeHint {
    if (Test-PythonRuntimeAvailable) {
        return
    }

    Write-Warning "Python is not on PATH. reverse-tools.ps1 still works, but the Python CLI examples and pytest require Python."
}

function Get-Entropy {
    param([byte[]]$Data)

    if ($Data.Length -eq 0) {
        return 0
    }

    $counts = @{}
    foreach ($byte in $Data) {
        if ($counts.ContainsKey($byte)) {
            $counts[$byte] += 1
        }
        else {
            $counts[$byte] = 1
        }
    }

    $entropy = 0.0
    foreach ($count in $counts.Values) {
        $p = $count / $Data.Length
        $entropy -= $p * [Math]::Log($p, 2)
    }

    return [Math]::Round($entropy, 4)
}

function Get-AsciiStrings {
    param(
        [byte[]]$Data,
        [int]$MinLength,
        [int]$Limit
    )

    $items = New-Object System.Collections.Generic.List[string]
    $buffer = New-Object System.Collections.Generic.List[byte]

    foreach ($byte in $Data) {
        $isPrintable = ($byte -ge 32 -and $byte -le 126)
        if ($isPrintable) {
            $buffer.Add($byte)
            continue
        }

        if ($buffer.Count -ge $MinLength -and $items.Count -lt $Limit) {
            $items.Add([System.Text.Encoding]::ASCII.GetString($buffer.ToArray()))
        }
        $buffer.Clear()

        if ($items.Count -ge $Limit) {
            break
        }
    }

    if ($buffer.Count -ge $MinLength -and $items.Count -lt $Limit) {
        $items.Add([System.Text.Encoding]::ASCII.GetString($buffer.ToArray()))
    }

    return $items
}

function Get-EntropyRegions {
    param(
        [byte[]]$Data,
        [int]$Window,
        [double]$Threshold
    )

    $regions = New-Object System.Collections.Generic.List[hashtable]
    if ($Data.Length -eq 0) {
        return $regions
    }

    for ($offset = 0; $offset -lt $Data.Length; $offset += $Window) {
        $size = [Math]::Min($Window, $Data.Length - $offset)
        $chunk = New-Object byte[] $size
        [Array]::Copy($Data, $offset, $chunk, 0, $size)
        $entropy = Get-Entropy -Data $chunk

        if ($entropy -ge $Threshold) {
            $regions.Add([ordered]@{
                offset = $offset
                size = $size
                entropy = $entropy
            })
        }

        if ($regions.Count -ge 20) {
            break
        }
    }

    return $regions
}

function Get-Indicators {
    param([byte[]]$Data)

    $text = [System.Text.Encoding]::ASCII.GetString($Data)
    $patterns = [ordered]@{
        url = "https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,}"
        ipv4 = "\b(?:\d{1,3}\.){3}\d{1,3}\b"
        email = "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
        registry = "\bHK(?:EY_)?(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS)\\[ -~]{4,}"
        windows_path = "\b[A-Za-z]:\\[ -~]{4,}"
    }

    $seen = @{}
    $items = New-Object System.Collections.Generic.List[hashtable]
    foreach ($kind in $patterns.Keys) {
        foreach ($match in [regex]::Matches($text, $patterns[$kind])) {
            $key = "$kind`0$($match.Value)"
            if ($seen.ContainsKey($key)) {
                continue
            }
            $seen[$key] = $true
            $items.Add([ordered]@{
                kind = $kind
                value = $match.Value
                source = "indicators"
                offset = $match.Index
            })
        }
    }

    return $items
}

function Get-SuspiciousCapabilities {
    param([byte[]]$Data)

    $text = [System.Text.Encoding]::ASCII.GetString($Data)
    $terms = [ordered]@{
        process_injection = @("VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtCreateThreadEx", "QueueUserAPC")
        dynamic_loading = @("LoadLibrary", "GetProcAddress")
        networking = @("InternetOpen", "InternetConnect", "HttpSendRequest", "WinHttpOpen", "WSAStartup")
        script_execution = @("powershell", "cmd.exe", "wscript", "cscript", "rundll32", "regsvr32", "mshta")
        persistence = @("Run\", "RunOnce\", "schtasks", "CreateService", "StartService")
        defense_evasion = @("IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "vssadmin", "wevtutil")
    }

    $capabilities = [ordered]@{}
    foreach ($category in $terms.Keys) {
        $hits = New-Object System.Collections.Generic.List[string]
        foreach ($term in $terms[$category]) {
            if ($text.IndexOf($term, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                $hits.Add($term)
            }
        }
        if ($hits.Count -gt 0) {
            $capabilities[$category] = @($hits)
        }
    }

    return $capabilities
}

function Get-PeKernelMetadata {
    param([byte[]]$Data)

    if ($Data.Length -lt 64 -or $Data[0] -ne 0x4D -or $Data[1] -ne 0x5A) {
        return [ordered]@{ format = "not_pe" }
    }

    $peOffset = Read-UInt32Le -Data $Data -Offset 0x3C
    if ($peOffset + 24 -gt $Data.Length) {
        return [ordered]@{ format = "invalid_pe" }
    }

    $signature = [System.Text.Encoding]::ASCII.GetString($Data, $peOffset, 4)
    if ($signature -ne "PE`0`0") {
        return [ordered]@{ format = "invalid_pe" }
    }

    $optionalSize = Read-UInt16Le -Data $Data -Offset ($peOffset + 20)
    $optionalOffset = $peOffset + 24
    if ($optionalOffset + $optionalSize -gt $Data.Length -or $optionalSize -lt 72) {
        return [ordered]@{
            format = "PE"
            valid = $false
            error = "Optional header is truncated."
        }
    }

    $optionalMagic = Read-UInt16Le -Data $Data -Offset $optionalOffset
    $subsystemValue = Read-UInt16Le -Data $Data -Offset ($optionalOffset + 68)
    $dllCharacteristics = Read-UInt16Le -Data $Data -Offset ($optionalOffset + 70)
    $dataDirectoryOffset = if ($optionalMagic -eq 0x10B) { $optionalOffset + 96 } else { $optionalOffset + 112 }
    $certSize = 0
    if ($dataDirectoryOffset + 40 -le $Data.Length) {
        $certSize = Read-UInt32Le -Data $Data -Offset ($dataDirectoryOffset + 36)
    }

    $subsystemName = switch ($subsystemValue) {
        1 { "NATIVE" }
        2 { "WINDOWS_GUI" }
        3 { "WINDOWS_CUI" }
        10 { "EFI_APPLICATION" }
        11 { "EFI_BOOT_SERVICE_DRIVER" }
        12 { "EFI_RUNTIME_DRIVER" }
        default { "$subsystemValue" }
    }

    return [ordered]@{
        format = "PE"
        valid = $true
        optional_header_magic = if ($optionalMagic -eq 0x10B) { "PE32" } elseif ($optionalMagic -eq 0x20B) { "PE32+" } else { "0x{0:X}" -f $optionalMagic }
        subsystem = $subsystemName
        subsystem_value = $subsystemValue
        dll_characteristics = "0x{0:X}" -f $dllCharacteristics
        certificate_table_size = $certSize
        certificate_table_present = $certSize -gt 0
    }
}

function Get-KernelSecurity {
    param(
        [byte[]]$Data,
        [string]$TargetPath
    )

    $text = [System.Text.Encoding]::ASCII.GetString($Data)
    $terms = [ordered]@{
        device_interface = @("IoCreateDevice", "IoCreateDeviceSecure", "IoCreateSymbolicLink", "\Device\", "\DosDevices\")
        ioctl_surface = @("IRP_MJ_DEVICE_CONTROL", "DeviceIoControl", "IOCTL", "METHOD_BUFFERED", "METHOD_NEITHER", "FILE_ANY_ACCESS")
        kernel_memory_access = @("MmMapIoSpace", "MmCopyVirtualMemory", "MmGetPhysicalAddress", "MmMapLockedPagesSpecifyCache", "ZwMapViewOfSection")
        process_thread_access = @("PsLookupProcessByProcessId", "PsGetCurrentProcess", "PsSetCreateProcessNotifyRoutine", "PsSetCreateThreadNotifyRoutine", "PsSetLoadImageNotifyRoutine", "ObOpenObjectByPointer")
        registry_or_driver_loading = @("ZwLoadDriver", "ZwUnloadDriver", "ZwCreateKey", "ZwSetValueKey", "RtlWriteRegistryValue")
        kernel_callbacks = @("ObRegisterCallbacks", "CmRegisterCallback", "PsSetCreateProcessNotifyRoutine", "PsSetCreateThreadNotifyRoutine", "PsSetLoadImageNotifyRoutine")
        kernel_tamper = @("KeServiceDescriptorTable", "KiServiceTable", "SSDT", "PatchGuard", "g_CiOptions", "DisableIntegrityChecks", "CR0", "MSR")
        known_vulnerable_driver_reference = @("WinRing0", "RTCore64", "RTCore32", "ASIO", "GDRV", "DBUtil", "iqvw64e", "eneio64", "PROCEXP", "NalDrv")
    }

    $capabilities = [ordered]@{}
    foreach ($category in $terms.Keys) {
        $hits = New-Object System.Collections.Generic.List[string]
        foreach ($term in $terms[$category]) {
            if ($text.IndexOf($term, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                $hits.Add($term)
            }
        }
        if ($hits.Count -gt 0) {
            $capabilities[$category] = @($hits)
        }
    }

    $deviceIndicators = New-Object System.Collections.Generic.List[hashtable]
    $devicePatterns = [ordered]@{
        kernel_device = "\\Device\\[A-Za-z0-9_.-]{2,80}"
        dos_device = "\\DosDevices\\[A-Za-z0-9_.-]{2,80}"
        nt_device_alias = "\\\?\?\\[A-Za-z0-9_.-]{2,80}"
    }
    $seenDevices = @{}
    foreach ($kind in $devicePatterns.Keys) {
        foreach ($match in [regex]::Matches($text, $devicePatterns[$kind])) {
            $key = "$kind`0$($match.Value)"
            if ($seenDevices.ContainsKey($key)) {
                continue
            }
            $seenDevices[$key] = $true
            $deviceIndicators.Add([ordered]@{
                kind = $kind
                value = $match.Value
                source = "kernel_security"
                offset = $match.Index
            })
        }
    }

    $pe = Get-PeKernelMetadata -Data $Data
    $driverLike = ([System.IO.Path]::GetExtension($TargetPath).Equals(".sys", [StringComparison]::OrdinalIgnoreCase) -or
        ($pe.Contains("subsystem") -and $pe.subsystem -eq "NATIVE") -or
        $capabilities.Contains("device_interface") -or
        $deviceIndicators.Count -gt 0)

    $riskScore = 0
    if ($driverLike) { $riskScore += 20 }
    if ($capabilities.Contains("ioctl_surface")) { $riskScore += 20 }
    if ($capabilities.Contains("kernel_memory_access")) { $riskScore += 25 }
    if ($capabilities.Contains("kernel_tamper")) { $riskScore += 30 }
    if ($capabilities.Contains("known_vulnerable_driver_reference")) { $riskScore += 25 }
    if ($driverLike -and $pe.Contains("format") -and $pe.format -eq "PE" -and -not $pe.certificate_table_present) { $riskScore += 10 }
    $riskScore = [Math]::Min($riskScore, 100)

    $kernelIssues = New-Object System.Collections.Generic.List[hashtable]
    if ($driverLike) {
        $kernelIssues.Add([ordered]@{
            id = "kernel_driver_candidate"
            title = "Kernel driver candidate detected"
            severity = "low"
            category = "kernel"
            summary = "The sample has signals commonly seen in Windows kernel drivers."
            confidence = 0.7
            evidence = @{ capability_categories = @($capabilities.Keys); pe = $pe }
            tags = @("kernel", "driver", "ring0")
            recommendation = "Analyze the sample in an isolated kernel-debugging lab."
        })
    }
    if ($driverLike -and $pe.Contains("format") -and $pe.format -eq "PE" -and -not $pe.certificate_table_present) {
        $kernelIssues.Add([ordered]@{
            id = "driver_signature_not_detected"
            title = "Driver certificate table not detected"
            severity = "medium"
            category = "kernel"
            summary = "The PE certificate table is missing or not visible in static parsing."
            confidence = 0.55
            evidence = @{ certificate_table_size = $pe.certificate_table_size }
            tags = @("kernel", "driver", "signature")
            recommendation = "Verify Authenticode signature with a trusted signing tool."
        })
    }
    if ($capabilities.Contains("ioctl_surface") -and $capabilities.Contains("kernel_memory_access")) {
        $kernelIssues.Add([ordered]@{
            id = "risky_kernel_ioctl_surface"
            title = "Risky kernel IOCTL surface indicators"
            severity = "high"
            category = "kernel"
            summary = "The sample exposes IOCTL-related strings and kernel memory access terms."
            confidence = 0.65
            evidence = @{ ioctl_surface = $capabilities.ioctl_surface; kernel_memory_access = $capabilities.kernel_memory_access }
            tags = @("kernel", "driver", "ioctl", "memory")
            recommendation = "Review IOCTL handlers for access checks and memory safety."
        })
    }
    if ($capabilities.Contains("kernel_tamper")) {
        $kernelIssues.Add([ordered]@{
            id = "kernel_tamper_indicators"
            title = "Kernel tamper indicators detected"
            severity = "high"
            category = "kernel"
            summary = "The sample contains strings linked to kernel tampering or integrity bypass attempts."
            confidence = 0.6
            evidence = @{ matched_terms = $capabilities.kernel_tamper }
            tags = @("kernel", "tamper", "integrity")
            recommendation = "Treat as high risk and inspect in a controlled analysis VM."
        })
    }
    if ($capabilities.Contains("known_vulnerable_driver_reference")) {
        $kernelIssues.Add([ordered]@{
            id = "byovd_reference_indicators"
            title = "Known vulnerable driver references detected"
            severity = "high"
            category = "kernel"
            summary = "The sample references names commonly associated with vulnerable driver abuse."
            confidence = 0.6
            evidence = @{ matched_terms = $capabilities.known_vulnerable_driver_reference }
            tags = @("kernel", "byovd", "driver")
            recommendation = "Check the sample against your vulnerable-driver blocklist."
        })
    }
    if ($riskScore -ge 50) {
        $kernelIssues.Add([ordered]@{
            id = "kernel_risk_score"
            title = "Elevated kernel risk score"
            severity = if ($riskScore -ge 80) { "critical" } else { "high" }
            category = "kernel"
            summary = "Multiple kernel-risk signals were found in the sample."
            confidence = 0.6
            evidence = @{ risk_score = $riskScore; capability_categories = @($capabilities.Keys) }
            tags = @("kernel", "risk-score")
            recommendation = "Prioritize manual review before allowing this driver in any environment."
        })
    }

    return [ordered]@{
        finding = [ordered]@{
            driver_like = $driverLike
            risk_score = $riskScore
            pe = $pe
            capabilities = $capabilities
            device_names = @($deviceIndicators)
        }
        indicators = @($deviceIndicators)
        issues = @($kernelIssues)
    }
}

function Read-UInt16Le {
    param([byte[]]$Data, [int]$Offset)
    return [BitConverter]::ToUInt16($Data, $Offset)
}

function Read-UInt32Le {
    param([byte[]]$Data, [int]$Offset)
    return [BitConverter]::ToUInt32($Data, $Offset)
}

function Get-PeHeader {
    param([byte[]]$Data)

    if ($Data.Length -lt 64 -or $Data[0] -ne 0x4D -or $Data[1] -ne 0x5A) {
        return $null
    }

    $peOffset = Read-UInt32Le -Data $Data -Offset 0x3C
    if ($peOffset + 24 -gt $Data.Length) {
        return @{ error = "MZ header found, but PE header is out of range." }
    }

    $signature = [System.Text.Encoding]::ASCII.GetString($Data, $peOffset, 4)
    if ($signature -ne "PE`0`0") {
        return @{ error = "MZ header found, but PE signature is invalid." }
    }

    $machineValue = Read-UInt16Le -Data $Data -Offset ($peOffset + 4)
    $machineMap = @{
        0x014C = "x86"
        0x8664 = "x64"
        0x01C0 = "ARM"
        0xAA64 = "ARM64"
    }

    $optionalMagic = Read-UInt16Le -Data $Data -Offset ($peOffset + 24)
    $optionalName = switch ($optionalMagic) {
        0x10B { "PE32" }
        0x20B { "PE32+" }
        default { "0x{0:X}" -f $optionalMagic }
    }

    return @{
        pe_offset = $peOffset
        machine = if ($machineMap.ContainsKey($machineValue)) { $machineMap[$machineValue] } else { "0x{0:X}" -f $machineValue }
        sections = Read-UInt16Le -Data $Data -Offset ($peOffset + 6)
        timestamp = Read-UInt32Le -Data $Data -Offset ($peOffset + 8)
        optional_header_size = Read-UInt16Le -Data $Data -Offset ($peOffset + 20)
        optional_header_magic = $optionalName
        characteristics = "0x{0:X}" -f (Read-UInt16Le -Data $Data -Offset ($peOffset + 22))
    }
}

function Get-ElfHeader {
    param([byte[]]$Data)

    if ($Data.Length -lt 20 -or $Data[0] -ne 0x7F -or $Data[1] -ne 0x45 -or $Data[2] -ne 0x4C -or $Data[3] -ne 0x46) {
        return $null
    }

    $className = switch ($Data[4]) {
        1 { "ELF32" }
        2 { "ELF64" }
        default { "unknown" }
    }

    if ($Data[5] -ne 1) {
        return @{
            class = $className
            endian = "big_or_unknown"
            note = "PowerShell entry supports little-endian ELF header triage."
        }
    }

    $typeMap = @{
        0 = "NONE"
        1 = "REL"
        2 = "EXEC"
        3 = "DYN"
        4 = "CORE"
    }
    $machineMap = @{
        3 = "x86"
        40 = "ARM"
        62 = "x64"
        183 = "ARM64"
    }

    $typeValue = Read-UInt16Le -Data $Data -Offset 16
    $machineValue = Read-UInt16Le -Data $Data -Offset 18

    return @{
        class = $className
        endian = "little"
        type = if ($typeMap.ContainsKey($typeValue)) { $typeMap[$typeValue] } else { "$typeValue" }
        machine = if ($machineMap.ContainsKey($machineValue)) { $machineMap[$machineValue] } else { "$machineValue" }
        version = Read-UInt32Le -Data $Data -Offset 20
    }
}

function ConvertTo-Markdown {
    param([hashtable]$Report)

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("# Reverse Analysis Report")
    $lines.Add("")
    $lines.Add("- Target: ``$($Report.target)``")
    $lines.Add("- Generated: ``$($Report.generated_at)``")
    $lines.Add("- Issues: ``$($Report.issues.Count)``")
    $lines.Add("- Indicators: ``$($Report.indicators.Count)``")
    $lines.Add("")
    $lines.Add("## Issues")
    $lines.Add("")

    if ($Report.issues.Count -gt 0) {
        foreach ($issue in $Report.issues) {
            $lines.Add("### $($issue.severity.ToUpperInvariant()) - $($issue.title)")
            $lines.Add("")
            $lines.Add($issue.summary)
            $lines.Add("")
            $lines.Add("``````json")
            $lines.Add(($issue | ConvertTo-Json -Depth 8))
            $lines.Add("``````")
            $lines.Add("")
        }
    }
    else {
        $lines.Add("No issues detected by enabled analyzers.")
        $lines.Add("")
    }

    if ($Report.indicators.Count -gt 0) {
        $lines.Add("## Indicators")
        $lines.Add("")
        foreach ($indicator in ($Report.indicators | Select-Object -First 200)) {
            $lines.Add("- ``$($indicator.kind)``: ``$($indicator.value)`` @ $($indicator.offset)")
        }
        $lines.Add("")
    }

    $lines.Add("## Findings")
    $lines.Add("")

    foreach ($key in $Report.findings.Keys) {
        $lines.Add("### $key")
        $lines.Add("")
        $lines.Add("``````json")
        $lines.Add(($Report.findings[$key] | ConvertTo-Json -Depth 8))
        $lines.Add("``````")
        $lines.Add("")
    }

    if ($Report.errors.Count -gt 0) {
        $lines.Add("## Errors")
        $lines.Add("")
        foreach ($item in $Report.errors) {
            $lines.Add("- ``$($item.analyzer)``: $($item.message)")
        }
        $lines.Add("")
    }

    return ($lines -join [Environment]::NewLine)
}

function Invoke-NativeProbe {
    param(
        [string]$ProbePath,
        [string]$TargetPath
    )

    if ([string]::IsNullOrWhiteSpace($ProbePath)) {
        return $null
    }

    $resolvedProbePath = $ProbePath
    if (-not (Test-Path -LiteralPath $resolvedProbePath -PathType Leaf)) {
        $scriptRelativePath = Join-Path $PSScriptRoot $ProbePath
        if (Test-Path -LiteralPath $scriptRelativePath -PathType Leaf) {
            $resolvedProbePath = $scriptRelativePath
        }
    }

    $command = @($resolvedProbePath, $TargetPath)
    if (-not (Test-Path -LiteralPath $resolvedProbePath -PathType Leaf)) {
        return [ordered]@{
            command = $command
            available = $false
            output = $null
            error = "Native probe executable not found: $resolvedProbePath"
            finding = $null
        }
    }

    try {
        $rawOutput = & $resolvedProbePath $TargetPath 2>&1
        $exitCode = $LASTEXITCODE
        $text = ($rawOutput | Out-String).Trim()
        $finding = $null

        if (-not [string]::IsNullOrWhiteSpace($text)) {
            try {
                $finding = $text | ConvertFrom-Json
            }
            catch {
                return [ordered]@{
                    command = $command
                    available = $true
                    output = $text
                    error = "Native probe returned invalid JSON."
                    finding = $null
                }
            }
        }

        return [ordered]@{
            command = $command
            available = $true
            output = $text
            error = if ($exitCode -eq 0) { $null } else { "Exit code $exitCode" }
            finding = $finding
        }
    }
    catch {
        return [ordered]@{
            command = $command
            available = $true
            output = $null
            error = $_.Exception.Message
            finding = $null
        }
    }
}

Write-PythonRuntimeHint

$resolvedTarget = Resolve-Path -LiteralPath $Target
$data = [System.IO.File]::ReadAllBytes($resolvedTarget.Path)
$outDir = New-Item -ItemType Directory -Force -Path $Out
$safeName = [System.IO.Path]::GetFileName($resolvedTarget.Path).Replace(" ", "_")

$findings = [ordered]@{
    file_profile = [ordered]@{
        name = [System.IO.Path]::GetFileName($resolvedTarget.Path)
        size = $data.Length
        sha256 = (Get-FileHash -LiteralPath $resolvedTarget.Path -Algorithm SHA256).Hash.ToLowerInvariant()
        md5 = (Get-FileHash -LiteralPath $resolvedTarget.Path -Algorithm MD5).Hash.ToLowerInvariant()
        entropy = Get-Entropy -Data $data
        magic = (($data | Select-Object -First 16 | ForEach-Object { "{0:x2}" -f $_ }) -join " ")
    }
    strings = [ordered]@{
        min_length = $MinString
        count = 0
        items = @()
    }
}

$stringItems = @(Get-AsciiStrings -Data $data -MinLength $MinString -Limit $MaxStrings)
$findings.strings.count = $stringItems.Count
$findings.strings.items = $stringItems

$errors = New-Object System.Collections.Generic.List[hashtable]
$issues = New-Object System.Collections.Generic.List[hashtable]
$tools = New-Object System.Collections.Generic.List[hashtable]

$nativeProbe = Invoke-NativeProbe -ProbePath $NativeProbePath -TargetPath $resolvedTarget.Path
if ($null -ne $nativeProbe) {
    $tools.Add([ordered]@{
        name = "native_probe"
        command = $nativeProbe.command
        available = $nativeProbe.available
        enabled = $true
        output = $nativeProbe.output
        error = $nativeProbe.error
    })

    if ($null -ne $nativeProbe.finding) {
        $findings.native_probe = $nativeProbe.finding
        if ($nativeProbe.finding.PSObject.Properties.Name -contains "valid" -and
            $nativeProbe.finding.PSObject.Properties.Name -contains "format" -and
            $nativeProbe.finding.valid -eq $false -and
            $nativeProbe.finding.format -ne "unknown") {
            $issues.Add([ordered]@{
                id = "native_probe_invalid_header"
                title = "Native probe found an invalid executable header"
                severity = "medium"
                category = "format"
                summary = "The native parser found a known file signature with an invalid header."
                confidence = 0.75
                evidence = @{ format = $nativeProbe.finding.format; error = $nativeProbe.finding.error }
                tags = @("native", "format")
                recommendation = "Open the sample in a disassembler and verify the header manually."
            })
        }
    }
    elseif ($nativeProbe.error) {
        $errors.Add(@{ analyzer = "native_probe"; message = $nativeProbe.error })
    }
}

$peHeader = Get-PeHeader -Data $data
if ($null -ne $peHeader) {
    if ($peHeader.ContainsKey("error")) {
        $errors.Add(@{ analyzer = "pe_header"; message = $peHeader.error })
    }
    else {
        $findings.pe_header = $peHeader
    }
}

$elfHeader = Get-ElfHeader -Data $data
if ($null -ne $elfHeader) {
    $findings.elf_header = $elfHeader
}

$indicators = @(Get-Indicators -Data $data)
$capabilities = Get-SuspiciousCapabilities -Data $data
$findings.indicators = [ordered]@{
    indicator_count = $indicators.Count
    indicators = @($indicators | Select-Object -First 200)
    capabilities = $capabilities
}

$kernelSecurity = Get-KernelSecurity -Data $data -TargetPath $resolvedTarget.Path
$findings.kernel_security = $kernelSecurity.finding
$indicators = @($indicators) + @($kernelSecurity.indicators)
foreach ($issue in $kernelSecurity.issues) {
    $issues.Add($issue)
}

$entropyRegions = @(Get-EntropyRegions -Data $data -Window $EntropyWindow -Threshold $EntropyThreshold)
$findings.entropy_regions = [ordered]@{
    window = $EntropyWindow
    threshold = $EntropyThreshold
    region_count = $entropyRegions.Count
    regions = $entropyRegions
}

if ($entropyRegions.Count -gt 0) {
    $issues.Add([ordered]@{
        id = "high_entropy_regions"
        title = "High entropy regions detected"
        severity = "medium"
        category = "packing"
        summary = "The sample contains regions that may be packed, encrypted, or compressed."
        confidence = 0.65
        evidence = @{ regions = @($entropyRegions | Select-Object -First 5) }
        tags = @("packing", "crypto", "triage")
        recommendation = "Review these offsets in a disassembler or unpacking workflow."
    })
}

$severityByCategory = @{
    process_injection = "high"
    script_execution = "medium"
    persistence = "medium"
    defense_evasion = "medium"
    networking = "low"
    dynamic_loading = "low"
}
foreach ($category in $capabilities.Keys) {
    $issues.Add([ordered]@{
        id = "capability_$category"
        title = "Suspicious capability: $category"
        severity = if ($severityByCategory.ContainsKey($category)) { $severityByCategory[$category] } else { "low" }
        category = "capability"
        summary = "The sample contains strings commonly linked to this behavior."
        confidence = 0.55
        evidence = @{ matched_terms = $capabilities[$category] }
        tags = @("capability", "$category")
        recommendation = "Confirm through imports, cross references, or dynamic analysis."
    })
}

$report = [ordered]@{
    target = $resolvedTarget.Path
    generated_at = [DateTimeOffset]::UtcNow.ToString("o")
    config = [ordered]@{
        min_string = $MinString
        max_strings = $MaxStrings
        entropy_window = $EntropyWindow
        entropy_threshold = $EntropyThreshold
    }
    findings = $findings
    issues = @($issues)
    indicators = @($indicators)
    tools = @($tools)
    errors = @($errors)
}

$written = New-Object System.Collections.Generic.List[string]
if ($Format -eq "all" -or $Format -eq "json") {
    $jsonPath = Join-Path $outDir.FullName "$safeName.json"
    $report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
    $written.Add($jsonPath)
}

if ($Format -eq "all" -or $Format -eq "markdown") {
    $mdPath = Join-Path $outDir.FullName "$safeName.md"
    ConvertTo-Markdown -Report $report | Set-Content -LiteralPath $mdPath -Encoding UTF8
    $written.Add($mdPath)
}

Write-Host "Analysis complete."
foreach ($path in $written) {
    Write-Host $path
}

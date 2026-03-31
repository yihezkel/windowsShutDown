#Requires -Version 5.1
<#
.SYNOPSIS
    Monitors Windows for abnormal shutdowns and diagnoses root causes.

.DESCRIPTION
    Runs at every Windows logon via Scheduled Task (elevated).
    - Detects whether the prior shutdown was normal or abnormal.
    - If abnormal: diagnoses the root cause, appends findings to lastShutDown.txt, opens the file.
    - Periodic tasks (every 21 days): sleep study, driver snapshot, power config audit.

.PARAMETER Install
    Registers the Scheduled Task "ShutdownMonitor" (replaces any existing one).

.PARAMETER Uninstall
    Removes the Scheduled Task "ShutdownMonitor".
#>

[CmdletBinding()]
param(
    [switch]$Install,
    [switch]$Uninstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# --- Configuration ---
$ScriptDir        = 'C:\workspace\personal\windowsShutDown'
$ShutdownLog      = Join-Path $ScriptDir 'lastShutDown.txt'
$RecommendFile    = Join-Path $ScriptDir 'generalRecommendations.txt'
$DriverFile       = Join-Path $ScriptDir 'driverSnapshot.txt'
$SleepStudyFile   = Join-Path $ScriptDir 'sleepStudy.html'
$StateFile        = Join-Path $ScriptDir '.monitorState.json'
$TaskName         = 'ShutdownMonitor'
$PeriodicDays     = 21

# --- BSOD Code Mapping ---
$BugcheckMap = @{
    0x0000001E = @{ Name = 'KMODE_EXCEPTION_NOT_HANDLED';       Cause = 'A kernel-mode program generated an exception the error handler did not catch. Often a faulty driver.' }
    0x00000024 = @{ Name = 'NTFS_FILE_SYSTEM';                  Cause = 'Problem with the NTFS file system driver. Possible disk corruption or failing drive.' }
    0x0000003B = @{ Name = 'SYSTEM_SERVICE_EXCEPTION';          Cause = 'A system thread generated an exception. Commonly caused by GPU or antivirus drivers.' }
    0x00000050 = @{ Name = 'PAGE_FAULT_IN_NONPAGED_AREA';       Cause = 'Invalid memory reference. Often caused by faulty RAM, a bad driver, or corrupted system files.' }
    0x0000007E = @{ Name = 'SYSTEM_THREAD_EXCEPTION_NOT_HANDLED'; Cause = 'A system thread generated an exception. Usually a driver issue.' }
    0x0000007F = @{ Name = 'UNEXPECTED_KERNEL_MODE_TRAP';       Cause = 'CPU trap the kernel failed to catch. Can indicate hardware failure or overheating.' }
    0x0000009F = @{ Name = 'DRIVER_POWER_STATE_FAILURE';        Cause = 'A driver is in an inconsistent or invalid power state. Very common cause of sleep/wake crashes.' }
    0x000000A0 = @{ Name = 'INTERNAL_POWER_ERROR';              Cause = 'Fatal error in the Windows power policy manager. Often related to sleep/hibernate transitions.' }
    0x000000BE = @{ Name = 'ATTEMPTED_WRITE_TO_READONLY_MEMORY'; Cause = 'A driver attempted to write to read-only memory. Faulty or incompatible driver.' }
    0x000000C2 = @{ Name = 'BAD_POOL_CALLER';                   Cause = 'A kernel-mode process made a bad pool request. Often driver or software issue.' }
    0x000000D1 = @{ Name = 'DRIVER_IRQL_NOT_LESS_OR_EQUAL';     Cause = 'A driver accessed paged memory at too high an IRQL. Very common driver bug, especially NIC/Wi-Fi.' }
    0x000000EF = @{ Name = 'CRITICAL_PROCESS_DIED';             Cause = 'A critical system process terminated unexpectedly. Can be caused by corrupted system files.' }
    0x000000F4 = @{ Name = 'CRITICAL_OBJECT_TERMINATION';       Cause = 'A critical system object was terminated. Possible disk or driver issue.' }
    0x00000116 = @{ Name = 'VIDEO_TDR_FAILURE';                 Cause = 'The display driver failed to respond in time. GPU driver crash — update or roll back GPU drivers.' }
    0x00000124 = @{ Name = 'WHEA_UNCORRECTABLE_ERROR';          Cause = 'Hardware error detected (CPU, RAM, or bus). May indicate failing hardware or overclocking issues.' }
    0x00000133 = @{ Name = 'DPC_WATCHDOG_VIOLATION';            Cause = 'A DPC routine ran too long. Often caused by storage drivers (SSD firmware) or NIC drivers.' }
    0x0000013A = @{ Name = 'KERNEL_MODE_HEAP_CORRUPTION';       Cause = 'Kernel heap corruption detected. Usually a driver bug.' }
    0x00000154 = @{ Name = 'UNEXPECTED_STORE_EXCEPTION';        Cause = 'Store component caught an unexpected exception. Often disk-related — check drive health.' }
    0x000001CA = @{ Name = 'SYNTHETIC_WATCHDOG_TIMEOUT';        Cause = 'The system did not respond in time. Can be caused by overloaded storage or misbehaving driver.' }
    0x00000019 = @{ Name = 'BAD_POOL_HEADER';                   Cause = 'Pool header corruption. Often caused by a driver writing out of bounds — faulty driver or bad RAM.' }
}

# ============================================================
# INSTALL / UNINSTALL
# ============================================================
if ($Install) {
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error 'The -Install switch requires an elevated (Administrator) PowerShell session.'
        exit 1
    }

    # Remove existing task first (idempotent — no duplicates)
    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($existing) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "Removed existing '$TaskName' scheduled task."
    }

    $scriptPath = $MyInvocation.MyCommand.Definition
    $action  = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -RunLevel Highest -LogonType Interactive
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 10)

    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
        -Principal $principal -Settings $settings -Description 'Monitors for abnormal Windows shutdowns and diagnoses root causes.' | Out-Null

    Write-Host "Scheduled task '$TaskName' registered successfully."
    Write-Host "It will run at every logon as $env:USERNAME (elevated)."
    exit 0
}

if ($Uninstall) {
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error 'The -Uninstall switch requires an elevated (Administrator) PowerShell session.'
        exit 1
    }
    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($existing) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "Scheduled task '$TaskName' removed."
    } else {
        Write-Host "No scheduled task named '$TaskName' found."
    }
    exit 0
}

# ============================================================
# HELPER FUNCTIONS
# ============================================================

function Get-MonitorState {
    if (Test-Path $StateFile) {
        try { return Get-Content $StateFile -Raw | ConvertFrom-Json }
        catch { return $null }
    }
    return $null
}

function Save-MonitorState {
    param([hashtable]$State)
    $State | ConvertTo-Json | Set-Content -Path $StateFile -Force
}

function Get-BootTime {
    return (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
}

function Get-EventsSince {
    param(
        [string]$LogName,
        [int[]]$EventIds,
        [datetime]$After,
        [string]$ProviderName = $null,
        [int]$MaxEvents = 50
    )
    $filter = @{ LogName = $LogName; Id = $EventIds; StartTime = $After.AddDays(-7); EndTime = $After.AddMinutes(5) }
    if ($ProviderName) { $filter['ProviderName'] = $ProviderName }
    try {
        Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
    } catch { @() }
}

function Get-RecentErrorEvents {
    param([datetime]$Before, [int]$Count = 15)
    try {
        Get-WinEvent -FilterHashtable @{
            LogName  = 'System'
            Level    = @(1, 2)  # Critical, Error
            EndTime  = $Before
            StartTime = $Before.AddHours(-24)
        } -MaxEvents $Count -ErrorAction SilentlyContinue
    } catch { @() }
}

function Format-BugcheckCode {
    param([long]$Code)
    '0x{0:X8}' -f $Code
}

function Get-BugcheckInfo {
    param([long]$Code)
    $entry = $BugcheckMap[[int]$Code]
    if ($entry) { return $entry }
    return @{ Name = 'UNKNOWN_BUGCHECK'; Cause = "Bugcheck code $(Format-BugcheckCode $Code) is not in the common-codes database." }
}

function Get-LastWakeSource {
    try {
        $output = & powercfg /lastwake 2>&1 | Out-String
        return $output.Trim()
    } catch { return 'Unable to retrieve last wake source.' }
}

function Get-MinidumpFiles {
    param([datetime]$Around)
    $dumpDir = "$env:SystemRoot\Minidump"
    if (-not (Test-Path $dumpDir)) { return @() }
    Get-ChildItem $dumpDir -Filter '*.dmp' -ErrorAction SilentlyContinue |
        Where-Object { [Math]::Abs(($_.LastWriteTime - $Around).TotalHours) -lt 24 } |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 5
}

function Get-PowerConfig {
    $info = @{}
    try {
        # Fast Startup
        $hibernate = & powercfg /a 2>&1 | Out-String
        $info['AvailableSleepStates'] = $hibernate.Trim()

        $hiberReg = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name 'HiberbootEnabled' -ErrorAction SilentlyContinue
        $info['FastStartupEnabled'] = if ($hiberReg -and $hiberReg.HiberbootEnabled -eq 1) { $true } else { $false }

        # Hybrid Sleep — read active power scheme
        $schemeOutput = & powercfg /getactivescheme 2>&1 | Out-String
        if ($schemeOutput -match '([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})') {
            $schemeGuid = $Matches[1]
            # Sleep subgroup = 238c9fa8-..., Hybrid Sleep = 94ac6d29-...
            $hybridOutput = & powercfg /query $schemeGuid 238c9fa8-0aab-4681-95f7-8bb9d0d6aa2d 94ac6d29-73ce-41a6-809f-6363ba21b47e 2>&1 | Out-String
            $info['HybridSleepSetting'] = $hybridOutput.Trim()
        }

        # Wake Timers
        $wakeOutput = & powercfg /query $schemeGuid 238c9fa8-0aab-4681-95f7-8bb9d0d6aa2d bd3b718a-0680-4d9d-8ab2-e1d2b4ac806d 2>&1 | Out-String
        $info['WakeTimersSetting'] = $wakeOutput.Trim()
    } catch {}
    return $info
}

function Refresh-DriverSnapshot {
    $lines = @()
    $lines += "Driver Snapshot — Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $lines += '=' * 60

    $categories = @(
        @{ Name = 'Display / GPU';  Class = 'Display' },
        @{ Name = 'Network';        Class = 'Net' },
        @{ Name = 'USB Controllers'; Class = 'USB' },
        @{ Name = 'System Devices (Chipset)'; Class = 'System' },
        @{ Name = 'Storage Controllers'; Class = 'SCSIAdapter' },
        @{ Name = 'Audio';           Class = 'Media' }
    )

    foreach ($cat in $categories) {
        $lines += ''
        $lines += "--- $($cat.Name) ---"
        try {
            $drivers = Get-CimInstance Win32_PnPSignedDriver -Filter "DeviceClass='$($cat.Class)'" -ErrorAction SilentlyContinue |
                Where-Object { $_.DeviceName } |
                Select-Object DeviceName, DriverVersion, DriverDate, Manufacturer
            if ($drivers) {
                foreach ($d in $drivers) {
                    $dateStr = if ($d.DriverDate) { $d.DriverDate.ToString('yyyy-MM-dd') } else { 'N/A' }
                    $lines += "  $($d.DeviceName)"
                    $lines += "    Version: $($d.DriverVersion)  Date: $dateStr  Manufacturer: $($d.Manufacturer)"
                }
            } else {
                $lines += "  (no drivers found in this category)"
            }
        } catch {
            $lines += "  (error querying this category)"
        }
    }

    $lines | Set-Content -Path $DriverFile -Force
}

function Refresh-SleepStudy {
    try {
        & powercfg /sleepstudy /output $SleepStudyFile 2>&1 | Out-Null
    } catch {}
}

function Refresh-Recommendations {
    $lines = @()
    $lines += "Power Configuration Audit — Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $lines += '=' * 60
    $lines += ''

    $config = Get-PowerConfig
    $issues = @()

    # Fast Startup
    if ($config['FastStartupEnabled']) {
        $issues += @{
            Issue = 'Fast Startup is ENABLED'
            Detail = 'Fast Startup (Hybrid Boot) saves a hibernation image at shutdown. This is a leading cause of sleep/wake instability, especially with driver incompatibilities.'
            Fix = 'To disable: Run as Admin: powercfg /h off'
        }
    }

    # Hybrid Sleep
    if ($config['HybridSleepSetting'] -and $config['HybridSleepSetting'] -match 'Current.*Setting.*:\s*0x0*1') {
        $issues += @{
            Issue = 'Hybrid Sleep is ENABLED'
            Detail = 'Hybrid Sleep combines sleep + hibernate. If the hibernate image becomes corrupted, Windows may fail to resume and force a cold shutdown.'
            Fix = 'To disable: Power Options > Change plan settings > Change advanced > Sleep > Allow hybrid sleep > Off'
        }
    }

    # Wake Timers
    if ($config['WakeTimersSetting'] -and $config['WakeTimersSetting'] -match 'Current.*Setting.*:\s*0x0*1') {
        $issues += @{
            Issue = 'Wake Timers are ENABLED'
            Detail = 'Wake timers allow scheduled tasks and Windows Update to wake the PC from sleep. If a woken PC encounters a driver issue or overheats, it may crash.'
            Fix = 'To disable: Power Options > Change plan settings > Change advanced > Sleep > Allow wake timers > Disable'
        }
    }

    if ($issues.Count -eq 0) {
        $lines += 'No concerning power configuration issues found.'
        $lines += ''
        $lines += 'Current settings look reasonable. If you are still experiencing'
        $lines += 'unexpected shutdowns after sleep, the issue is likely driver-related.'
    } else {
        $lines += "Found $($issues.Count) potential issue(s):"
        $lines += ''
        foreach ($issue in $issues) {
            $lines += ">> $($issue.Issue)"
            $lines += "   $($issue.Detail)"
            $lines += "   FIX: $($issue.Fix)"
            $lines += ''
        }
    }

    $lines += ''
    $lines += '--- Available Sleep States ---'
    if ($config['AvailableSleepStates']) {
        $lines += $config['AvailableSleepStates']
    }

    $lines | Set-Content -Path $RecommendFile -Force
}

function Get-TrendSummary {
    if (-not (Test-Path $ShutdownLog)) { return $null }
    $content = Get-Content $ShutdownLog -Raw
    # Parse timestamps from log entries
    $pattern = '===\s+ABNORMAL SHUTDOWN DETECTED\s+—\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+==='
    $matches_ = [regex]::Matches($content, $pattern)
    if ($matches_.Count -lt 3) { return $null }

    $timestamps = $matches_ | ForEach-Object {
        [datetime]::ParseExact($_.Groups[1].Value, 'yyyy-MM-dd HH:mm:ss', $null)
    }

    $lines = @()
    $lines += ''
    $lines += '--- TREND SUMMARY (from prior incidents) ---'
    $lines += "Total recorded abnormal shutdowns: $($timestamps.Count)"

    # Frequency
    $firstDt = $timestamps | Sort-Object | Select-Object -First 1
    $lastDt  = $timestamps | Sort-Object | Select-Object -Last 1
    $spanDays = [Math]::Max(1, ($lastDt - $firstDt).TotalDays)
    $freqPerWeek = [Math]::Round($timestamps.Count / ($spanDays / 7), 1)
    $lines += "Frequency: ~$freqPerWeek per week (over $([Math]::Round($spanDays)) days)"

    # Time-of-day clustering
    $hourGroups = $timestamps | Group-Object { $_.Hour } | Sort-Object Count -Descending | Select-Object -First 3
    $lines += 'Most common hours of occurrence:'
    foreach ($g in $hourGroups) {
        $lines += "  $($g.Name):00 — $($g.Count) occurrence(s)"
    }

    # Recurring bugcheck codes
    $codePattern = 'Bugcheck Code:\s*(0x[0-9A-Fa-f]+)'
    $codeMatches = [regex]::Matches($content, $codePattern)
    if ($codeMatches.Count -gt 0) {
        $codeGroups = $codeMatches | ForEach-Object { $_.Groups[1].Value } |
            Group-Object | Sort-Object Count -Descending | Select-Object -First 5
        $lines += 'Recurring bugcheck codes:'
        foreach ($g in $codeGroups) {
            $bc = $BugcheckMap[[int]$g.Name]
            $name = if ($bc) { $bc.Name } else { 'UNKNOWN' }
            $lines += "  $($g.Name) ($name) — $($g.Count) time(s)"
        }
    }

    # Recurring wake sources
    $wakePattern = 'Last Wake Source:[\r\n]+([\s\S]*?)(?=\r?\n\r?\n|\r?\n---|\r?\n===|$)'
    $wakeMatches = [regex]::Matches($content, $wakePattern)
    if ($wakeMatches.Count -gt 0) {
        $wakeSources = $wakeMatches | ForEach-Object { $_.Groups[1].Value.Trim() } |
            Group-Object | Sort-Object Count -Descending | Select-Object -First 3
        $lines += 'Recurring wake sources:'
        foreach ($g in $wakeSources) {
            $lines += "  [$($g.Count)x] $($g.Name)"
        }
    }

    return ($lines -join "`r`n")
}

# ============================================================
# MAIN LOGIC
# ============================================================

# Ensure output directory exists
if (-not (Test-Path $ScriptDir)) { New-Item -Path $ScriptDir -ItemType Directory -Force | Out-Null }

$bootTime = Get-BootTime
$now = Get-Date

# ----- Periodic Tasks (every 21 days) -----
$state = Get-MonitorState
$runPeriodic = $false

if (-not $state -or -not $state.LastPeriodicRun) {
    $runPeriodic = $true
} else {
    $lastPeriodic = [datetime]::Parse($state.LastPeriodicRun)
    if (($now - $lastPeriodic).TotalDays -ge $PeriodicDays) {
        $runPeriodic = $true
    }
}

if ($runPeriodic) {
    Refresh-SleepStudy
    Refresh-DriverSnapshot
    Refresh-Recommendations
    $stateData = @{ LastPeriodicRun = $now.ToString('o') }
    Save-MonitorState $stateData
}

# ----- Shutdown Detection -----
# Look for clean shutdown (Event 1074) vs abnormal (6008, Kernel-Power 41)
# Only consider events between (bootTime - 7 days) and bootTime (the prior session)

$cleanEvents = Get-EventsSince -LogName 'System' -EventIds @(1074) -After $bootTime -MaxEvents 5
$abnormal6008 = Get-EventsSince -LogName 'System' -EventIds @(6008) -After $bootTime -ProviderName 'EventLog' -MaxEvents 5
$kernelPower41 = Get-EventsSince -LogName 'System' -EventIds @(41) -After $bootTime -ProviderName 'Microsoft-Windows-Kernel-Power' -MaxEvents 5

# Filter: only events from BEFORE this boot (i.e., about the prior session)
$abnormal6008   = $abnormal6008   | Where-Object { $_.TimeCreated -le $bootTime.AddMinutes(2) -and $_.TimeCreated -ge $bootTime.AddDays(-7) }
$kernelPower41  = $kernelPower41  | Where-Object { $_.TimeCreated -le $bootTime.AddMinutes(2) -and $_.TimeCreated -ge $bootTime.AddDays(-7) }
$cleanEvents    = $cleanEvents    | Where-Object { $_.TimeCreated -le $bootTime.AddMinutes(2) -and $_.TimeCreated -ge $bootTime.AddDays(-7) }

# If there's a clean shutdown event MORE RECENT than any abnormal event, consider it normal
$lastCleanTime = if ($cleanEvents) { ($cleanEvents | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated } else { [datetime]::MinValue }
$lastAbnormalTime = [datetime]::MinValue
if ($abnormal6008) {
    $t = ($abnormal6008 | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated
    if ($t -gt $lastAbnormalTime) { $lastAbnormalTime = $t }
}
if ($kernelPower41) {
    $t = ($kernelPower41 | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated
    if ($t -gt $lastAbnormalTime) { $lastAbnormalTime = $t }
}

if ($lastAbnormalTime -eq [datetime]::MinValue) {
    # No abnormal shutdown detected
    exit 0
}

if ($lastCleanTime -gt $lastAbnormalTime) {
    # Most recent event was a clean shutdown — normal
    exit 0
}

# ============================================================
# ABNORMAL SHUTDOWN DETECTED — DIAGNOSE
# ============================================================

$report = @()
$timestamp = $now.ToString('yyyy-MM-dd HH:mm:ss')
$report += ''
$report += ('=' * 70)
$report += "=== ABNORMAL SHUTDOWN DETECTED — $timestamp ==="
$report += ('=' * 70)
$report += ''

$conclusive = $false
$rootCause = ''
$fixSuggestions = @()

# --- Parse Kernel-Power 41 details ---
$kp41 = $kernelPower41 | Sort-Object TimeCreated -Descending | Select-Object -First 1
$bugcheckCode = 0
$sleepInProgress = $false

if ($kp41) {
    $report += "Event: Kernel-Power 41 at $($kp41.TimeCreated)"
    $report += "Message: $($kp41.Message)"
    $report += ''

    # Extract properties from the event XML
    try {
        $xml = [xml]$kp41.ToXml()
        $eventData = $xml.Event.EventData.Data
        foreach ($d in $eventData) {
            switch ($d.Name) {
                'BugcheckCode'       { $bugcheckCode = [long]$d.'#text' }
                'SleepInProgress'    { $sleepInProgress = $d.'#text' -eq '6' -or $d.'#text' -eq 'true' }
                'PowerButtonTimestamp' {
                    if ($d.'#text' -and $d.'#text' -ne '0') {
                        $report += "Power Button Timestamp: $($d.'#text')"
                    }
                }
            }
            $report += "  $($d.Name): $($d.'#text')"
        }
    } catch {
        $report += '  (Could not parse Kernel-Power 41 event data)'
    }
    $report += ''
}

# --- Parse BSOD/BugCheck event (Event 1001, BugCheck) ---
$bugcheckEvent = $null
try {
    $bugcheckEvent = Get-WinEvent -FilterHashtable @{
        LogName      = 'System'
        ProviderName = 'Microsoft-Windows-WER-SystemErrorReporting'
        Id           = 1001
        StartTime    = $bootTime.AddDays(-7)
        EndTime      = $bootTime.AddMinutes(5)
    } -MaxEvents 3 -ErrorAction SilentlyContinue |
        Where-Object { $_.TimeCreated -ge $bootTime.AddDays(-7) } |
        Sort-Object TimeCreated -Descending |
        Select-Object -First 1
} catch {}

$faultingDriver = ''
if ($bugcheckEvent) {
    $report += "Event: BugCheck (WER 1001) at $($bugcheckEvent.TimeCreated)"
    $report += "Message: $($bugcheckEvent.Message)"
    $report += ''
    if ($bugcheckEvent.Message -match '(?i)image\s+name:\s*(\S+)') {
        $faultingDriver = $Matches[1]
    }
    if ($bugcheckEvent.Message -match '(?i)bug\s*check\s*code:\s*(0x[0-9a-fA-F]+)') {
        $eventBugcheck = [long]$Matches[1]
        if ($eventBugcheck -ne 0 -and $bugcheckCode -eq 0) {
            $bugcheckCode = $eventBugcheck
        }
    }
}

# --- Event 6008 details ---
$ev6008 = $abnormal6008 | Sort-Object TimeCreated -Descending | Select-Object -First 1
if ($ev6008) {
    $report += "Event: EventLog 6008 at $($ev6008.TimeCreated)"
    $report += "Message: $($ev6008.Message)"
    $report += ''
}

# --- Sleep/Wake context ---
$sleepEvent = Get-EventsSince -LogName 'System' -EventIds @(42) -After $bootTime -ProviderName 'Microsoft-Windows-Kernel-Power' -MaxEvents 3
$wakeEvent  = Get-EventsSince -LogName 'System' -EventIds @(107) -After $bootTime -ProviderName 'Microsoft-Windows-Kernel-Power' -MaxEvents 3

if ($sleepEvent) {
    $lastSleep = $sleepEvent | Sort-Object TimeCreated -Descending | Select-Object -First 1
    $report += "Last Sleep Entry: $($lastSleep.TimeCreated) — $($lastSleep.Message)"
}
if ($wakeEvent) {
    $lastWake = $wakeEvent | Sort-Object TimeCreated -Descending | Select-Object -First 1
    $report += "Last Wake (Event 107): $($lastWake.TimeCreated) — $($lastWake.Message)"
}
$report += ''

# --- Last Wake Source ---
$wakeSource = Get-LastWakeSource
$report += 'Last Wake Source:'
$report += $wakeSource
$report += ''

# --- Recent errors before crash ---
$recentErrors = Get-RecentErrorEvents -Before $bootTime
if ($recentErrors) {
    $report += '--- Recent System Errors/Critical Events (24h before crash) ---'
    foreach ($ev in $recentErrors) {
        $report += "  [$($ev.TimeCreated)] ID:$($ev.Id) Source:$($ev.ProviderName) — $($ev.Message)"
    }
    $report += ''
}

# --- Minidump files ---
$dumps = Get-MinidumpFiles -Around $bootTime
if ($dumps) {
    $report += '--- Minidump Files Found ---'
    foreach ($d in $dumps) {
        $report += "  $($d.FullName)  ($($d.LastWriteTime))  Size: $([Math]::Round($d.Length/1KB, 1)) KB"
    }
    $report += ''
} else {
    $report += '(No minidump files found near the crash time.)'
    $report += ''
}

# ============================================================
# DETERMINE ROOT CAUSE
# ============================================================

if ($bugcheckCode -ne 0) {
    # --- CONCLUSIVE: BSOD with known code ---
    $conclusive = $true
    $bcInfo = Get-BugcheckInfo $bugcheckCode
    $bcHex  = Format-BugcheckCode $bugcheckCode

    $rootCause = "Your computer crashed with a Blue Screen of Death (BSOD).`r`n"
    $rootCause += "Bugcheck Code: $bcHex ($($bcInfo.Name))`r`n"
    $rootCause += "Explanation: $($bcInfo.Cause)`r`n"

    if ($faultingDriver) {
        $rootCause += "Faulting Driver: $faultingDriver`r`n"
        $rootCause += "This driver was directly involved in the crash. Consider updating, rolling back, or reinstalling it.`r`n"
    }

    if ($sleepInProgress) {
        $rootCause += "`r`nNote: The system was in the process of sleeping when the crash occurred.`r`n"
        $rootCause += "This strongly suggests a driver that cannot handle power state transitions properly.`r`n"
    }

    # Auto-fix suggestions
    switch -Wildcard ($bcInfo.Name) {
        'DRIVER_POWER_STATE_FAILURE' {
            $fixSuggestions += 'UPDATE your GPU, Wi-Fi, and chipset drivers to the latest versions from the manufacturer (not Windows Update).'
            if ($faultingDriver) {
                $fixSuggestions += "SPECIFICALLY: Update or rollback the driver '$faultingDriver'."
                $fixSuggestions += "Run as Admin: powercfg /requestsoverride DRIVER `"$faultingDriver`" SYSTEM"
            }
            $fixSuggestions += 'DISABLE Fast Startup: Run as Admin: powercfg /h off'
            $fixSuggestions += 'DISABLE Hybrid Sleep: Power Options > Advanced > Sleep > Allow hybrid sleep > Off'
        }
        'INTERNAL_POWER_ERROR' {
            $fixSuggestions += 'UPDATE all drivers, especially GPU and chipset.'
            $fixSuggestions += 'DISABLE Fast Startup: Run as Admin: powercfg /h off'
            $fixSuggestions += 'Run: sfc /scannow  and  DISM /Online /Cleanup-Image /RestoreHealth'
        }
        'VIDEO_TDR_FAILURE' {
            $fixSuggestions += 'UPDATE your GPU driver to the latest version from NVIDIA/AMD/Intel.'
            $fixSuggestions += 'If already latest, try ROLLING BACK to a previous GPU driver version.'
            $fixSuggestions += 'Check GPU temperatures — overheating can cause TDR failures.'
        }
        'DRIVER_IRQL_NOT_LESS_OR_EQUAL' {
            $fixSuggestions += 'A driver is accessing memory incorrectly.'
            if ($faultingDriver) {
                $fixSuggestions += "UPDATE or REINSTALL: $faultingDriver"
            }
            $fixSuggestions += 'Common culprits: Wi-Fi drivers, VPN software, antivirus kernel drivers.'
        }
        'WHEA_UNCORRECTABLE_ERROR' {
            $fixSuggestions += 'This is typically a HARDWARE error. Check:'
            $fixSuggestions += '  - CPU: Disable any overclocking. Check temperatures.'
            $fixSuggestions += '  - RAM: Run Windows Memory Diagnostic (mdsched.exe).'
            $fixSuggestions += '  - Motherboard: Update BIOS/UEFI firmware.'
        }
        'DPC_WATCHDOG_VIOLATION' {
            $fixSuggestions += 'UPDATE your SSD firmware and storage controller (AHCI/NVMe) drivers.'
            $fixSuggestions += 'UPDATE network adapter drivers.'
            $fixSuggestions += 'Check for BIOS updates from your PC/motherboard manufacturer.'
        }
        'CRITICAL_PROCESS_DIED' {
            $fixSuggestions += 'Run: sfc /scannow  to check for corrupted system files.'
            $fixSuggestions += 'Run: DISM /Online /Cleanup-Image /RestoreHealth'
            $fixSuggestions += 'Consider whether recently installed software could be interfering.'
        }
        default {
            if ($faultingDriver) {
                $fixSuggestions += "UPDATE or REINSTALL the faulting driver: $faultingDriver"
            }
            $fixSuggestions += 'Run: sfc /scannow  and  DISM /Online /Cleanup-Image /RestoreHealth'
            $fixSuggestions += 'Update all drivers from manufacturer websites.'
        }
    }

} else {
    # --- INCONCLUSIVE: No BSOD code ---
    $conclusive = $false
}

# ============================================================
# BUILD OUTPUT
# ============================================================

if ($conclusive) {
    $report += '============================================'
    $report += 'ROOT CAUSE (Conclusive)'
    $report += '============================================'
    $report += ''
    $report += $rootCause

    if ($fixSuggestions.Count -gt 0) {
        $report += ''
        $report += '--- SUGGESTED FIXES ---'
        foreach ($fix in $fixSuggestions) {
            $report += "  * $fix"
        }
    }

    # Include sleep study reference if available
    if (Test-Path $SleepStudyFile) {
        $report += ''
        $report += "For detailed sleep/wake transition analysis, open: $SleepStudyFile"
    }

} else {
    # --- Build AI Prompt ---
    $report += '============================================'
    $report += 'COULD NOT DETERMINE A SPECIFIC ROOT CAUSE'
    $report += '============================================'
    $report += ''
    $report += 'A specific BSOD code was not found (bugcheck code was 0 or absent).'
    $report += 'This often means Windows lost power abruptly (hardware, PSU, overheating,'
    $report += 'or a driver froze the system without generating a formal BSOD).'
    $report += ''
    $report += 'Below is a prompt you can provide to an AI assistant for deeper analysis.'
    $report += ''
    $report += '╔══════════════════════════════════════════════════════════════════╗'
    $report += '║                    AI ANALYSIS PROMPT                           ║'
    $report += '╚══════════════════════════════════════════════════════════════════╝'
    $report += ''
    $report += 'I am experiencing unexpected shutdowns on my Windows PC, typically'
    $report += 'after putting it to sleep. Windows does not generate a BSOD code.'
    $report += 'Please analyze the following diagnostic data and help me identify'
    $report += 'the root cause and suggest specific fixes.'
    $report += ''
    $report += '--- SYSTEM INFO ---'
    try {
        $os = Get-CimInstance Win32_OperatingSystem
        $cs = Get-CimInstance Win32_ComputerSystem
        $report += "OS: $($os.Caption) Build $($os.BuildNumber)"
        $report += "Computer: $($cs.Manufacturer) $($cs.Model)"
        $report += "RAM: $([Math]::Round($cs.TotalPhysicalMemory / 1GB, 1)) GB"
    } catch {
        $report += '(Could not retrieve system info)'
    }
    $report += "Boot Time: $bootTime"
    $report += ''

    if ($sleepInProgress) {
        $report += '** The system was in the process of SLEEPING when the crash occurred. **'
        $report += ''
    }

    # Include driver snapshot if available
    if (Test-Path $DriverFile) {
        $report += '--- DRIVER SNAPSHOT ---'
        $report += "(Captured on: see file for date. May be up to $PeriodicDays days old.)"
        $report += (Get-Content $DriverFile -Raw)
        $report += ''
    }

    # Include sleep study reference
    if (Test-Path $SleepStudyFile) {
        $report += "--- SLEEP STUDY ---"
        $report += "A detailed sleep study HTML report is available at: $SleepStudyFile"
        $report += "Please ask me to share its contents if you need the details."
        $report += ''
    }

    # Include power config
    $report += '--- POWER CONFIGURATION ---'
    $config = Get-PowerConfig
    foreach ($key in $config.Keys) {
        $report += "${key}: $($config[$key])"
        $report += ''
    }

    # Include recommendations file reference
    if (Test-Path $RecommendFile) {
        $report += '--- POWER CONFIG AUDIT ---'
        $report += (Get-Content $RecommendFile -Raw)
        $report += ''
    }

    $report += '--- QUESTIONS FOR ANALYSIS ---'
    $report += '1. Based on the event log data above, what is the most likely cause of'
    $report += '   the unexpected shutdown?'
    $report += '2. Given that SleepInProgress flag and the wake/sleep events, is this'
    $report += '   likely a driver issue during S3 sleep transition?'
    $report += '3. Which specific drivers should I update or investigate?'
    $report += '4. Are there any power configuration changes I should make?'
    $report += '5. Should I run any additional diagnostics (memtest, disk check, etc.)?'
    $report += '6. Is there a pattern in the timestamps or error sources that points'
    $report += '   to a specific component?'
}

# --- Trend Summary ---
$trend = Get-TrendSummary
if ($trend) {
    $report += ''
    $report += $trend
}

$report += ''
$report += ('-' * 70)

# ============================================================
# WRITE AND OPEN
# ============================================================

$report | Out-File -FilePath $ShutdownLog -Append -Encoding UTF8

# Open the file for the user
Start-Process notepad.exe $ShutdownLog

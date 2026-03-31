# Windows Shutdown Monitor

A PowerShell tool that automatically detects abnormal Windows shutdowns (especially after sleep), diagnoses the root cause, and logs findings for review or AI-assisted analysis.

## Problem

Windows sometimes force-shuts-down after being put to sleep instead of resuming normally. This tool runs silently at every logon and, when it detects an abnormal shutdown, tells you exactly what happened.

## How It Works

1. **At every logon**, the script checks Windows Event Logs for shutdown indicators:
   - **Event 1074** (clean shutdown/restart) → exits silently
   - **Event 6008** / **Kernel-Power 41** (abnormal shutdown) → begins diagnosis

2. **If the shutdown was abnormal**, it gathers:
   - Kernel-Power 41 properties (BugcheckCode, SleepInProgress, etc.)
   - BSOD details from Windows Error Reporting (Event 1001)
   - Sleep/wake transition events
   - Last wake source (`powercfg /lastwake`)
   - Recent critical/error events from the System log
   - Minidump file locations

3. **Determines the root cause**:
   - **Conclusive** (e.g., BSOD with a known bugcheck code): outputs a plain-English explanation with the crash name, faulting driver, and actionable fix suggestions
   - **Inconclusive** (no BSOD code, e.g., abrupt power loss during sleep): generates a structured AI prompt containing all diagnostic data, driver versions, power configuration, and trend analysis — ready to paste into an AI assistant

4. **Appends the report** (with timestamp) to `lastShutDown.txt` and opens it in Notepad.

## Periodic Tasks (Every 21 Days)

To avoid slowing down every boot, the following are refreshed once every 21 days:

| Task | Output File | Description |
|------|-------------|-------------|
| Sleep Study | `sleepStudy.html` | Detailed sleep/wake transition report via `powercfg /sleepstudy` |
| Driver Snapshot | `driverSnapshot.txt` | GPU, network, USB, chipset, storage, and audio driver versions |
| Power Config Audit | `generalRecommendations.txt` | Checks for risky settings (Fast Startup, Hybrid Sleep, Wake Timers) with fix instructions |

All three files are **overwritten** on each refresh (not appended).

## Features

- **BSOD code mapping** — ~20 common bugcheck codes mapped to human-readable names and typical causes, with emphasis on sleep-related crashes
- **Auto-fix suggestions** — for known root causes (e.g., `DRIVER_POWER_STATE_FAILURE` → update specific driver, disable Fast Startup)
- **Trend analysis** — after 3+ incidents, includes frequency, time-of-day clustering, recurring bugcheck codes, and recurring wake sources
- **AI prompt generation** — when root cause is inconclusive, generates a comprehensive prompt with all gathered data for AI analysis
- **Idempotent installation** — re-running `-Install` replaces the existing scheduled task (no duplicates)

## Installation

Open an **elevated** (Run as Administrator) PowerShell window:

```powershell
C:\workspace\personal\windowsShutDown\ShutdownMonitor.ps1 -Install
```

This registers a scheduled task called `ShutdownMonitor` that runs at logon with elevated privileges and a hidden window. No UAC prompt will appear at login.

Verify it's installed:

```powershell
Get-ScheduledTask -TaskName "ShutdownMonitor"
```

## Uninstallation

```powershell
C:\workspace\personal\windowsShutDown\ShutdownMonitor.ps1 -Uninstall
```

## Output Files

| File | Behavior | Purpose |
|------|----------|---------|
| `lastShutDown.txt` | Appended (timestamped) | Abnormal shutdown reports — diagnosis or AI prompt |
| `generalRecommendations.txt` | Overwritten every 21 days | Power configuration audit and recommendations |
| `driverSnapshot.txt` | Overwritten every 21 days | Installed driver versions for key hardware categories |
| `sleepStudy.html` | Overwritten every 21 days | Microsoft sleep study report |
| `.monitorState.json` | Internal | Tracks when periodic tasks last ran |

## Requirements

- Windows 10 / 11
- PowerShell 5.1+
- Administrator privileges (for installation and event log access)

## Manual Test Run

To test without waiting for an abnormal shutdown, run the script directly in an elevated PowerShell:

```powershell
C:\workspace\personal\windowsShutDown\ShutdownMonitor.ps1
```

If the last shutdown was normal, it exits silently. If abnormal, it produces the report.

# SentinelThreatintelligenceScripts

A community PowerShell toolkit for managing **Microsoft Sentinel Threat Intelligence indicators** via the Azure REST API.

---

## Overview

This repository provides scripts to list and bulk-delete threat intelligence (TI) indicators from a Microsoft Sentinel workspace. It is designed for security engineers and SOC teams who need to clean up stale or unwanted indicators at scale.

---

## Scripts

| Script | Description |
|--------|-------------|
| `Scripts\delete-SentinelThreatIntelligence.ps1` | Contains the `Remove-SentinelThreatIndicator` function. Dot-source this file to load the function. |
| `Scripts\Invoke-DeleteSentinelThreatIntelligence.ps1` | Caller script. Edit the configuration block at the top and run this file. |

---

## Prerequisites

| Requirement | Details |
|-------------|---------|
| PowerShell | 5.1 or later. PowerShell 7+ recommended for parallel deletes. |
| Az.Accounts module | `Install-Module Az.Accounts` |
| Azure RBAC | **Microsoft Sentinel Contributor** (or equivalent) on the target workspace. |

---

## Quick Start

1. **Install the required module** (if not already installed):

   ```powershell
   Install-Module Az.Accounts -Scope CurrentUser
   ```

2. **Sign in to Azure:**

   ```powershell
   Connect-AzAccount
   ```

3. **Edit the configuration** in `Invoke-DeleteSentinelThreatIntelligence.ps1`:

   ```powershell
   $SubscriptionId    = "<your-subscription-id>"
   $ResourceGroupName = "<your-resource-group>"
   $WorkspaceName     = "<your-workspace-name>"
   $SourceFilter      = "ThreatViewIPBlockList"  # leave "" to target ALL sources
   $ListOnly          = $false                    # $true = list only, no deletion
   $BatchSize         = 1000
   $ThrottleLimit     = 5                         # parallel threads (PS 7+ only)
   $Force             = $false                    # $true = skip confirmation prompt
   $LogFile           = ""                        # leave "" to use default log location
   ```

4. **Run the caller script:**

   ```powershell
   .\Scripts\Invoke-DeleteSentinelThreatIntelligence.ps1
   ```

---

## Parameters — `Remove-SentinelThreatIndicator`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `SubscriptionId` | String | Yes | Azure subscription ID containing the Sentinel workspace. |
| `ResourceGroupName` | String | Yes | Resource group name of the workspace. |
| `WorkspaceName` | String | Yes | Log Analytics workspace name linked to Microsoft Sentinel. |
| `SourceFilter` | String | No | Filter by source name. Leave empty to target all sources. |
| `PageSize` | Int | No | Indicators per API page. Defaults to `100`. |
| `ListOnly` | Bool | No | When `$true`, lists indicators without deleting. |
| `ThrottleLimit` | Int | No | Max concurrent DELETE threads. PS 7+ only; ignored on PS 5. |
| `Force` | Switch | No | Skips the interactive deletion confirmation prompt. |
| `LogFile` | String | No | Path to log file. Defaults to `Remove-SentinelThreatIndicator.log` in the script folder. |

---

## Usage Examples

**List all indicators for a specific source (no deletion):**

```powershell
Remove-SentinelThreatIndicator `
    -SubscriptionId    "<sub-id>" `
    -ResourceGroupName "<rg>" `
    -WorkspaceName     "<workspace>" `
    -SourceFilter      "ThreatViewIPBlockList" `
    -ListOnly          $true
```

**Delete indicators from a specific source with confirmation prompt:**

```powershell
Remove-SentinelThreatIndicator `
    -SubscriptionId    "<sub-id>" `
    -ResourceGroupName "<rg>" `
    -WorkspaceName     "<workspace>" `
    -SourceFilter      "ThreatViewIPBlockList"
```

**Delete all indicators from all sources, skip confirmation (unattended/automation):**

```powershell
Remove-SentinelThreatIndicator `
    -SubscriptionId    "<sub-id>" `
    -ResourceGroupName "<rg>" `
    -WorkspaceName     "<workspace>" `
    -Force
```

---

## Logging

The script writes a log entry when it starts and when it completes. Each entry includes:

- Timestamp (`yyyy-MM-dd HH:mm:ss`)
- Mode (`Delete` or `ListOnly`)
- Source filter applied
- Indicators found
- Indicators deleted / failed (Delete mode)
- Elapsed time (Delete mode)

**Default log location:** `<script folder>\Remove-SentinelThreatIndicator_<yyyyMMdd_HHmmss>.log`

A new log file is created for each run. If `$PSScriptRoot` is unavailable (e.g. interactive session), the current working directory is used.

**Example log entries:**

```
2026-04-11 14:22:01  Started | Mode: Delete | SourceFilter: ThreatViewIPBlockList | Found: 3500
2026-04-11 14:25:43  Completed | Mode: Delete | SourceFilter: ThreatViewIPBlockList | Deleted: 3500 | Failed: 0 | Elapsed: 3m 42s
```

---

## Notes

- The script uses the **Microsoft Sentinel REST API** (`2025-09-01`) directly, via `Invoke-RestMethod`.
- Token refresh is handled automatically on `401 Unauthorized` responses.
- Rate limiting (`429 Too Many Requests`) is handled with automatic backoff and retry (up to 3 attempts).
- Parallel deletion requires **PowerShell 7+**. On PowerShell 5.1 the script falls back to sequential deletion automatically.

---

## License

See [LICENSE](LICENSE).

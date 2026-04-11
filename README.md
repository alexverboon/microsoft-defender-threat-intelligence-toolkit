# sentinel-ti-maintenance-scripts

A community PowerShell toolkit for managing **Microsoft Sentinel Threat Intelligence indicators** via the Azure REST API.

---

## Overview

This repository provides scripts to list and bulk-delete threat intelligence (TI) indicators from a Microsoft Sentinel workspace. It is designed for security engineers and SOC teams who need to clean up stale or unwanted indicators at scale.

### The problem: indicator bloat

Over time, a Microsoft Sentinel workspace can accumulate a very large number of threat intelligence indicators. A common cause is automated threat feed ingestion — feeds such as ThreatView, MDTI, or other third-party sources push indicators into Sentinel on a schedule. Each import cycle adds new indicators, and unless old ones are actively expired or deleted, the total count grows unbounded.

The screenshot below shows an example workspace with over **6.3 million indicators**:

![Sentinel indicator total count](docs/images/sentinel-indicators-total-count.png)

At this scale, indicator management through the portal becomes impractical. Searches are slow, filtering is cumbersome, and there is no built-in bulk delete capability for large volumes.

### Identifying the source

To understand which feeds are responsible for the high volume, use the **Source** filter in the Microsoft Defender portal under **Intel management**. Filtering by source lets you quickly see how many indicators each feed has contributed:

![Filtering by source to find large indicator counts](docs/images/sentinel-ti-indicators-largecount.png)

In the example above, filtering by `ThreatViewURLBlockList` and `ThreatViewIPBlockList` reveals nearly **967,000 indicators** from those two sources alone. Once you know the source name, you have everything needed to target a bulk delete.

### Impact on Log Analytics costs

A high indicator count does not only affect portal usability — it also directly drives up the size of the `ThreatIntelIndicators` and `ThreatIntelObjects` tables in Log Analytics, which contributes to ingestion and retention costs.

The screenshot below (from the Microsoft Sentinel workspace workbook) shows how the TI-related tables contribute to overall data volume:

![TI table usage from workspace workbook](docs/images/ti-tables-usage-from-workbook.png)

To quantify the cost contribution per feed source, run the following KQL query in your Log Analytics workspace:

```kql
ThreatIntelIndicators
| where TimeGenerated > ago(360d)
| where _IsBillable == true
| summarize 
    TotalVolumeGBLog = round(sum(_BilledSize / 1024 / 1024 / 1024), 2),
    Count = count() 
    by SourceSystem
    //| summarize round((sum(TotalVolumeGBLog)),2)
```

This returns the billed volume in GB and indicator count broken down by source — making it straightforward to identify which feeds are the largest cost contributors and prioritise which ones to clean up first.

### Cleaning up with this script

With the source name identified, set `$SourceFilter` in `Invoke-DeleteSentinelThreatIntelligence.ps1` to one or more source values and run the script. It will count all matching indicators, prompt for confirmation, then delete them in batches — handling pagination, token refresh, and rate limiting automatically.

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
    $SourceFilter      = @("ThreatViewIPBlockList")  # or @("ThreatViewIPBlockList","ThreatViewURLBlockList"); use @() for ALL sources
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
| `SourceFilter` | String[] | No | Filter by one or more source names. Use an empty array to target all sources. |
| `PageSize` | Int | No | Indicators per API page. Defaults to `100`. |
| `ListOnly` | Bool | No | When `$true`, lists indicators without deleting. |
| `ThrottleLimit` | Int | No | Max concurrent DELETE threads. PS 7+ only; ignored on PS 5. |
| `Force` | Switch | No | Skips the interactive deletion confirmation prompt. |
| `LogFile` | String | No | Path to log file. Defaults to `Remove-SentinelThreatIndicator.log` in the script folder. |

---

## Usage Examples

**List all indicators for specific sources (no deletion):**

```powershell
Remove-SentinelThreatIndicator `
    -SubscriptionId    "<sub-id>" `
    -ResourceGroupName "<rg>" `
    -WorkspaceName     "<workspace>" `
    -SourceFilter      @("ThreatViewIPBlockList", "ThreatViewURLBlockList") `
    -ListOnly          $true
```

**Delete indicators from specific sources with confirmation prompt:**

```powershell
Remove-SentinelThreatIndicator `
    -SubscriptionId    "<sub-id>" `
    -ResourceGroupName "<rg>" `
    -WorkspaceName     "<workspace>" `
    -SourceFilter      @("ThreatViewIPBlockList", "ThreatViewURLBlockList")
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

The script writes log entries during key execution phases (run initialization, page-size probe, start, completion/abort). Each entry includes:

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
2026-04-11 11:34:55  Run initiated | SubscriptionId: 00000000-0000-0000-0000-00000000000X | ResourceGroup: rg_sentinel01 | Workspace: AVSentinel01 | SourceFilter: Blocklistde, TORExitNodes
2026-04-11 11:34:58  Page size probe | Requested: 1000 | API returned: 1000 per page
2026-04-11 11:35:06  Started | Mode: Delete | SourceFilter: Blocklistde, TORExitNodes | Found: 4800
```

---

## Notes

- The script uses the **Microsoft Sentinel REST API** (`2025-09-01`) directly, via `Invoke-RestMethod`.
- Token refresh is handled automatically on `401 Unauthorized` responses.
- Rate limiting (`429 Too Many Requests`) is handled with automatic backoff and retry (up to 3 attempts).
- Parallel deletion requires **PowerShell 7+**. On PowerShell 5.1 the script falls back to sequential deletion automatically.

---

## How It Works at Scale

The script is designed to handle workspaces with large numbers of indicators (tens of thousands or more) efficiently. It uses a **two-pass approach** for deletion:

### Pass 1 — Count only

Before deleting anything, the script pages through the API purely to count how many indicators match the filter. No indicator objects are stored in memory during this pass — only a running total is maintained. This gives you an accurate count for the confirmation prompt without holding the entire dataset in RAM.

### Pass 2 — Fetch one page, delete it, repeat

Rather than loading all indicators into memory before starting deletion, the script fetches one page at a time and immediately deletes that batch before fetching the next. Because deleted indicators disappear from the API, each subsequent query without a pagination token naturally returns the next set of remaining indicators. This loop continues until the API returns an empty page.

This design has several benefits:

| Concern | How it's handled |
|---------|-----------------|
| **Memory usage** | Bounded to one page (~`$BatchSize` objects) at all times, regardless of total indicator count. |
| **Token expiry** | The bearer token is refreshed at the start of every batch, preventing expiry during long-running deletes. |
| **Resilience** | If the script is interrupted, already-deleted indicators are gone. Re-running picks up automatically from wherever it left off — no state file needed. |
| **Page size** | On the first batch, the script logs how many indicators the API actually returned vs. how many were requested, detecting any server-side cap. |

### Parallel vs. sequential deletion

Within each batch, individual DELETE requests are issued either in parallel (PowerShell 7+ with `ForEach-Object -Parallel`) or sequentially (PowerShell 5.1). The `$ThrottleLimit` setting controls how many concurrent DELETE requests are in flight at once in parallel mode. Setting it too high may trigger `429 Too Many Requests` responses from the API; the default of `5` is a conservative starting point.

---

## License

See [LICENSE](LICENSE).

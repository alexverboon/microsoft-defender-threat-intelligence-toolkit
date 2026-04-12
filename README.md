# Microsoft Defender Threat Intelligence Toolkit

A community PowerShell toolkit for managing **Microsoft Sentinel Threat Intelligence indicators** via the Azure REST API.

---

## Overview

This repository provides scripts to bulk-delete threat intelligence (TI) indicators from a Microsoft Sentinel workspace. It is designed for security engineers and SOC teams who need to clean up stale or unwanted indicators at scale.

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

With the source name identified, set `$SourceFilter` in `Invoke-RemoveSentinelThreatIndicator.ps1` to one or more source values and run the script. It will count all matching indicators, prompt for confirmation, then delete them in batches — handling pagination, token refresh, and rate limiting automatically.

The screenshot below shows the indicator delete progress view used during bulk cleanup runs:

![Indicator delete progress](docs/images/indicator-delete-progress.png)

---

## Scripts

| Script | Description |
|--------|-------------|
| `Scripts\Remove-SentinelThreatIndicators.ps1` | Contains the `Remove-SentinelThreatIndicators` function. Dot-source this file to load the function. |
| `Scripts\Invoke-RemoveSentinelThreatIndicator.ps1` | Caller script. Edit the configuration block at the top and run this file. |

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

3. **Edit the configuration** in `Invoke-RemoveSentinelThreatIndicator.ps1`:

   ```powershell
    $SubscriptionId    = "<subscription-guid>"       # Required: Azure subscription GUID containing the Sentinel workspace
    $ResourceGroupName = "<resource-group-name>"     # Required: Azure resource group name containing the workspace
    $WorkspaceName     = "<workspace-name>"          # Required: Log Analytics workspace name linked to Sentinel
    $BatchSize         = 100                          # Integer > 0; lower values reduce burst pressure
    $SourceFilter      = @("<source-name>")          # One or more source names; use @() for ALL sources
    $ConcurrentWorkers = 5                            # Integer >= 1; used on PowerShell 7+ for parallel delete workers
    $TargetDeleteRatePerSecond = 10.0                # Decimal > 0; sustained delete rate across all workers
    $ShowAPIWarnings = $false                        # $true = print per-request API diagnostics
    $Confirm           = $true                        # $true = confirmation prompt; set $false for unattended runs
    $LogFile           = ""                          # Optional full file path; leave "" for default (script folder\Logs)
   ```

4. **Run the caller script:**

   ```powershell
    .\Scripts\Invoke-RemoveSentinelThreatIndicator.ps1
   ```

## Usage Examples

**Simulate delete run without changes (`-WhatIf`):**

```powershell
Remove-SentinelThreatIndicators `
    -SubscriptionId    "<sub-id>" `
    -ResourceGroupName "<rg>" `
    -WorkspaceName     "<workspace>" `
    -SourceFilter      @("ThreatViewIPBlockList", "ThreatViewURLBlockList") `
    -WhatIf
```

**Delete indicators from specific sources with confirmation prompt:**

```powershell
Remove-SentinelThreatIndicators `
    -SubscriptionId    "<sub-id>" `
    -ResourceGroupName "<rg>" `
    -WorkspaceName     "<workspace>" `
    -SourceFilter      @("ThreatViewIPBlockList", "ThreatViewURLBlockList") `
    -Confirm
```

**Delete all indicators from all sources, skip confirmation (unattended/automation):**

```powershell
Remove-SentinelThreatIndicators `
    -SubscriptionId    "<sub-id>" `
    -ResourceGroupName "<rg>" `
    -WorkspaceName     "<workspace>" `
    -Confirm:$false
```

---

## Logging

The script writes one logfmt line per event to the log file. Every line contains fixed leading keys followed by event-specific key=value pairs:

- `ts` — ISO 8601 UTC timestamp
- `level` — severity (`info`, `warn`, `error`)
- `run_id` — unique random integer generated once per run
- `event` — what happened (e.g. `run_started`, `preflight_config`, `delete_started`, `run_completed`)

Additional fields are included depending on the event, such as `subscription_id`, `workspace`, `source_filter`, `found`, `deleted`, `failed`, `elapsed`, `delta`, and `remaining_now`. Values containing spaces are quoted.

When API warning conditions occur, the log includes `api_warning` entries (for HTTP `401` token refresh and HTTP `429` throttling) plus an `api_warning_summary` line at the end of the run.

The log also captures the full preflight information for each run, including workspace targeting details, execution mode, target delete rate, and the exact counts calculated before deletion starts.

**Default log location:** `<script folder>\Logs\Remove-SentinelThreatIndicators_<yyyyMMdd_HHmmss>.log`

A new log file is created for each run. The `Logs` folder is created automatically if it does not exist. If `$PSScriptRoot` is unavailable (e.g. interactive session), the current working directory is used.

**Example log entries:**

```
ts=2026-04-11T15:11:57Z level=info run_id=48273194 event=run_started subscription_id=00000000-0000-0000-0000-00000000000X resource_group=rg_sentinel01 workspace=AVSentinel01 source_filter="ThreatViewIPBlock, TORExitNodes"
ts=2026-04-11T15:11:58Z level=info run_id=48273194 event=preflight_counts total_all_sources=2100000 matching_source_filter=1947621 source_share_pct=92.74
ts=2026-04-11T15:12:00Z level=info run_id=48273194 event=delete_started source_filter=CoinBlocker found=1947621
ts=2026-04-12T09:44:51Z level=info run_id=48273194 event=run_completed source_filter=CoinBlocker deleted=1947600 failed=21 elapsed="20h 22m 51s"
```

---

## Notes

- The script uses the **Microsoft Sentinel / SecurityInsights REST API** directly, via `Invoke-RestMethod`.
- Token refresh is handled automatically on `401 Unauthorized` responses.
- Rate limiting (`429 Too Many Requests`) is handled with automatic backoff and retry on delete, query, count, and internal fallback list requests.
- Parallel deletion requires **PowerShell 7+**. On PowerShell 5.1 the script falls back to sequential deletion automatically.

---

## Used APIs

The toolkit currently uses the following Microsoft Sentinel / SecurityInsights REST APIs:

| Operation | Purpose | API version used | Microsoft Learn reference |
|---------|---------|------------------|---------------------------|
| Count | Exact pre-delete count and periodic remaining-count refresh | `2025-07-01-preview` | `Threat Intelligence API` - https://learn.microsoft.com/en-us/rest/api/securityinsights/threat-intelligence?view=rest-securityinsights-2025-07-01-preview |
| Query | Fetch matching indicators in pages before deletion | `2025-09-01` by default, with compatibility fallback probing when required by the tenant | `Threat Intelligence API` - https://learn.microsoft.com/en-us/rest/api/securityinsights/threat-intelligence?view=rest-securityinsights-2025-07-01-preview |
| Delete | Delete individual indicators | `2025-09-01` | `Threat Intelligence Indicator Delete API` - https://learn.microsoft.com/en-us/rest/api/securityinsights/threat-intelligence-indicator/delete?view=rest-securityinsights-2025-09-01&tabs=HTTP |

**Not currently used:** The [Microsoft Graph Security Threat Intelligence API](https://learn.microsoft.com/en-us/graph/api/resources/security-threatintelligence-overview?view=graph-rest-1.0) is not used by this toolkit at this time, but will be considered for future updates.

---

## How It Works at Scale

The script is designed to handle workspaces with large numbers of indicators (tens of thousands or more) efficiently. It uses a count-and-drain approach with resilient query fallbacks.

### Phase 1 - Count before delete

Before deleting anything, the script first calls the threat intelligence count endpoint (`2025-07-01-preview`) to get an exact count. If that endpoint is unavailable, delete mode stops immediately so the run never proceeds with an inexact pre-count.

### Phase 2 - Fetch, delete, repeat

Rather than loading all indicators into memory, the script processes one page at a time and deletes that batch before moving on. Batch fetch uses a resilient shared fetch path:

- Primary: filtered query endpoint (`2025-09-01`, with compatibility fallbacks when required by the tenant).
- Fallback 1: client-side source filtering when filtered query returns 400.
- Fallback 2: indicator list GET scan when query scan also returns 400.

The loop continues until no more matching items are returned.

### Phase 3 - Optional recount per batch

By default, the script performs an additional recount after each delete batch and updates the reconciled total in progress output. This keeps long-running operations auditable and gives more reliable remaining counts while the dataset changes.

This design has several benefits:

| Concern | How it's handled |
|---------|-----------------|
| **Memory usage** | Bounded to one page (~`$BatchSize` objects) at all times, regardless of total indicator count. |
| **Token expiry** | The bearer token is refreshed on a time threshold during long-running runs, reducing auth failures. |
| **Resilience** | If the script is interrupted, already-deleted indicators are gone. Re-running picks up automatically from wherever it left off — no state file needed. |
| **Endpoint compatibility** | Automatic query-mode and endpoint fallbacks handle API 400 behavior differences across tenants. |
| **Progress integrity** | Optional per-batch recount helps reconcile remaining work during long-running deletes. |

### Parallel vs. sequential deletion

Within each batch, individual DELETE requests are issued either in parallel (PowerShell 7+ with `ForEach-Object -Parallel`) or sequentially (PowerShell 5.1). The `$ConcurrentWorkers` setting controls how many workers can prepare delete calls, while `$TargetDeleteRatePerSecond` controls the sustained delete rate across the whole run with token-bucket pacing. For ARM-backed Sentinel cleanup jobs, a conservative starting point is `0.25` requests per second, which is about `900` deletes per hour and leaves headroom for query and count calls.

### Tuning for throttling

If you are seeing `429 Too Many Requests`, tune in this order:

1. Lower `$TargetDeleteRatePerSecond` first.
2. Increase `$ProgressRefreshIntervalSeconds` to reduce count calls.
3. Lower `$ConcurrentWorkers` if you still see burst-related throttling on PowerShell 7+.

For most production cleanup runs, `ConcurrentWorkers=1..2`, `TargetDeleteRatePerSecond=0.20..0.25`, and `ProgressRefreshIntervalSeconds=60..180` are safer defaults than increasing parallelism.

### Progress updates

During deletion the script maintains a single `0-100%` progress bar. Every `ProgressRefreshIntervalSeconds`, the script pauses briefly, recounts the remaining indicators for the active source filter, updates the progress bar, and then resumes deleting.

### Indicator removal process status

![Indicator delete progress](docs/images/indicator-delete-progress.png)

> **Note:** Depending on the total number of indicators to delete, the job can take **several hours** to complete. For workspaces with millions of indicators, plan accordingly and ensure the host running the script remains active for the duration.

---

## License

See [LICENSE](LICENSE).

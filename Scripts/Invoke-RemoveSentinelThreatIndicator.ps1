#region --- CONFIGURATION - Edit these values ---
# Replace these values with your environment and preferred run settings before execution.
$SubscriptionId    = ""  # Subscription ID of the Sentinel workspace
$ResourceGroupName = "rg_sentinel01"  # Resource group containing the target workspace
$WorkspaceName     = "AVSentinel01"   # Log Analytics workspace name linked to Microsoft Sentinel
$BatchSize         = 100      # Number of indicators to delete in each batch (smaller = safer to avoid rate limits)
$SourceFilter      = @("CoinBlocker")  # one or more sources, e.g. @("ThreatViewIPBlockList","ThreatViewURLBlockList") - leave @() to delete ALL
$ConcurrentWorkers = 5        # Max concurrent DELETE workers on PowerShell 7+; sustained rate is controlled separately
$TargetDeleteRatePerSecond = 10.0  # Sustained DELETE rate across all workers (~3600/hour)
$ShowAPIWarnings = $false  # $true = print per-request API diagnostics
$Confirm           = $true    # $true = show confirmation prompt; set $false for unattended runs
$WhatIf            = $false   # $true = simulate the run without making any changes
$LogFile           = ""       # log file path, leave empty to use default (script folder\Logs)
#endregion

#region --- Load Functions ---
. "$PSScriptRoot\Remove-SentinelThreatIndicators.ps1"
#endregion

#region --- Run ---
Remove-SentinelThreatIndicators `
    -SubscriptionId    $SubscriptionId `
    -ResourceGroupName $ResourceGroupName `
    -WorkspaceName     $WorkspaceName `
    -SourceFilter      $SourceFilter `
    -PageSize          $BatchSize `
    -ConcurrentWorkers $ConcurrentWorkers `
    -TargetDeleteRatePerSecond $TargetDeleteRatePerSecond `
    -ShowAPIWarnings:$ShowAPIWarnings `
    -Confirm:$Confirm `
    -WhatIf:$WhatIf `
    -LogFile           $LogFile
#endregion

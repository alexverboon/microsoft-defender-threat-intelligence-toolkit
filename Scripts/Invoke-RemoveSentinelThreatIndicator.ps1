#region --- CONFIGURATION - Edit these values ---
# Replace these values with your environment and preferred run settings before execution.
$SubscriptionId    = ""  # Subscription ID of the Sentinel workspace
$ResourceGroupName = "rg_sentinel01"  # Resource group containing the target workspace
$WorkspaceName     = "AVSentinel01"   # Log Analytics workspace name linked to Microsoft Sentinel
$BatchSize         = 100      # Number of indicators to delete in each batch 
$SourceFilter      = @("DigitalSide")  # Required for safety: one or more sources, e.g. @("ThreatViewIPBlockList","ThreatViewURLBlockList"). Missing/empty values abort the run.
$ConcurrentWorkers = 5        #  Max concurrent DELETE workers; sustained rate is controlled separately by TargetDeleteRatePerSecond
$TargetDeleteRatePerSecond = 10.0  # Sustained DELETE rate across all workers. Start with 1.0 req/s as a safe baseline (~3600/hour). Higher values (for example 10.0 req/s) can speed up overall processing but increase the chance of throttling (HTTP 429), depending on tenant and subscription limits.
$ShowAPIWarnings = $false     # When set, writes per-request 401/429 throttle diagnostics to the console. By default these messages are suppressed.
$Confirm           = $true    # $true = show confirmation prompt; set $false for unattended runs
$WhatIf            = $false   # $true = simulate the run without making any changes
$LogFile           = ""       # Optional full file path; leave "" for default (script folder\Logs)
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
    -BatchSize         $BatchSize `
    -ConcurrentWorkers $ConcurrentWorkers `
    -TargetDeleteRatePerSecond $TargetDeleteRatePerSecond `
    -ShowAPIWarnings:$ShowAPIWarnings `
    -Confirm:$Confirm `
    -WhatIf:$WhatIf `
    -LogFile           $LogFile
#endregion

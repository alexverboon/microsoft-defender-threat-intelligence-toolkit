#region --- CONFIGURATION - Edit these values ---
$SubscriptionId    = ""  # Subscription ID of the Sentinel workspace
$ResourceGroupName = "rg_sentinel01"
$WorkspaceName     = "AVSentinel01"
$BatchSize         = 100      # Number of indicators to delete in each batch (smaller = safer to avoid rate limits)
$SourceFilter      = @("baseVISION-SOC-TI-Feed")  # one or more sources, e.g. @("ThreatViewIPBlockList","ThreatViewURLBlockList") - leave @() to delete ALL
$ListOnly          = $false   # $true = only list indicators, no deletion
$ThrottleLimit     = 3        # Max concurrent DELETE requests (1 = sequential, safer; 5 = parallel)
$Force             = $false   # $true = skip deletion confirmation prompt
$LogFile           = ""       # log file path, leave empty to use default (script folder)
#endregion

#region --- Load Functions ---
. "$PSScriptRoot\delete-SentinelThreatIntelligence.ps1"
#endregion

#region --- Run ---
Remove-SentinelThreatIndicator `
    -SubscriptionId    $SubscriptionId `
    -ResourceGroupName $ResourceGroupName `
    -WorkspaceName     $WorkspaceName `
    -SourceFilter      $SourceFilter `
    -PageSize          $BatchSize `
    -ListOnly          $ListOnly `
    -ThrottleLimit     $ThrottleLimit `
    -Force:$Force `
    -LogFile           $LogFile
#endregion

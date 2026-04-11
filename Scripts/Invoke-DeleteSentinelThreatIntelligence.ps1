#region --- CONFIGURATION - Edit these values ---
$SubscriptionId    = "00000000-0000-0000-0000-000000000000"  # Subscription ID of the Sentinel workspace
$ResourceGroupName = "rg_sentinel01"
$WorkspaceName     = "AVSentinel01"
$BatchSize         = 1000
$SourceFilter      = "ThreatViewIPBlockList"   # e.g. "Microsoft Defender Threat Intelligence" - leave empty "" to delete ALL
$ListOnly          = $false   # $true = only list indicators, no deletion
$ThrottleLimit     = 5        # Max concurrent DELETE requests (PowerShell 7+ only; ignored on PS 5)
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

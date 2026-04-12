<#
.SYNOPSIS
Shared logfmt logging helpers for toolkit scripts.

.DESCRIPTION
Provides reusable logging functions for PowerShell scripts in this repository.
Call Initialize-ToolkitLogger once per run to set logging context (log file and run ID),
then call Write-Log with ordered key/value fields to write logfmt lines.

Each output line includes fixed fields:
- ts (UTC timestamp)
- level (defaults to info)
- run_id

Event-specific fields are appended from the ordered dictionary passed to Write-Log.
Values containing spaces, equals signs, or quotes are quoted and escaped.
Format reference: https://brandur.org/logfmt

.PARAMETER LogFile
Target log file path to write log lines to.

.PARAMETER RunId
Optional run identifier. If omitted or empty, an 8-digit random run ID is generated.

.PARAMETER Fields
Ordered dictionary of event fields for Write-Log.
Use an [ordered] hashtable when calling Write-Log.

.EXAMPLE
. "$PSScriptRoot\Common\Toolkit.Logging.ps1"
Initialize-ToolkitLogger -LogFile "C:\Temp\run.log"
Write-Log ([ordered]@{ event = 'run_started'; script = 'Remove-SentinelThreatIndicators' })

Initializes logger context with an auto-generated run ID and writes a run_started event.

.EXAMPLE
. "$PSScriptRoot\Common\Toolkit.Logging.ps1"
Initialize-ToolkitLogger -LogFile "C:\Temp\run.log" -RunId "41334086"
Write-Log ([ordered]@{ level = 'warn'; event = 'query_fallback_disabled'; status_code = 400 })

Initializes logger context with an explicit run ID and writes a warning event.

.NOTES
This file is designed to be dot-sourced from scripts that need consistent logging output.
Logfmt reference: https://brandur.org/logfmt
#>

function Initialize-ToolkitLogger {
    <#
    .SYNOPSIS
        Initializes shared logger context for Write-Log.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$LogFile,
        [string]$RunId
    )

    if ([string]::IsNullOrWhiteSpace($RunId)) {
        $RunId = [string](Get-Random -Minimum 10000000 -Maximum 99999999)
    }

    $script:ToolkitLoggerContext = @{
        LogFile = $LogFile
        RunId   = $RunId
    }
}

function Write-Log {
    <#
    .SYNOPSIS
        Writes a logfmt event line to the configured log file.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.Specialized.OrderedDictionary]$Fields
    )

    if (-not $script:ToolkitLoggerContext -or -not $script:ToolkitLoggerContext.LogFile -or -not $script:ToolkitLoggerContext.RunId) {
        throw "Logger is not initialized. Call Initialize-ToolkitLogger first."
    }

    $level = if ($Fields.Contains('level')) { $Fields['level'] } else { 'info' }
    $ts    = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $pairs = [System.Collections.Generic.List[string]]::new()
    $pairs.Add("ts=$ts")
    $pairs.Add("level=$level")
    $pairs.Add("run_id=$($script:ToolkitLoggerContext.RunId)")

    foreach ($key in $Fields.Keys) {
        if ($key -eq 'level') { continue }
        $val = $Fields[$key]
        if ($null -eq $val) { $val = 'null' }
        if ($val -match '[ ="""]') { $val = '"' + ($val -replace '"', '\"') + '"' }
        $pairs.Add("$key=$val")
    }

    ($pairs -join ' ') | Out-File -FilePath $script:ToolkitLoggerContext.LogFile -Append -Encoding utf8 -Confirm:$false
}

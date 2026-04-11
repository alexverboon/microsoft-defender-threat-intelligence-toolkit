function Remove-SentinelThreatIndicator {
    <#
    .SYNOPSIS
        Remove-SentinelThreatIndicator - Deletes threat intelligence indicators from a Microsoft Sentinel workspace, with optional list-only mode.
    .PARAMETER SubscriptionId
        Azure subscription ID containing the Sentinel workspace.
    .PARAMETER ResourceGroupName
        Resource group name containing the Sentinel workspace.
    .PARAMETER WorkspaceName
        Log Analytics workspace name linked to Microsoft Sentinel.
    .PARAMETER SourceFilter
        Filter indicators by source name. Leave empty to target all sources.
    .PARAMETER PageSize
        Number of indicators to retrieve per API page. Defaults to 100.
    .PARAMETER ListOnly
        When set, lists indicators without deleting them.
    .PARAMETER ThrottleLimit
        Maximum concurrent DELETE requests. Requires PowerShell 7+; ignored on PS 5.
    .PARAMETER Force
        Skips the deletion confirmation prompt.
    .PARAMETER LogFile
        Path to the log file. Defaults to Remove-SentinelThreatIndicator.log in the script's folder.
    #>
    param (
        [string]$SubscriptionId,
        [string]$ResourceGroupName,
        [string]$WorkspaceName,
        [string]$SourceFilter,
        [int]$PageSize,
        [bool]$ListOnly,
        [int]$ThrottleLimit,
        [switch]$Force,
        [string]$LogFile = ""
    )

    if (-not $LogFile) {
        $logDir  = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
        $logDate = Get-Date -Format 'yyyyMMdd_HHmmss'
        $LogFile = Join-Path $logDir "Remove-SentinelThreatIndicator_$logDate.log"
    }

    function Write-Log {
        param([string]$Message)
        $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        "$timestamp  $Message" | Out-File -FilePath $LogFile -Append -Encoding utf8
    }

    $requiredModules = @('Az.Accounts')
    foreach ($module in $requiredModules) {
        if (-not (Get-Module -Name $module -ListAvailable)) {
            Write-Error "Required module '$module' is not installed. Run: Install-Module $module"
            return
        }
    }

    if (-not $PageSize -or $PageSize -lt 1) {
        $PageSize = 100
    }

    $ProgressIdListCollect   = 10
    $ProgressIdDeleteCollect = 20
    $ProgressIdDeleteRun     = 30

    function Write-Status {
        <#
        .SYNOPSIS
            Writes a tagged status message to output.
        #>
        param(
            [ValidateSet("INFO", "PASS", "WARN", "FAIL")]
            [string]$Level,
            [string]$Message
        )

        Write-Output "[$Level] $Message"
    }

    function Confirm-Deletion {
        <#
        .SYNOPSIS
            Prompts the user to confirm indicator deletion.
        #>
        param(
            [int]$Count,
            [string]$Scope
        )

        $title   = "Confirm Sentinel Indicator Deletion"
        $message = "You are about to delete $Count indicator(s) $Scope.`n`nThis action cannot be undone."
        $choices = [System.Management.Automation.Host.ChoiceDescription[]]@(
            (New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Proceed with deletion"),
            (New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Cancel and exit")
        )

        $selection = $Host.UI.PromptForChoice($title, $message, $choices, 1)
        return ($selection -eq 0)
    }

    function Get-BearerToken {
        <#
        .SYNOPSIS
            Acquires a bearer token for the Azure management API.
        #>
        $t = $null
        try {
            $tokenObj = Get-AzAccessToken -ResourceUrl "https://management.azure.com/" -ErrorAction Stop
            if ($tokenObj.Token -is [System.Security.SecureString]) {
                $t = [System.Net.NetworkCredential]::new("", $tokenObj.Token).Password
            } else {
                $t = $tokenObj.Token
            }
        }
        catch {
            try {
                # If there is no active Az session, prompt sign-in and retry once.
                Connect-AzAccount -ErrorAction Stop | Out-Null
                $tokenObj = Get-AzAccessToken -ResourceUrl "https://management.azure.com/" -ErrorAction Stop
                if ($tokenObj.Token -is [System.Security.SecureString]) {
                    $t = [System.Net.NetworkCredential]::new("", $tokenObj.Token).Password
                } else {
                    $t = $tokenObj.Token
                }
            }
            catch {
                return $null
            }
        }
        return $t
    }

    $token = Get-BearerToken
    if (-not $token) {
        Write-Status -Level FAIL -Message "Failed to acquire access token. Run 'Connect-AzAccount' and try again."
        return
    }

    $logSourceFilter = if ($SourceFilter) { $SourceFilter } else { '(all sources)' }
    $logMode = if ($ListOnly) { 'ListOnly' } else { 'Delete' }

    $headers = @{
        "Authorization" = "Bearer $token"
        "Content-Type"  = "application/json"
    }

    $apiVersion = "2025-09-01"
    $baseUri    = "https://management.azure.com/subscriptions/$SubscriptionId" +
                  "/resourceGroups/$ResourceGroupName" +
                  "/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName" +
                  "/providers/Microsoft.SecurityInsights"
    $queryUri   = "$baseUri/threatIntelligence/main/queryIndicators?api-version=$apiVersion"
    $deleteBase = "$baseUri/threatIntelligence/main/indicators"

    function Get-IndicatorPage {
        <#
        .SYNOPSIS
            Queries a single page of threat intelligence indicators.
        #>
        param(
            [hashtable]$Headers,
            [string]$Uri,
            [string]$Source,
            [int]$Size,
            [string]$SkipToken
        )

        $body = [ordered]@{
            pageSize = $Size
            sortBy   = @(@{ itemKey = "lastUpdatedTimeUtc"; sortOrder = "descending" })
        }
        if ($Source) { $body.sources = @($Source) }
        if ($SkipToken) { $body.skipToken = $SkipToken }

        $response = Invoke-RestMethod -Uri $Uri `
                                      -Headers $Headers `
                                      -Method POST `
                                      -Body ($body | ConvertTo-Json -Depth 5) `
                                      -ErrorAction Stop

        $nextSkipToken = $null

        foreach ($tokenKey in @("skipToken", "nextSkipToken", "continuationToken", "nextContinuationToken")) {
            $prop = $response.PSObject.Properties | Where-Object { $_.Name -ieq $tokenKey } | Select-Object -First 1
            if ($prop -and $prop.Value) {
                $nextSkipToken = [string]$prop.Value
                break
            }
        }

        if (-not $nextSkipToken) {
            foreach ($linkKey in @("nextLink", "@odata.nextLink", "odata.nextLink", "nextPageLink")) {
                $prop = $response.PSObject.Properties | Where-Object { $_.Name -ieq $linkKey } | Select-Object -First 1
                if (-not $prop -or -not $prop.Value) { continue }

                $nextLink = [string]$prop.Value
                if ($nextLink -match '(?i)[?&](?:skipToken|\$skiptoken|continuationToken)=([^&]+)') {
                    $nextSkipToken = [System.Uri]::UnescapeDataString($Matches[1])
                    break
                }
            }
        }

        [PSCustomObject]@{
            Items         = @($response.value)
            NextSkipToken = $nextSkipToken
        }
    }

    if ($ListOnly) {
        Write-Output "Querying indicators$(if ($SourceFilter) { " for source: $SourceFilter" } else { " (all sources)" })..."

        $allIndicators = [System.Collections.Generic.List[object]]::new()
        $page          = 1
        $skipToken     = $null
        $hadPaginationToken = $false
        $seenSkipToken = [System.Collections.Generic.HashSet[string]]::new()

        do {
            try {
                $pageResult = Get-IndicatorPage -Headers $headers -Uri $queryUri -Source $SourceFilter -Size $PageSize -SkipToken $skipToken
                $batch = $pageResult.Items
                $batchCount = if ($batch) { @($batch).Count } else { 0 }
                $skipToken = $pageResult.NextSkipToken
                if ($skipToken) { $hadPaginationToken = $true }

                if ($batchCount -gt 0) {
                    $allIndicators.AddRange([object[]]@($batch))
                    Write-Progress -Activity "Collecting Threat Intelligence Indicators" `
                                   -Id $ProgressIdListCollect `
                                   -Status "Page $page | Fetched: $batchCount | Total so far: $($allIndicators.Count)" `
                                   -PercentComplete 0
                    $page++
                }

                if ($skipToken -and (-not $seenSkipToken.Add($skipToken))) {
                    Write-Output "WARNING: Duplicate pagination token received; stopping to prevent loop."
                    break
                }
            }
            catch {
                $errorDetail = ""
                try {
                    $reader      = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
                    $errorDetail = $reader.ReadToEnd()
                } catch {}
                Write-Output "ERROR querying page $page — $($_.Exception.Message)"
                if ($errorDetail) { Write-Output "API detail: $errorDetail" }
                break
            }
        } while ($skipToken)

        Write-Progress -Activity "Collecting Threat Intelligence Indicators" -Id $ProgressIdListCollect -Completed

        if (-not $hadPaginationToken -and $allIndicators.Count -ge $PageSize) {
            Write-Output "WARNING: API returned a full page ($PageSize) but no continuation token. Results may be capped to one page."
        }

        if ($allIndicators.Count -eq 0) {
            Write-Output "No indicators found$(if ($SourceFilter) { " for source '$SourceFilter'" })."
            return
        }

        $uniqueSources = $allIndicators | Select-Object -ExpandProperty properties |
                         Select-Object -ExpandProperty source -Unique | Sort-Object
        Write-Output ""
        Write-Output "Found $($allIndicators.Count) indicator(s) across $($uniqueSources.Count) source(s):"
        foreach ($src in $uniqueSources) {
            $count = ($allIndicators | Where-Object { $_.properties.source -eq $src }).Count
            Write-Output "  - $src ($count indicators)"
        }
        Write-Output ""
        Write-Output "===== Indicator Listing ====="
        Write-Output ""

        $allIndicators | ForEach-Object {
            $p = $_.properties
            [PSCustomObject]@{
                Name        = $_.name
                DisplayName = $p.displayName
                Source      = $p.source
                PatternType = $p.patternType
                Pattern     = $p.pattern
                ThreatTypes = ($p.threatTypes -join ", ")
                Confidence  = $p.confidence
                ValidFrom   = $p.validFrom
                ValidUntil  = $p.validUntil
                Revoked     = $p.revoked
                LastUpdated = $p.lastUpdatedTimeUtc
            }
        } | Format-Table -AutoSize -Wrap

        Write-Output "============================="
        Write-Output "Total: $($allIndicators.Count) indicator(s)"
        Write-Log "Started | Mode: ListOnly | SourceFilter: $logSourceFilter | Found: $($allIndicators.Count)"
        Write-Log "Completed | Mode: ListOnly | SourceFilter: $logSourceFilter | Found: $($allIndicators.Count)"
        return
    }

    Write-Output ""
    Write-Output "===== Preflight ====="
    Write-Status -Level PASS -Message "Access token acquired."
    Write-Status -Level INFO -Message "Target workspace: $WorkspaceName"
    Write-Status -Level INFO -Message "Source filter: $(if ($SourceFilter) { $SourceFilter } else { "(all sources)" })"
    Write-Status -Level INFO -Message "Execution mode: $(if ($PSVersionTable.PSVersion.Major -ge 7 -and $ThrottleLimit -gt 1) { "Parallel (Throttle=$ThrottleLimit)" } else { "Sequential" })"
    Write-Output "====================="

    # First pass: count how many indicators exist
    Write-Output "Querying indicators$(if ($SourceFilter) { " for source: $SourceFilter" } else { " (all sources)" })..."

    $indicatorsToDelete = [System.Collections.Generic.List[object]]::new()
    $totalPages         = 0
    $countPage          = 1
    $skipToken          = $null
    $hadPaginationToken = $false
    $seenSkipToken      = [System.Collections.Generic.HashSet[string]]::new()

    do {
        try {
            $pageResult = Get-IndicatorPage -Headers $headers -Uri $queryUri -Source $SourceFilter -Size $PageSize -SkipToken $skipToken
            $batch      = $pageResult.Items
            $batchCount = if ($batch) { @($batch).Count } else { 0 }
            $skipToken  = $pageResult.NextSkipToken
            if ($skipToken) { $hadPaginationToken = $true }

            if ($batchCount -gt 0) {
                $indicatorsToDelete.AddRange([object[]]@($batch))
                $totalPages++
                Write-Progress -Activity "Collecting Indicators For Deletion" `
                               -Id $ProgressIdDeleteCollect `
                               -Status "Page $countPage | Fetched: $batchCount | Total so far: $($indicatorsToDelete.Count)" `
                               -PercentComplete 0
                $countPage++
            }

            if ($skipToken -and (-not $seenSkipToken.Add($skipToken))) {
                Write-Output "WARNING: Duplicate pagination token received during count; stopping to prevent loop."
                break
            }
        }
        catch {
            $errorDetail = ""
            try {
                $reader      = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
                $errorDetail = $reader.ReadToEnd()
            } catch {}
            Write-Output "ERROR querying page $countPage — $($_.Exception.Message)"
            if ($errorDetail) { Write-Output "API detail: $errorDetail" }
            return
        }
    } while ($skipToken)

    Write-Progress -Activity "Collecting Indicators For Deletion" -Id $ProgressIdDeleteCollect -Completed

    $totalFound = $indicatorsToDelete.Count

    if (-not $hadPaginationToken -and $totalFound -ge $PageSize) {
        Write-Output "WARNING: API returned a full page ($PageSize) but no continuation token. Increase page size or use API version with pagination support if available."
    }

    if ($totalFound -eq 0) {
        Write-Output "No indicators found$(if ($SourceFilter) { " for source '$SourceFilter'" }). Nothing to delete."
        Write-Log "Completed | Mode: Delete | SourceFilter: $logSourceFilter | Deleted: 0 | Nothing to delete"
        return
    }

    Write-Output ""
    Write-Output "Found $totalFound indicator(s) across $totalPages page(s)$(if ($SourceFilter) { " from source '$SourceFilter'" })."
    Write-Output ""
    Write-Log "Started | Mode: Delete | SourceFilter: $logSourceFilter | Found: $totalFound"

    # Confirm before deleting
    $scopeMsg = if ($SourceFilter) { "from source '$SourceFilter'" } else { "from ALL sources" }
    if ($Force) {
        $confirmed = $true
    } else {
        $confirmed = Confirm-Deletion -Count $totalFound -Scope $scopeMsg
    }

    if (-not $confirmed) {
        Write-Output "Aborted. No indicators were deleted."
        Write-Log "Aborted | Mode: Delete | SourceFilter: $logSourceFilter | Deleted: 0"
        return
    }

    # Delete from the pre-collected list so each indicator is processed once.
    $sync       = [hashtable]::Synchronized(@{ Deleted = 0; Failed = 0; Processed = 0 })
    $failedBag  = [System.Collections.Concurrent.ConcurrentBag[string]]::new()
    $startTime  = [datetime]::UtcNow
    $useParallel = ($PSVersionTable.PSVersion.Major -ge 7) -and ($ThrottleLimit -gt 1)

    Write-Output ""
    if ($useParallel) {
        Write-Output "Running parallel deletes (throttle: $ThrottleLimit concurrent requests)..."
    }
    Write-Output ""

    if ($useParallel) {
        $indicatorsToDelete | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
            $s         = $using:sync
            $bag       = $using:failedBag
            $total     = $using:totalFound
            $startT    = $using:startTime
            $hdrs      = $using:headers
            $delBase   = $using:deleteBase
            $apiVer    = $using:apiVersion
            $progressId = $using:ProgressIdDeleteRun

            $name      = $_.name
            $deleteUri = "$delBase/$name`?api-version=$apiVer"

            # Helper: extract Retry-After seconds from a 429 response
            $getRetryAfter = {
                param($ex)
                $ra = 10  # default backoff if header missing
                try {
                    $raHeader = $ex.Exception.Response.Headers.GetValues("Retry-After") | Select-Object -First 1
                    if ($raHeader) { $ra = [int]$raHeader }
                } catch {}
                $ra
            }

            $maxRetries    = 3
            $attempt       = 0
            $deleteSuccess = $false
            $did401Refresh = $false

            do {
                $attempt++
                try {
                    Invoke-RestMethod -Uri $deleteUri -Headers $hdrs -Method DELETE -ErrorAction Stop | Out-Null
                    $s.Deleted++
                    $deleteSuccess = $true
                }
                catch {
                    $sc = if ($_.Exception.Response) { $_.Exception.Response.StatusCode.value__ } else { 0 }

                    # Refresh token once per indicator when a 401 occurs.
                    if ($sc -eq 401 -and -not $did401Refresh) {
                        try {
                            $tokenObj = Get-AzAccessToken -ResourceUrl "https://management.azure.com/" -ErrorAction Stop
                            $newToken = if ($tokenObj.Token -is [System.Security.SecureString]) {
                                [System.Net.NetworkCredential]::new("", $tokenObj.Token).Password
                            } else {
                                $tokenObj.Token
                            }

                            if ($newToken) {
                                $hdrs["Authorization"] = "Bearer $newToken"
                                $did401Refresh = $true
                                Write-Warning "  401 Unauthorized - token refreshed, retrying..."
                                $attempt--  # do not count token refresh as a retry attempt
                                continue
                            }
                        } catch {}
                    }

                    if ($sc -eq 429 -and $attempt -lt $maxRetries) {
                        $wait = & $getRetryAfter $_
                        Write-Warning "  429 Too Many Requests — waiting ${wait}s before retry (attempt $attempt/$maxRetries)..."
                        Start-Sleep -Seconds $wait
                        # loop back and retry
                    }
                    else {
                        $errDetail = ""
                        try { $errDetail = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream()).ReadToEnd() } catch {}
                        $sd = if ($_.Exception.Response) { $_.Exception.Response.StatusCode.ToString() } else { $_.Exception.Message }
                        $d  = if ($errDetail) { $errDetail } elseif ($_.Exception.Message) { $_.Exception.Message } else { "" }
                        $s.Failed++
                        $bag.Add($name)
                        Write-Warning "  FAILED [$sc $sd] $name$(if ($d) { " — $d" })"
                        $deleteSuccess = $true  # exit retry loop
                    }
                }
            } while (-not $deleteSuccess)

            $s.Processed++
            $proc      = $s.Processed
            $del       = $s.Deleted
            $fail      = $s.Failed
            $remaining = [math]::Max($total - $proc, 0)
            $pct       = if ($total -gt 0) { [math]::Round(($proc / $total) * 100) } else { 0 }
            $elapsed   = ([datetime]::UtcNow - $startT).TotalSeconds
            $avgSec    = if ($proc -gt 0) { $elapsed / $proc } else { 0 }
            $etaSec    = [math]::Round($avgSec * $remaining)
            $etaStr    = if ($proc -gt 0 -and $remaining -gt 0) {
                             $ts = [timespan]::FromSeconds($etaSec)
                             if     ($ts.TotalHours -ge 1)   { "{0}h {1}m {2}s" -f [int]$ts.TotalHours, $ts.Minutes, $ts.Seconds }
                             elseif ($ts.TotalMinutes -ge 1)  { "{0}m {1}s" -f $ts.Minutes, $ts.Seconds }
                             else                             { "{0}s" -f $ts.Seconds }
                         } else { "calculating..." }
            Write-Progress -Activity "Deleting Threat Intelligence Indicators" `
                           -Id $progressId `
                           -Status "Deleted: $del/$total  Failed: $fail  Remaining: ~$remaining  ETA: $etaStr" `
                           -PercentComplete ([math]::Min($pct, 100))
        }
    }
    else {
        foreach ($indicator in @($indicatorsToDelete)) {
            $name      = $indicator.name
            $deleteUri = "$deleteBase/$name`?api-version=$apiVersion"

            $maxRetries    = 3
            $attempt       = 0
            $deleteSuccess = $false
            $did401Refresh = $false

            do {
                $attempt++
                try {
                    Invoke-RestMethod -Uri $deleteUri -Headers $headers -Method DELETE -ErrorAction Stop | Out-Null
                    $sync.Deleted++
                    $deleteSuccess = $true
                }
                catch {
                    $errorDetail = ""
                    try {
                        $reader      = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
                        $errorDetail = $reader.ReadToEnd()
                    } catch {}

                    $statusCode = if ($_.Exception.Response) { $_.Exception.Response.StatusCode.value__ } else { 0 }

                    # On 401 Unauthorized, refresh the token once per indicator and retry.
                    if ($statusCode -eq 401 -and -not $did401Refresh) {
                        Write-Output "  INFO: Token expired, refreshing..."
                        $newToken = Get-BearerToken
                        if ($newToken) {
                            $token = $newToken
                            $headers["Authorization"] = "Bearer $token"
                            $did401Refresh = $true
                            $attempt--  # do not count token refresh as a retry attempt
                            continue
                        } else {
                            $errorDetail   = "Could not refresh access token."
                            $deleteSuccess = $true  # give up
                        }
                    }
                    # On 429 Too Many Requests, back off and retry
                    elseif ($statusCode -eq 429 -and $attempt -lt $maxRetries) {
                        $retryAfter = 10  # default backoff
                        try {
                            $raHeader = $_.Exception.Response.Headers.GetValues("Retry-After") | Select-Object -First 1
                            if ($raHeader) { $retryAfter = [int]$raHeader }
                        } catch {}
                        Write-Output "  INFO: Rate limited (429). Waiting ${retryAfter}s before retry (attempt $attempt/$maxRetries)..."
                        Start-Sleep -Seconds $retryAfter
                        # loop back and retry
                    }
                    else {
                        $sync.Failed++
                        $failedBag.Add($name)

                        $statusDesc = if ($_.Exception.Response) { $_.Exception.Response.StatusCode.ToString() } else { $_.Exception.Message }
                        $detail     = if ($errorDetail) { $errorDetail } elseif ($_.Exception.Message) { $_.Exception.Message } else { "" }
                        Write-Output "  FAILED [$statusCode $statusDesc] $name$(if ($detail) { " — $detail" })"
                        $deleteSuccess = $true  # exit retry loop
                    }
                }
            } while (-not $deleteSuccess)

            $sync.Processed++
            $pct               = if ($totalFound -gt 0) { [math]::Round(($sync.Processed / $totalFound) * 100) } else { 0 }
            $remainingToDelete = [math]::Max($totalFound - $sync.Processed, 0)
            $elapsed           = ([datetime]::UtcNow - $startTime).TotalSeconds
            $avgSec            = if ($sync.Processed -gt 0) { $elapsed / $sync.Processed } else { 0 }
            $etaSec            = [math]::Round($avgSec * $remainingToDelete)
            $etaStr            = if ($sync.Processed -gt 0 -and $remainingToDelete -gt 0) {
                                     $ts = [timespan]::FromSeconds($etaSec)
                                     if     ($ts.TotalHours -ge 1)  { "{0}h {1}m {2}s" -f [int]$ts.TotalHours, $ts.Minutes, $ts.Seconds }
                                     elseif ($ts.TotalMinutes -ge 1) { "{0}m {1}s" -f $ts.Minutes, $ts.Seconds }
                                     else   { "{0}s" -f $ts.Seconds }
                                 } else { "calculating..." }
            $status = "Deleted: $($sync.Deleted)/$totalFound  Failed: $($sync.Failed)  Remaining: ~$remainingToDelete  ETA: $etaStr"
            Write-Progress -Activity "Deleting Threat Intelligence Indicators" `
                           -Id $ProgressIdDeleteRun `
                           -Status $status `
                           -PercentComplete ([math]::Min($pct, 100))
        }
    }

    Write-Progress -Activity "Deleting Threat Intelligence Indicators" -Id $ProgressIdDeleteRun -Completed
    Write-Progress -Activity "Collecting Threat Intelligence Indicators" -Id $ProgressIdListCollect -Completed
    Write-Progress -Activity "Collecting Indicators For Deletion" -Id $ProgressIdDeleteCollect -Completed

    $deleted   = $sync.Deleted
    $failed    = $sync.Failed
    $failedIds = [System.Collections.Generic.List[string]]$failedBag

    $totalElapsed = [datetime]::UtcNow - $startTime
    $elapsedStr   = if     ($totalElapsed.TotalHours -ge 1)  { "{0}h {1}m {2}s" -f [int]$totalElapsed.TotalHours, $totalElapsed.Minutes, $totalElapsed.Seconds }
                    elseif ($totalElapsed.TotalMinutes -ge 1) { "{0}m {1}s" -f $totalElapsed.Minutes, $totalElapsed.Seconds }
                    else                                       { "{0}s" -f $totalElapsed.Seconds }
    Write-Output ""
    Write-Output "===== Summary ====="
    Write-Output "Source filter : $(if ($SourceFilter) { $SourceFilter } else { "(all sources)" })"
    Write-Output "Total found   : $totalFound"
    Write-Output "Deleted       : $deleted"
    Write-Output "Failed        : $failed"
    Write-Output "Elapsed time  : $elapsedStr"
    if ($failedIds.Count -gt 0) {
        Write-Output ""
        Write-Output "Failed indicators:"
        $failedIds | ForEach-Object { Write-Output "  - $_" }
    }
    Write-Output "==================="
    Write-Log "Completed | Mode: Delete | SourceFilter: $logSourceFilter | Deleted: $deleted | Failed: $failed | Elapsed: $elapsedStr"
}
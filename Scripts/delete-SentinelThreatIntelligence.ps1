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
        Filter indicators by one or more source names. Leave empty to target all sources.
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
    .PARAMETER RecountAfterBatch
        When set, recounts remaining indicators after each delete batch and updates progress totals.
    #>
    param (
        [string]$SubscriptionId,
        [string]$ResourceGroupName,
        [string]$WorkspaceName,
        [string[]]$SourceFilter,
        [int]$PageSize,
        [bool]$ListOnly,
        [int]$ThrottleLimit,
        [switch]$Force,
        [string]$LogFile = "",
        [bool]$RecountAfterBatch = $true
    )

    # Validate required parameters
    $configErrors = @()
    if ([string]::IsNullOrWhiteSpace($SubscriptionId))    { $configErrors += "  - SubscriptionId is empty." }
    if ([string]::IsNullOrWhiteSpace($ResourceGroupName)) { $configErrors += "  - ResourceGroupName is empty." }
    if ([string]::IsNullOrWhiteSpace($WorkspaceName))     { $configErrors += "  - WorkspaceName is empty." }
    if ($configErrors.Count -gt 0) {
        Write-Error "One or more required parameters are missing:`n$($configErrors -join "`n")"
        return
    }

    # Validate Azure login
    $azContext = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $azContext) {
        Write-Warning "You are not logged in to Azure. Please run 'Connect-AzAccount' first."
        return
    }

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

    Write-Output "Log file: $LogFile"
    Write-Log "Run initiated | SubscriptionId: $SubscriptionId | ResourceGroup: $ResourceGroupName | Workspace: $WorkspaceName | SourceFilter: $(if ($SourceFilter) { $SourceFilter -join ', ' } else { '(all sources)' })"

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
            [string]$Scope,
            [switch]$IsMinimumCount
        )

        $title   = "Confirm Sentinel Indicator Deletion"
        $countText = if ($IsMinimumCount) { "at least $Count" } else { "$Count" }
        $scopeText = $Scope
        if ($scopeText -and $scopeText -notmatch '[.!?]$') {
            $scopeText += "."
        }
        $message = "You are about to delete $countText indicator(s) $scopeText`n`nThis action cannot be undone."
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

    $logSourceFilter = if ($SourceFilter) { $SourceFilter -join ', ' } else { '(all sources)' }

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
    $script:QueryBodyMode = $null
    $script:QueryApiVersion = $apiVersion
    $script:ListApiVersion = $apiVersion

    function Resolve-AbsoluteApiUri {
        param([string]$CandidateUri)

        if ([string]::IsNullOrWhiteSpace($CandidateUri)) { return $CandidateUri }
        if ([System.Uri]::IsWellFormedUriString($CandidateUri, [System.UriKind]::Absolute)) { return $CandidateUri }
        if ($CandidateUri.StartsWith('/')) { return "https://management.azure.com$CandidateUri" }
        return "https://management.azure.com/$CandidateUri"
    }

    function Get-IndicatorPage {
        <#
        .SYNOPSIS
            Queries a single page of threat intelligence indicators.
        #>
        param(
            [hashtable]$Headers,
            [string]$Uri,
            [string[]]$Source,
            [int]$Size,
            [string]$SkipToken
        )

        function New-QueryBody {
            param(
                [int]$PageSize,
                [string[]]$SourceNames,
                [string]$Token,
                [ValidateSet("legacy", "legacy-pascal", "legacy-no-sort", "sort-single", "sort-single-pascal", "singular-source", "source-string", "condition")]
                [string]$Mode
            )

            $body = [ordered]@{ pageSize = $PageSize }

            switch ($Mode) {
                "legacy" {
                    $body.sortBy = @(@{ itemKey = "lastUpdatedTimeUtc"; sortOrder = "descending" })
                    if ($SourceNames) { $body.sources = @($SourceNames) }
                }
                "legacy-pascal" {
                    $body.sortBy = @(@{ itemKey = "LastUpdatedTimeUtc"; sortOrder = "Descending" })
                    if ($SourceNames) { $body.sources = @($SourceNames) }
                }
                "legacy-no-sort" {
                    if ($SourceNames) { $body.sources = @($SourceNames) }
                }
                "sort-single" {
                    $body.sortBy = @{ itemKey = "lastUpdatedTimeUtc"; sortOrder = "descending" }
                    if ($SourceNames) { $body.sources = @($SourceNames) }
                }
                "sort-single-pascal" {
                    $body.sortBy = @{ itemKey = "LastUpdatedTimeUtc"; sortOrder = "Descending" }
                    if ($SourceNames) { $body.sources = @($SourceNames) }
                }
                "singular-source" {
                    if ($SourceNames) { $body.source = @($SourceNames) }
                }
                "source-string" {
                    if ($SourceNames -and $SourceNames.Count -gt 0) { $body.source = [string]$SourceNames[0] }
                }
                "condition" {
                    if ($SourceNames -and $SourceNames.Count -gt 0) {
                        $clauses = @()
                        foreach ($src in $SourceNames) {
                            $clauses += @{
                                field    = "source"
                                operator = "Equals"
                                values   = @("$src")
                            }
                        }
                        $body.condition = @{
                            conditionConnective = "Or"
                            clauses             = $clauses
                        }
                    }
                }
            }

            if ($Token) { $body.skipToken = $Token }
            return $body
        }

        $effectiveSize = $Size
        while ($true) {
            $allModes = @("legacy", "legacy-pascal", "legacy-no-sort", "sort-single", "sort-single-pascal", "singular-source", "source-string", "condition")
            $probeModes = if ($script:QueryBodyMode) {
                @($script:QueryBodyMode) + @($allModes | Where-Object { $_ -ne $script:QueryBodyMode })
            }
            else {
                $allModes
            }

            $response = $null
            $usedMode = $null
            $lastError = $null

            foreach ($mode in $probeModes) {
                $body = New-QueryBody -PageSize $effectiveSize -SourceNames $Source -Token $SkipToken -Mode $mode

                $requestUri = Resolve-AbsoluteApiUri -CandidateUri $Uri

                try {
                    $response = Invoke-RestMethod -Uri $requestUri `
                                                  -Headers $Headers `
                                                  -Method POST `
                                                  -Body ($body | ConvertTo-Json -Depth 10) `
                                                  -ErrorAction Stop
                    $usedMode = $mode
                    break
                }
                catch {
                    $lastError = $_
                    $statusCode = 0
                    try {
                        if ($_.Exception.Response) {
                            if ($_.Exception.Response.StatusCode -is [int]) {
                                $statusCode = [int]$_.Exception.Response.StatusCode
                            }
                            elseif ($_.Exception.Response.StatusCode.PSObject.Properties.Name -contains 'value__') {
                                $statusCode = [int]$_.Exception.Response.StatusCode.value__
                            }
                            else {
                                $statusCode = [int]$_.Exception.Response.StatusCode
                            }
                        }
                    } catch {}
                    if (-not $statusCode) {
                        $errText = ""
                        try { $errText = ($_ | Out-String) } catch {}
                        if (($_.Exception.Message -match '\b400\b') -or ($errText -match '\b400\b|Bad Request')) {
                            $statusCode = 400
                        }
                    }

                    # On 400, try other payload schema variants before failing.
                    if ($statusCode -eq 400 -and $probeModes.Count -gt 1) {
                        continue
                    }

                    throw
                }
            }

            if (-not $response) {
                $statusCode = 0
                if ($lastError) {
                    try {
                        if ($lastError.Exception.Response) {
                            if ($lastError.Exception.Response.StatusCode -is [int]) {
                                $statusCode = [int]$lastError.Exception.Response.StatusCode
                            }
                            elseif ($lastError.Exception.Response.StatusCode.PSObject.Properties.Name -contains 'value__') {
                                $statusCode = [int]$lastError.Exception.Response.StatusCode.value__
                            }
                            else {
                                $statusCode = [int]$lastError.Exception.Response.StatusCode
                            }
                        }
                    } catch {}

                    if (-not $statusCode) {
                        $errText = ""
                        try { $errText = ($lastError | Out-String) } catch {}
                        if (($lastError.Exception.Message -match '\b400\b') -or ($errText -match '\b400\b|Bad Request')) {
                            $statusCode = 400
                        }
                    }

                    if ($statusCode -eq 400 -and $effectiveSize -gt 100) {
                        $nextSize = [math]::Max([int][math]::Floor($effectiveSize / 2), 100)
                        if ($nextSize -lt $effectiveSize) {
                            Write-Output "INFO: API rejected page size $effectiveSize (400). Retrying with $nextSize."
                            $effectiveSize = $nextSize
                            continue
                        }
                    }

                    if ($statusCode -eq 400) {
                        $versionCandidates = @()
                        foreach ($candidate in @("2025-09-01", "2025-07-01-preview", "2024-09-01-preview")) {
                            if ($candidate -and ($candidate -ne $script:QueryApiVersion)) { $versionCandidates += $candidate }
                        }

                        foreach ($candidateVersion in $versionCandidates) {
                            $candidateUri = if ($Uri -match '([?&])api-version=[^&]+') {
                                [regex]::Replace($Uri, '([?&])api-version=[^&]+', "`$1api-version=$candidateVersion")
                            }
                            else {
                                "$Uri$(if ($Uri -match '\?') { '&' } else { '?' })api-version=$candidateVersion"
                            }

                            try {
                                $candidateBody = New-QueryBody -PageSize $effectiveSize -SourceNames $Source -Token $SkipToken -Mode "legacy-no-sort"
                                $candidateResponse = Invoke-RestMethod -Uri $candidateUri `
                                                                       -Headers $Headers `
                                                                       -Method POST `
                                                                       -Body ($candidateBody | ConvertTo-Json -Depth 10) `
                                                                       -ErrorAction Stop
                                $script:QueryApiVersion = $candidateVersion
                                $response = $candidateResponse
                                $usedMode = "legacy-no-sort"
                                Write-Output "INFO: Using query API version '$candidateVersion'."
                                break
                            }
                            catch {}
                        }

                        if ($response) { break }
                    }

                    throw $lastError
                }
                throw "Query request failed for unknown reason."
            }

            if (-not $script:QueryBodyMode) {
                $script:QueryBodyMode = $usedMode
                Write-Output "INFO: Using query payload mode '$usedMode'."
            }

            break
        }

        $nextLink = $null
        foreach ($linkKey in @("nextLink", "@odata.nextLink", "odata.nextLink", "nextPageLink")) {
            $prop = $response.PSObject.Properties | Where-Object { $_.Name -ieq $linkKey } | Select-Object -First 1
            if ($prop -and $prop.Value) {
                $nextLink = Resolve-AbsoluteApiUri -CandidateUri ([string]$prop.Value)
                break
            }
        }

        if (-not $nextLink) {
            foreach ($tokenKey in @("skipToken", "nextSkipToken", "continuationToken", "nextContinuationToken")) {
                $prop = $response.PSObject.Properties | Where-Object { $_.Name -ieq $tokenKey } | Select-Object -First 1
                if ($prop -and $prop.Value) {
                    $encodedToken = [System.Uri]::EscapeDataString([string]$prop.Value)
                    $sep = if ($Uri -match '\?') { '&' } else { '?' }
                    $nextLink = "$Uri${sep}`$skipToken=$encodedToken"
                    break
                }
            }
        }

        $items = @($response.value)

        [PSCustomObject]@{
            Items         = $items
            NextLink      = $nextLink
            EffectiveSize = $effectiveSize
        }
    }

    function Get-IndicatorTotalCount {
        <#
        .SYNOPSIS
            Gets an exact TI object count using the preview count endpoint.
        #>
        param(
            [hashtable]$Headers,
            [string]$SubscriptionId,
            [string]$ResourceGroupName,
            [string]$WorkspaceName,
            [string[]]$Source
        )

        $countUri = "https://management.azure.com/subscriptions/$SubscriptionId" +
                    "/resourceGroups/$ResourceGroupName" +
                    "/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName" +
                    "/providers/Microsoft.SecurityInsights/threatIntelligence/main/count?api-version=2025-07-01-preview"

        $body = $null
        if ($Source -and $Source.Count -gt 0) {
            $clauses = @()
            foreach ($src in $Source) {
                $clauses += @{
                    field    = "source"
                    operator = "Equals"
                    values   = @("$src")
                }
            }
            $body = @{
                condition = @{
                    conditionConnective = "Or"
                    clauses             = $clauses
                }
            }
        }

        try {
            if ($body) {
                $resp = Invoke-RestMethod -Uri $countUri `
                                          -Headers $Headers `
                                          -Method POST `
                                          -Body ($body | ConvertTo-Json -Depth 10) `
                                          -ErrorAction Stop
            }
            else {
                $resp = Invoke-RestMethod -Uri $countUri `
                                          -Headers $Headers `
                                          -Method POST `
                                          -ErrorAction Stop
            }

            if ($null -ne $resp.count) {
                return [int64]$resp.count
            }
        }
        catch {
            return $null
        }

        return $null
    }

    function Get-IndicatorPageList {
        <#
        .SYNOPSIS
            Lists indicators using GET endpoint as a fallback when queryIndicators POST is rejected.
        #>
        param(
            [hashtable]$Headers,
            [string]$Uri,
            [int]$Size
        )

        $requestUri = $Uri
        if (-not $requestUri) {
            # Some tenants reject $top on this endpoint with HTTP 400; rely on server paging via nextLink.
            $requestUri = "$deleteBase?api-version=$($script:ListApiVersion)"
        }
        $requestUri = Resolve-AbsoluteApiUri -CandidateUri $requestUri

        $response = $null
        try {
            $response = Invoke-RestMethod -Uri $requestUri -Headers $Headers -Method GET -ErrorAction Stop
        }
        catch {
            $statusCode = 0
            try {
                if ($_.Exception.Response) {
                    if ($_.Exception.Response.StatusCode -is [int]) {
                        $statusCode = [int]$_.Exception.Response.StatusCode
                    }
                    elseif ($_.Exception.Response.StatusCode.PSObject.Properties.Name -contains 'value__') {
                        $statusCode = [int]$_.Exception.Response.StatusCode.value__
                    }
                    else {
                        $statusCode = [int]$_.Exception.Response.StatusCode
                    }
                }
            } catch {}

            if (-not $statusCode) {
                $errText = ""
                try { $errText = ($_ | Out-String) } catch {}
                if (($_.Exception.Message -match '\b400\b') -or ($errText -match '\b400\b|Bad Request')) {
                    $statusCode = 400
                }
            }

            if ($statusCode -eq 400) {
                foreach ($candidateVersion in @("2025-09-01", "2025-07-01-preview", "2024-09-01-preview")) {
                    if ($candidateVersion -eq $script:ListApiVersion) { continue }
                    $candidateUri = if ($requestUri -match '([?&])api-version=[^&]+') {
                        [regex]::Replace($requestUri, '([?&])api-version=[^&]+', "`$1api-version=$candidateVersion")
                    }
                    else {
                        "$requestUri$(if ($requestUri -match '\?') { '&' } else { '?' })api-version=$candidateVersion"
                    }

                    try {
                        $candidateUri = Resolve-AbsoluteApiUri -CandidateUri $candidateUri
                        $response = Invoke-RestMethod -Uri $candidateUri -Headers $Headers -Method GET -ErrorAction Stop
                        $script:ListApiVersion = $candidateVersion
                        Write-Output "INFO: Using list API version '$candidateVersion'."
                        break
                    }
                    catch {}
                }
            }

            if (-not $response) { throw }
        }

        $nextLink = $null
        foreach ($linkKey in @("nextLink", "@odata.nextLink", "odata.nextLink", "nextPageLink")) {
            $prop = $response.PSObject.Properties | Where-Object { $_.Name -ieq $linkKey } | Select-Object -First 1
            if ($prop -and $prop.Value) {
                $nextLink = Resolve-AbsoluteApiUri -CandidateUri ([string]$prop.Value)
                break
            }
        }

        [PSCustomObject]@{
            Items         = @($response.value)
            NextLink      = $nextLink
            EffectiveSize = $Size
        }
    }

    function New-FetchState {
        param(
            [string]$InitialQueryUri,
            [string[]]$Filter
        )

        return [ordered]@{
            SourceFilter               = $Filter
            UseClientSideSourceFilter  = $false
            UseListGetFallback         = $false
            ScanPageUri                = $InitialQueryUri
            ListNextPageUri            = $null
            SeenScanPageLink           = [System.Collections.Generic.HashSet[string]]::new()
            SeenListPageLink           = [System.Collections.Generic.HashSet[string]]::new()
            HadContinuation            = $false
        }
    }

    function Get-ResilientIndicatorBatch {
        param(
            [hashtable]$Headers,
            [hashtable]$State,
            [int]$Size,
            [hashtable]$Sync
        )

        while ($true) {
            try {
                if ($Sync) { $Sync.QuerySubmitted++ }

                if ($State.UseClientSideSourceFilter) {
                    if ($State.UseListGetFallback) {
                        $pageResult = Get-IndicatorPageList -Headers $Headers -Uri $State.ListNextPageUri -Size $Size
                    }
                    else {
                        $pageResult = Get-IndicatorPage -Headers $Headers -Uri $State.ScanPageUri -Source $null -Size $Size -SkipToken $null
                    }

                    $rawBatch = @($pageResult.Items)
                    $batch = @($rawBatch | Where-Object { $State.SourceFilter -contains $_.properties.source })
                    $batchCount = $batch.Count

                    if ($State.UseListGetFallback) {
                        $State.ListNextPageUri = $pageResult.NextLink
                        if ($State.ListNextPageUri) {
                            $State.HadContinuation = $true
                            if (-not $State.SeenListPageLink.Add($State.ListNextPageUri)) {
                                Write-Output "WARNING: Duplicate pagination link received during list fallback scan; stopping to prevent loop."
                                $State.ListNextPageUri = $null
                            }
                        }
                    }
                    else {
                        $State.ScanPageUri = $pageResult.NextLink
                        if ($State.ScanPageUri) {
                            $State.HadContinuation = $true
                            if (-not $State.SeenScanPageLink.Add($State.ScanPageUri)) {
                                Write-Output "WARNING: Duplicate pagination link received during client-side source filtering; stopping to prevent loop."
                                $State.ScanPageUri = $null
                            }
                        }
                    }
                }
                else {
                    $pageResult = Get-IndicatorPage -Headers $Headers -Uri $queryUri -Source $State.SourceFilter -Size $Size -SkipToken $null
                    $batch = @($pageResult.Items)
                    $batchCount = $batch.Count
                }

                $effectiveSize = $pageResult.EffectiveSize

                if ($batchCount -eq 0) {
                    if ($State.UseClientSideSourceFilter -and (($State.UseListGetFallback -and $State.ListNextPageUri) -or ((-not $State.UseListGetFallback) -and $State.ScanPageUri))) {
                        # Current page had no matching source; continue scanning remaining pages.
                        continue
                    }

                    return [PSCustomObject]@{
                        FetchFailed    = $false
                        EndOfStream    = $true
                        Batch          = @()
                        BatchCount     = 0
                        EffectiveSize  = $effectiveSize
                        FailureStage   = $null
                        FailureStatusCode = $null
                        FailureUri     = $null
                        ErrorMessage   = $null
                        ErrorDetail    = $null
                    }
                }

                return [PSCustomObject]@{
                    FetchFailed    = $false
                    EndOfStream    = $false
                    Batch          = $batch
                    BatchCount     = $batchCount
                    EffectiveSize  = $effectiveSize
                    FailureStage   = $null
                    FailureStatusCode = $null
                    FailureUri     = $null
                    ErrorMessage   = $null
                    ErrorDetail    = $null
                }
            }
            catch {
                $errorDetail = ""
                try {
                    $reader      = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
                    $errorDetail = $reader.ReadToEnd()
                } catch {}

                $statusCode = 0
                try {
                    if ($_.Exception.Response) {
                        if ($_.Exception.Response.StatusCode -is [int]) {
                            $statusCode = [int]$_.Exception.Response.StatusCode
                        }
                        elseif ($_.Exception.Response.StatusCode.PSObject.Properties.Name -contains 'value__') {
                            $statusCode = [int]$_.Exception.Response.StatusCode.value__
                        }
                        else {
                            $statusCode = [int]$_.Exception.Response.StatusCode
                        }
                    }
                } catch {}

                if (-not $statusCode) {
                    $errText = ""
                    try { $errText = ($_ | Out-String) } catch {}
                    if (($_.Exception.Message -match '\b400\b') -or ($errText -match '\b400\b|Bad Request')) {
                        $statusCode = 400
                    }
                }

                if (($statusCode -eq 400) -and (-not $State.UseClientSideSourceFilter) -and $State.SourceFilter -and $State.SourceFilter.Count -gt 0) {
                    Write-Warning "Source-filtered query rejected (400). Falling back to client-side source filtering with paged scan."
                    $State.UseClientSideSourceFilter = $true
                    $State.ScanPageUri = $queryUri
                    $State.SeenScanPageLink.Clear()
                    continue
                }

                if (($statusCode -eq 400) -and $State.UseClientSideSourceFilter -and (-not $State.UseListGetFallback)) {
                    Write-Warning "Query scan endpoint rejected (400). Falling back to indicator list GET scan."
                    $State.UseListGetFallback = $true
                    $State.ListNextPageUri = $null
                    $State.SeenListPageLink.Clear()
                    continue
                }

                $failureStage = if (-not $State.UseClientSideSourceFilter) { "filtered-query" }
                                elseif (-not $State.UseListGetFallback) { "client-side-query-scan" }
                                else { "list-get-scan" }
                $failureUri = if ($State.UseListGetFallback) { $State.ListNextPageUri } else { $State.ScanPageUri }

                return [PSCustomObject]@{
                    FetchFailed    = $true
                    EndOfStream    = $true
                    Batch          = @()
                    BatchCount     = 0
                    EffectiveSize  = $Size
                    FailureStage   = $failureStage
                    FailureStatusCode = $statusCode
                    FailureUri     = $failureUri
                    ErrorMessage   = $_.Exception.Message
                    ErrorDetail    = $errorDetail
                }
            }
        }
    }

    if ($ListOnly) {
        Write-Output "Querying indicators$(if ($SourceFilter) { " for source(s): $($SourceFilter -join ', ')" } else { " (all sources)" })..."

        $allIndicators = [System.Collections.Generic.List[object]]::new()
        $page          = 1
        $fetchState    = New-FetchState -InitialQueryUri $queryUri -Filter $SourceFilter
        $hadPaginationToken = $false

        while ($true) {
            $fetchResult = Get-ResilientIndicatorBatch -Headers $headers -State $fetchState -Size $PageSize -Sync $null
            if ($fetchResult.FetchFailed) {
                Write-Output "ERROR querying page $page — $($fetchResult.ErrorMessage)"
                if ($fetchResult.ErrorDetail) { Write-Output "API detail: $($fetchResult.ErrorDetail)" }
                return
            }
            if ($fetchResult.EndOfStream) { break }

            $batch = $fetchResult.Batch
            $batchCount = $fetchResult.BatchCount
            $PageSize = $fetchResult.EffectiveSize
            $hadPaginationToken = $fetchState.HadContinuation

            $allIndicators.AddRange([object[]]@($batch))
            if ($page -eq 1) {
                Write-Log "Page size probe | Requested: $PageSize | API returned: $batchCount per page"
                if ($batchCount -lt $PageSize) {
                    Write-Output "INFO: Requested page size $PageSize but API returned $batchCount — API may be capping the page size."
                }
            }
            Write-Progress -Activity "Collecting Threat Intelligence Indicators" `
                           -Id $ProgressIdListCollect `
                           -Status "Page $page | Fetched: $batchCount | Total so far: $($allIndicators.Count)" `
                           -PercentComplete 0
            $page++
        }

        Write-Progress -Activity "Collecting Threat Intelligence Indicators" -Id $ProgressIdListCollect -Completed

        if (-not $hadPaginationToken -and $allIndicators.Count -ge $PageSize) {
            Write-Output "WARNING: API returned a full page ($PageSize) but no continuation token. Results may be capped to one page."
        }

        if ($allIndicators.Count -eq 0) {
            Write-Output "No indicators found$(if ($SourceFilter) { " for source(s) '$($SourceFilter -join "', '")'" })."
            Write-Log "Completed | Mode: ListOnly | SourceFilter: $logSourceFilter | Found: 0"
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
    Write-Status -Level INFO -Message "Source filter: $(if ($SourceFilter) { $SourceFilter -join ', ' } else { "(all sources)" })"
    Write-Status -Level INFO -Message "Execution mode: $(if ($PSVersionTable.PSVersion.Major -ge 7 -and $ThrottleLimit -gt 1) { "Parallel (Throttle=$ThrottleLimit)" } else { "Sequential" })"
    Write-Output "====================="

    # Pass 1: Count indicators using exact count API; fallback to pagination count when unavailable.
    Write-Output "Counting indicators$(if ($SourceFilter) { " for source(s): $($SourceFilter -join ', ')" } else { " (all sources)" })..."

    $countIsExact = $false
    $totalFound   = Get-IndicatorTotalCount -Headers $headers `
                                            -SubscriptionId $SubscriptionId `
                                            -ResourceGroupName $ResourceGroupName `
                                            -WorkspaceName $WorkspaceName `
                                            -Source $SourceFilter

    if ($null -ne $totalFound) {
        $countIsExact = $true
        Write-Status -Level PASS -Message "Exact count retrieved via TI count API: $totalFound"
    }
    else {
        Write-Output "WARNING: Exact count API unavailable. Falling back to pagination-based counting."
    }

    if (-not $countIsExact) {

        $totalFound    = 0
        $countPage     = 1
        $nextPageUri   = $queryUri
        $seenPageLink  = [System.Collections.Generic.HashSet[string]]::new()
        $firstBatch    = $true

        do {
            try {
                $pageResult = Get-IndicatorPage -Headers $headers -Uri $nextPageUri -Source $SourceFilter -Size $PageSize -SkipToken $null
                $batchCount = if ($pageResult.Items) { @($pageResult.Items).Count } else { 0 }
                $PageSize   = $pageResult.EffectiveSize
                $nextPageUri = $pageResult.NextLink

                if ($batchCount -gt 0) {
                    if ($firstBatch) {
                        $firstBatch = $false
                        Write-Log "Page size probe | Requested: $PageSize | API returned: $batchCount per page"
                        if ($batchCount -lt $PageSize) {
                            Write-Output "INFO: Requested page size $PageSize but API returned $batchCount — API may be capping the page size."
                        }
                    }
                    $totalFound += $batchCount
                    Write-Progress -Activity "Counting Indicators" `
                                   -Id $ProgressIdDeleteCollect `
                                   -Status "Page $countPage | Counted so far: $totalFound" `
                                   -PercentComplete 0
                    $countPage++
                }

                if ($nextPageUri -and (-not $seenPageLink.Add($nextPageUri))) {
                    Write-Output "WARNING: Duplicate pagination link received during count; stopping to prevent loop."
                    break
                }
            }
            catch {
                $errorDetail = ""
                try {
                    $reader      = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
                    $errorDetail = $reader.ReadToEnd()
                } catch {}
                Write-Output "ERROR counting page $countPage — $($_.Exception.Message)"
                if ($errorDetail) { Write-Output "API detail: $errorDetail" }
                return
            }
        } while ($nextPageUri)

        Write-Progress -Activity "Counting Indicators" -Id $ProgressIdDeleteCollect -Completed
    }

    if ($totalFound -eq 0) {
        Write-Output "No indicators found$(if ($SourceFilter) { " for source(s) '$($SourceFilter -join "', '")'" }). Nothing to delete."
        Write-Log "Completed | Mode: Delete | SourceFilter: $logSourceFilter | Deleted: 0 | Nothing to delete"
        return
    }

    Write-Output ""
    if ($countIsExact) {
        Write-Output "Found $totalFound indicator(s)$(if ($SourceFilter) { " from source(s) '$($SourceFilter -join "', '")'" })."
    } else {
        Write-Warning "Initial count is incomplete due to pagination behavior. Continuing with a minimum count of $totalFound."
        Write-Output "Found at least $totalFound indicator(s)$(if ($SourceFilter) { " from source(s) '$($SourceFilter -join "', '")'" })."
    }
    Write-Output ""
    Write-Log "Started | Mode: Delete | SourceFilter: $logSourceFilter | Found: $(if ($countIsExact) { $totalFound } else { ">=$totalFound (count incomplete)" })"

    # Confirm before deleting
    $scopeMsg = if ($SourceFilter) { "from source(s) '$($SourceFilter -join "', '")'" } else { "from ALL sources" }
    if (-not $countIsExact) {
        $scopeMsg = "$scopeMsg`n`nNote: initial count is a minimum estimate due to pagination behavior."
    }
    if ($Force) {
        $confirmed = $true
    } else {
        $confirmed = Confirm-Deletion -Count $totalFound -Scope $scopeMsg -IsMinimumCount:(-not $countIsExact)
    }

    if (-not $confirmed) {
        Write-Output "Aborted. No indicators were deleted."
        Write-Log "Aborted | Mode: Delete | SourceFilter: $logSourceFilter | Deleted: 0"
        return
    }

    # Pass 2: Fetch one page at a time and delete it, then re-query from the start.
    # Not using a skipToken between batches avoids pagination inconsistency after deletions.
    $sync        = [hashtable]::Synchronized(@{ Deleted = 0; Failed = 0; Processed = 0; DeleteSubmitted = 0; QuerySubmitted = 0; CountSubmitted = 0; Retry429 = 0 })
    $failedBag   = [System.Collections.Concurrent.ConcurrentBag[string]]::new()
    $startTime   = [datetime]::UtcNow
    $useParallel = ($PSVersionTable.PSVersion.Major -ge 7) -and ($ThrottleLimit -gt 1)

    Write-Output ""
    if ($useParallel) {
        Write-Output "Running parallel deletes (throttle: $ThrottleLimit concurrent requests)..."
    } else {
        Write-Output "Running sequential deletes..."
    }
    Write-Output ""
    
    $globalStartTime      = [datetime]::UtcNow
    $lastProgressTime     = [datetime]::UtcNow
    $progressIntervalSec  = 30
    $tokenAcquiredAt      = [datetime]::UtcNow   # token was just fetched above before confirmation
    $tokenRefreshMinutes  = 45                   # Az tokens last ~60 min; refresh at 45
    $printedRateLimitHeaders = $false            # print detailed 429 headers once for diagnostics
    $fetchBatchFailed     = $false
    $fetchBatchErrorText  = $null
    $endedByRemainingProbe = $false
    $fetchState           = New-FetchState -InitialQueryUri $queryUri -Filter $SourceFilter
    $fetchRetryCount      = 0
    $fetchRetryDelaysSec  = @(15, 30, 60, 120, 180) # progressive back-off delays between retries
    $fetchRetryMaxAttempts = $fetchRetryDelaysSec.Count

    function Write-DeleteProgress {
        param([switch]$Force)

        $now = [datetime]::UtcNow
        if (-not $Force -and (($now - $lastProgressTime).TotalSeconds -lt $progressIntervalSec)) {
            return
        }

        $elapsed = ($now - $globalStartTime).TotalSeconds
        $rate = if ($elapsed -gt 0 -and $sync.Processed -gt 0) { $sync.Processed / $elapsed } else { 0 }
        $remaining = [math]::Max($totalFound - $sync.Processed, 0)
        $etaSec = if ($rate -gt 0) { [math]::Round($remaining / $rate) } else { 0 }
        $etaStr = if ($remaining -gt 0) {
            if ($etaSec -ge 3600)  { "{0}h {1}m" -f [int]($etaSec/3600), [int](($etaSec%3600)/60) }
            elseif ($etaSec -ge 60) { "{0}m {1}s" -f [int]($etaSec/60), $etaSec%60 }
            else { "{0}s" -f $etaSec }
        } else { "Done" }
        $ts = Get-Date -Format 'HH:mm:ss'
        $rateStr = if ($rate -gt 0) { "{0:F1}/s" -f $rate } else { "--" }
        Write-Output "[$ts] Progress: Deleted=$($sync.Deleted) | Failed=$($sync.Failed) | Processed=$($sync.Processed)/$totalFound | ReqSubmitted(D/Q)=$($sync.DeleteSubmitted)/$($sync.QuerySubmitted) | 429Retries=$($sync.Retry429) | Rate=$rateStr | ETA=$etaStr"
        $lastProgressTime = $now
    }

    while ($true) {
        # Fetch only the first filtered page each iteration; after deletion, the next
        # first page naturally contains the next set to process. This avoids unstable
        # continuation links while still draining the source.
        if (([datetime]::UtcNow - $tokenAcquiredAt).TotalMinutes -ge $tokenRefreshMinutes) {
            $freshToken = Get-BearerToken
            if ($freshToken) {
                $headers["Authorization"] = "Bearer $freshToken"
                $tokenAcquiredAt = [datetime]::UtcNow
            }
        }

        $fetchResult = Get-ResilientIndicatorBatch -Headers $headers -State $fetchState -Size $PageSize -Sync $sync
        if ($fetchResult.FetchFailed) {
            $stage = if ($fetchResult.FailureStage) { [string]$fetchResult.FailureStage } else { "unknown" }
            $activeUri = if ($fetchResult.FailureUri) { [string]$fetchResult.FailureUri } else { $null }
            $uriPreview = if ($activeUri) {
                if ($activeUri.Length -gt 180) { "$($activeUri.Substring(0, 180))..." } else { $activeUri }
            } else {
                "(null)"
            }
            $failureStatus = 0
            try { $failureStatus = [int]$fetchResult.FailureStatusCode } catch {}
            Write-Output "INFO: Fetch diagnostic | Stage=$stage | Status=$failureStatus | QueryMode=$script:QueryBodyMode | QueryApiVersion=$script:QueryApiVersion | ListApiVersion=$script:ListApiVersion | PageSize=$PageSize | Processed=$($sync.Processed) | Uri=$uriPreview"

            # Probe remaining count to distinguish endpoint instability from true remaining workload.
            $sync.CountSubmitted++
            $remainingProbe = Get-IndicatorTotalCount -Headers $headers `
                                                    -SubscriptionId $SubscriptionId `
                                                    -ResourceGroupName $ResourceGroupName `
                                                    -WorkspaceName $WorkspaceName `
                                                    -Source $SourceFilter
            if ($null -ne $remainingProbe) {
                Write-Output "INFO: Fetch failure probe | Remaining=$remainingProbe"
                if ([int64]$remainingProbe -eq 0) {
                    Write-Output "INFO: Remaining count is zero. Treating run as complete despite fetch endpoint errors."
                    $endedByRemainingProbe = $true
                    $countIsExact = $true
                    $totalFound = $sync.Processed
                    break
                }
            }

            if ($fetchRetryCount -lt $fetchRetryMaxAttempts) {
                if ($PageSize -gt 10) {
                    $newPageSize = if ($PageSize -gt 50) { 50 } elseif ($PageSize -gt 25) { 25 } else { 10 }
                    if ($newPageSize -lt $PageSize) {
                        Write-Warning "Reducing page size from $PageSize to $newPageSize after fetch failure to improve endpoint compatibility."
                        $PageSize = $newPageSize
                    }
                }
                $delaySec = $fetchRetryDelaysSec[$fetchRetryCount]
                $fetchRetryCount++
                $ts = Get-Date -Format 'HH:mm:ss'
                Write-Warning "[$ts] All fetch paths returned 400 (attempt $fetchRetryCount/$fetchRetryMaxAttempts). Waiting ${delaySec}s before retrying..."
                if ($fetchResult.ErrorDetail) { Write-Output "  API detail: $($fetchResult.ErrorDetail)" }
                Start-Sleep -Seconds $delaySec

                # Refresh the token in case the prior failures were auth-related.
                $freshToken = Get-BearerToken
                if ($freshToken) { $headers["Authorization"] = "Bearer $freshToken" }
                # Clear the cached query-body mode so the full payload-mode probe runs fresh.
                $script:QueryBodyMode   = $null
                $script:QueryApiVersion = $apiVersion
                $script:ListApiVersion  = $apiVersion
                # Reset the fetch state so all fallback paths are re-attempted from scratch.
                $fetchState = New-FetchState -InitialQueryUri $queryUri -Filter $SourceFilter
                continue
            }

            Write-Output "ERROR fetching batch — $($fetchResult.ErrorMessage)"
            if ($fetchResult.ErrorDetail) { Write-Output "API detail: $($fetchResult.ErrorDetail)" }
            $fetchBatchFailed = $true
            $fetchBatchErrorText = if ($fetchResult.ErrorDetail) { $fetchResult.ErrorDetail } else { $fetchResult.ErrorMessage }
            break
        }
        if ($fetchRetryCount -gt 0) {
            $ts = Get-Date -Format 'HH:mm:ss'
            Write-Output "[$ts] Fetch recovered after $fetchRetryCount retr$(if ($fetchRetryCount -eq 1) { 'y' } else { 'ies' })."
        }
        $fetchRetryCount = 0

        if ($fetchResult.EndOfStream) { break }

        $batch      = $fetchResult.Batch
        $batchCount = $fetchResult.BatchCount
        $PageSize   = $fetchResult.EffectiveSize

        $processedBeforeBatch = $sync.Processed

        if ($useParallel) {
            $batchArray = @($batch)
            # Start with modest chunks so progress stays visible and request bursts stay controlled.
            $parallelChunkSize = [math]::Max(($ThrottleLimit * 4), 12)
            $parallelChunkSize = [math]::Min($parallelChunkSize, 40)
            $parallelChunkMin  = [math]::Max(($ThrottleLimit * 2), 6)
            $parallelChunkMax  = [math]::Max(($ThrottleLimit * 12), 40)
            $parallelInterChunkDelayMs = 150

            $offset = 0
            while ($offset -lt $batchArray.Count) {
                $chunkEnd = [math]::Min(($offset + $parallelChunkSize - 1), ($batchArray.Count - 1))
                $chunk = @($batchArray[$offset..$chunkEnd])
                $chunkLen = $chunk.Count
                $retry429BeforeChunk = $sync.Retry429

                $chunk | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
                $s          = $using:sync
                $bag        = $using:failedBag
                $hdrs       = $using:headers
                $delBase    = $using:deleteBase
                $apiVer     = $using:apiVersion

                $name      = $_.name
                $deleteUri = "$delBase/$name`?api-version=$apiVer"

                $getRetryAfter = {
                    param($ex)
                    $raw = $null
                    $ra = 10
                    try {
                        $raw = $ex.Exception.Response.Headers.GetValues("Retry-After") | Select-Object -First 1
                    } catch {}
                    if ($raw) {
                        $parsedSeconds = 0
                        if ([int]::TryParse([string]$raw, [ref]$parsedSeconds)) {
                            $ra = [math]::Max($parsedSeconds, 1)
                        }
                        else {
                            $retryAt = [datetimeoffset]::MinValue
                            if ([datetimeoffset]::TryParse([string]$raw, [ref]$retryAt)) {
                                $delta = [math]::Ceiling(($retryAt - [datetimeoffset]::UtcNow).TotalSeconds)
                                $ra = [math]::Max($delta, 1)
                            }
                        }
                    }
                    [pscustomobject]@{
                        Raw         = $raw
                        Seconds     = $ra
                        ResumeAtUtc = ([datetime]::UtcNow).AddSeconds($ra)
                    }
                }

                $maxRetries    = 3
                $attempt       = 0
                $deleteSuccess = $false
                $did401Refresh = $false

                do {
                    $attempt++
                    try {
                        $s.DeleteSubmitted++
                        Invoke-RestMethod -Uri $deleteUri -Headers $hdrs -Method DELETE -ErrorAction Stop | Out-Null
                        $s.Deleted++
                        $deleteSuccess = $true
                    }
                    catch {
                        $sc = if ($_.Exception.Response) { $_.Exception.Response.StatusCode.value__ } else { 0 }

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
                                    $attempt--
                                    continue
                                }
                            } catch {}
                        }

                        if ($sc -eq 429 -and $attempt -lt $maxRetries) {
                            $s.Retry429++
                            $retryInfo = & $getRetryAfter $_
                            $rawText = if ($retryInfo.Raw) { "'$($retryInfo.Raw)'" } else { "(missing)" }
                            $resumeUtc = $retryInfo.ResumeAtUtc.ToString("yyyy-MM-dd HH:mm:ss 'UTC'")
                            Write-Warning "  429 Too Many Requests — raw Retry-After=$rawText; interpreted wait=$($retryInfo.Seconds)s; resume ~$resumeUtc (attempt $attempt/$maxRetries)..."
                            Start-Sleep -Seconds $retryInfo.Seconds
                        }
                        else {
                            $errDetail = ""
                            try { $errDetail = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream()).ReadToEnd() } catch {}
                            $sd = if ($_.Exception.Response) { $_.Exception.Response.StatusCode.ToString() } else { $_.Exception.Message }
                            $d  = if ($errDetail) { $errDetail } elseif ($_.Exception.Message) { $_.Exception.Message } else { "" }
                            $s.Failed++
                            $bag.Add($name)
                            Write-Warning "  FAILED [$sc $sd] $name$(if ($d) { " — $d" })"
                            $deleteSuccess = $true
                        }
                    }
                } while (-not $deleteSuccess)

                $s.Processed++
            }

                $retry429AfterChunk = $sync.Retry429
                $chunk429 = $retry429AfterChunk - $retry429BeforeChunk
                if ($chunk429 -gt 0) {
                    # If the current burst produced 429s, reduce chunk size and add cooldown.
                    $parallelChunkSize = [math]::Max([int][math]::Floor($parallelChunkSize / 2), $parallelChunkMin)
                    $cooldownMs = [math]::Min((300 * $chunk429), 3000)
                    Start-Sleep -Milliseconds $cooldownMs
                }
                elseif ($parallelChunkSize -lt $parallelChunkMax) {
                    # Slowly scale up when no rate limiting is observed.
                    $parallelChunkSize = [math]::Min(($parallelChunkSize + $ThrottleLimit), $parallelChunkMax)
                    Start-Sleep -Milliseconds $parallelInterChunkDelayMs
                }

                Write-DeleteProgress -Force
                $offset += $chunkLen
            }
        }
        else {
                foreach ($indicator in @($batch)) {
                $name      = $indicator.name
                $deleteUri = "$deleteBase/$name`?api-version=$apiVersion"

                $maxRetries    = 3
                $attempt       = 0
                $deleteSuccess = $false
                $did401Refresh = $false

                do {
                    $attempt++
                    try {
                        $sync.DeleteSubmitted++
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

                        if ($statusCode -eq 401 -and -not $did401Refresh) {
                            Write-Output "  INFO: Token expired, refreshing..."
                            $newToken = Get-BearerToken
                            if ($newToken) {
                                $headers["Authorization"] = "Bearer $newToken"
                                $did401Refresh = $true
                                $attempt--
                                continue
                            } else {
                                $errorDetail   = "Could not refresh access token."
                                $deleteSuccess = $true
                            }
                        }
                        elseif ($statusCode -eq 429 -and $attempt -lt $maxRetries) {
                            $sync.Retry429++
                            $retryAfter = 10
                            $retryAfterRaw = $null
                            try {
                                $raHeader = $_.Exception.Response.Headers.GetValues("Retry-After") | Select-Object -First 1
                                $retryAfterRaw = $raHeader
                                if ($raHeader) {
                                    $parsedSeconds = 0
                                    if ([int]::TryParse([string]$raHeader, [ref]$parsedSeconds)) {
                                        $retryAfter = [math]::Max($parsedSeconds, 1)
                                    }
                                    else {
                                        $retryAt = [datetimeoffset]::MinValue
                                        if ([datetimeoffset]::TryParse([string]$raHeader, [ref]$retryAt)) {
                                            $delta = [math]::Ceiling(($retryAt - [datetimeoffset]::UtcNow).TotalSeconds)
                                            $retryAfter = [math]::Max($delta, 1)
                                        }
                                    }
                                }
                            } catch {}
                            $ts = Get-Date -Format 'HH:mm:ss'
                            if (-not $printedRateLimitHeaders -and $_.Exception.Response) {
                                try {
                                    $respHeaders = $_.Exception.Response.Headers
                                    $headerKeys = @(
                                        "x-ms-ratelimit-remaining-subscription-writes",
                                        "x-ms-ratelimit-remaining-subscription-resource-requests",
                                        "x-ms-ratelimit-remaining-tenant-writes",
                                        "x-ms-ratelimit-remaining-tenant-resource-requests",
                                        "x-ms-request-id",
                                        "x-ms-correlation-request-id"
                                    )
                                    $headerParts = @()
                                    foreach ($headerKey in $headerKeys) {
                                        try {
                                            $headerValue = $respHeaders.GetValues($headerKey) | Select-Object -First 1
                                            if ($headerValue) { $headerParts += "$headerKey=$headerValue" }
                                        } catch {}
                                    }
                                    if ($headerParts.Count -gt 0) {
                                        Write-Output "[$ts] 429 headers: $($headerParts -join ' | ')"
                                        $printedRateLimitHeaders = $true
                                    }
                                } catch {}
                            }
                            $resumeUtc = ([datetime]::UtcNow).AddSeconds($retryAfter).ToString("yyyy-MM-dd HH:mm:ss 'UTC'")
                            $rawText = if ($retryAfterRaw) { "'$retryAfterRaw'" } else { "(missing)" }
                            Write-Output "[$ts] Rate limited (429) — raw Retry-After=$rawText; interpreted wait=${retryAfter}s; resume ~$resumeUtc (attempt $attempt/$maxRetries)..."
                            Start-Sleep -Seconds $retryAfter
                        }
                        else {
                            $sync.Failed++
                            $failedBag.Add($name)
                            $statusDesc = if ($_.Exception.Response) { $_.Exception.Response.StatusCode.ToString() } else { $_.Exception.Message }
                            $detail     = if ($errorDetail) { $errorDetail } elseif ($_.Exception.Message) { $_.Exception.Message } else { "" }
                            Write-Output "  FAILED [$statusCode $statusDesc] $name$(if ($detail) { " — $detail" })"
                            $deleteSuccess = $true
                        }
                    }
                } while (-not $deleteSuccess)

                $sync.Processed++
                # Proactive per-request throttle — paces DELETE calls to avoid 429 bursts
                Start-Sleep -Milliseconds 250
                Write-DeleteProgress
                }
        }

        if ($sync.Processed -le $processedBeforeBatch) {
            if ($fetchState.UseClientSideSourceFilter -and (($fetchState.UseListGetFallback -and $fetchState.ListNextPageUri) -or ((-not $fetchState.UseListGetFallback) -and $fetchState.ScanPageUri))) {
                continue
            }
            Write-Output "WARNING: No indicators were processed in this delete batch; stopping to avoid loop."
            break
        }

        # Deletions mutate the dataset, which can invalidate continuation links.
        # In fallback scan modes, restart from the first page each batch to avoid stale-token 400s.
        if ($fetchState.UseClientSideSourceFilter) {
            if ($fetchState.UseListGetFallback) {
                $fetchState.ListNextPageUri = $null
                $fetchState.SeenListPageLink.Clear()
            }
            else {
                $fetchState.ScanPageUri = $queryUri
                $fetchState.SeenScanPageLink.Clear()
            }
            $fetchState.HadContinuation = $false
        }

        if ($RecountAfterBatch) {
            $sync.CountSubmitted++
            $remainingCount = Get-IndicatorTotalCount -Headers $headers `
                                                    -SubscriptionId $SubscriptionId `
                                                    -ResourceGroupName $ResourceGroupName `
                                                    -WorkspaceName $WorkspaceName `
                                                    -Source $SourceFilter
            if ($null -ne $remainingCount) {
                $totalFound = $sync.Processed + [int64]$remainingCount
                $countIsExact = $true
                $ts = Get-Date -Format 'HH:mm:ss'
                Write-Output "[$ts] Recount: Remaining=$remainingCount | ReconciledTotal=$totalFound"
                if ($remainingCount -eq 0) {
                    break
                }
            }
        }
        
        # Delay between batches to avoid rate limiting
        Start-Sleep -Milliseconds 1000
    }

    $deleted   = $sync.Deleted
    $failed    = $sync.Failed
    $failedIds = [System.Collections.Generic.List[string]]$failedBag

    $totalElapsed = [datetime]::UtcNow - $startTime
    $elapsedStr   = if     ($totalElapsed.TotalHours -ge 1)  { "{0}h {1}m {2}s" -f [int]$totalElapsed.TotalHours, $totalElapsed.Minutes, $totalElapsed.Seconds }
                    elseif ($totalElapsed.TotalMinutes -ge 1) { "{0}m {1}s" -f $totalElapsed.Minutes, $totalElapsed.Seconds }
                    else                                       { "{0}s" -f $totalElapsed.Seconds }
    Write-Output ""
    Write-Output "===== Summary ====="
    Write-Output "Source filter : $(if ($SourceFilter) { $SourceFilter -join ', ' } else { "(all sources)" })"
    Write-Output "Total found   : $(if ($countIsExact) { "$totalFound" } else { ">=$totalFound (count incomplete)" })"
    Write-Output "Deleted       : $deleted"
    Write-Output "Failed        : $failed"
    Write-Output "Delete reqs   : $($sync.DeleteSubmitted)"
    Write-Output "Query reqs    : $($sync.QuerySubmitted)"
    Write-Output "Count reqs    : $($sync.CountSubmitted)"
    Write-Output "429 retries   : $($sync.Retry429)"
    Write-Output "Total reqs    : $($sync.DeleteSubmitted + $sync.QuerySubmitted + $sync.CountSubmitted)"
    Write-Output "Elapsed time  : $elapsedStr"

    $processedTotal = $deleted + $failed
    $countDelta = $totalFound - $processedTotal
    if ($endedByRemainingProbe) {
        $countDelta = 0
    }
    if ($countDelta -ne 0) {
        if ($processedTotal -eq 0 -and $fetchBatchFailed) {
            Write-Warning "Deletion run ended before any items were processed due to query failure. Skipping count reconciliation warning."
            if ($fetchBatchErrorText) {
                Write-Output "Last query error: $fetchBatchErrorText"
            }
            Write-Log "Count reconciliation skipped | Found: $totalFound | Processed: 0 | Reason: initial query failed"
            $countDelta = 0
        }
    }

    if ($countDelta -ne 0) {
        # Recount remaining indicators to verify whether mismatch is drift vs. an inaccurate initial count.
        # Use the same resilient fetch chain as the main delete loop.
        $remainingNow        = 0
        $recountFailed       = $false
        $recountErrorText    = $null
        $recountRetryCount   = 0
        $recountRetryDelays  = @(10, 20, 40)
        $recountMaxRetries   = $recountRetryDelays.Count
        $recountPageSize     = $PageSize
        $recountState        = New-FetchState -InitialQueryUri $queryUri -Filter $SourceFilter

        while ($true) {
            $recountResult = Get-ResilientIndicatorBatch -Headers $headers -State $recountState -Size $recountPageSize -Sync $sync
            if ($recountResult.FetchFailed) {
                if ($recountRetryCount -lt $recountMaxRetries) {
                    $retryDelay = $recountRetryDelays[$recountRetryCount]
                    $recountRetryCount++
                    Write-Output "INFO: Recount fetch failed. Retrying in ${retryDelay}s (attempt $recountRetryCount/$recountMaxRetries)."
                    Start-Sleep -Seconds $retryDelay
                    $freshToken = Get-BearerToken
                    if ($freshToken) { $headers["Authorization"] = "Bearer $freshToken" }
                    $script:QueryBodyMode   = $null
                    $script:QueryApiVersion = $apiVersion
                    $script:ListApiVersion  = $apiVersion
                    $recountState = New-FetchState -InitialQueryUri $queryUri -Filter $SourceFilter
                    continue
                }
                $recountFailed = $true
                $recountErrorText = if ($recountResult.ErrorDetail) { $recountResult.ErrorDetail } else { $recountResult.ErrorMessage }
                break
            }

            $recountRetryCount = 0

            if ($recountResult.EndOfStream) { break }

            $remainingNow += $recountResult.BatchCount
            $recountPageSize = $recountResult.EffectiveSize
        }

        if (-not $recountFailed) {
            $reconciledFound = $processedTotal + $remainingNow
            $reconciledDelta = $totalFound - $reconciledFound
            $looksLikeUnfilteredCount = $false
            if ($countIsExact -and $SourceFilter -and $SourceFilter.Count -gt 0) {
                $threshold = [math]::Max(100, [int][math]::Ceiling($reconciledFound * 0.05))
                $looksLikeUnfilteredCount = ([math]::Abs($reconciledDelta) -gt $threshold)
            }

            if ($looksLikeUnfilteredCount) {
                Write-Warning "Initial count API result appears inaccurate for source filter. API Found=$totalFound, Reconciled Found=$reconciledFound (Processed=$processedTotal, Remaining=$remainingNow)."
                Write-Output "Reconciled total : $reconciledFound"
            }
            else {
                Write-Warning "Count reconciliation mismatch detected. Found=$totalFound, Processed=$processedTotal (Delta=$countDelta). This can happen when indicators change during the run."
            }
            Write-Output "Remaining now : $remainingNow"
            Write-Log "Count reconciliation | Found: $totalFound | Processed: $processedTotal | Delta: $countDelta | RemainingNow: $remainingNow"
        }
        else {
            Write-Warning "Count reconciliation mismatch detected. Found=$totalFound, Processed=$processedTotal (Delta=$countDelta). Recount failed."
            if ($recountErrorText) { Write-Output "Recount last error: $recountErrorText" }
            Write-Log "Count reconciliation | Found: $totalFound | Processed: $processedTotal | Delta: $countDelta | RemainingNow: (recount failed)"
        }
    }

    if ($failedIds.Count -gt 0) {
        Write-Output ""
        Write-Output "Failed indicators:"
        $failedIds | ForEach-Object { Write-Output "  - $_" }
    }
    Write-Output "==================="
    Write-Log "Completed | Mode: Delete | SourceFilter: $logSourceFilter | Deleted: $deleted | Failed: $failed | Elapsed: $elapsedStr"
}
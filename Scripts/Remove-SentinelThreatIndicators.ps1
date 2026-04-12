function Remove-SentinelThreatIndicators {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    <#
    .SYNOPSIS
        Remove-SentinelThreatIndicators - Deletes threat intelligence indicators from a Microsoft Sentinel workspace.
    .PARAMETER SubscriptionId
        Azure subscription ID containing the Sentinel workspace.
    .PARAMETER ResourceGroupName
        Resource group name containing the Sentinel workspace.
    .PARAMETER WorkspaceName
        Log Analytics workspace name linked to Microsoft Sentinel.
    .PARAMETER SourceFilter
        Filter indicators by one or more source names.
        At least one non-empty source value is required; empty input is rejected for safety.
        One or more sources, for example:
        @("ThreatViewIPBlockList","ThreatViewURLBlockList") 
    .PARAMETER BatchSize
        Number of indicators to retrieve per API page. Defaults to 100.
    .PARAMETER ConcurrentWorkers
        Maximum concurrent DELETE workers.
        Default is 1 (sequential mode).
        Values greater than 1 enable parallel deletes on PowerShell 7+.
        This controls concurrency, while TargetDeleteRatePerSecond controls sustained throughput.
        Higher worker counts can improve throughput on high-latency runs but may increase burst
        pressure and throttling (HTTP 429).
    .PARAMETER TargetDeleteRatePerSecond
        Sustained DELETE request rate across the whole run.
        Start with 1.0 req/s as a safe baseline (~3600/hour).
        Higher values (for example 10.0 req/s) can speed up overall processing but increase
        the chance of throttling (HTTP 429), depending on tenant and subscription limits.
    .PARAMETER LogFile
        Path to the log file. Defaults to Remove-SentinelThreatIndicators.log in the script's folder.
    .PARAMETER ProgressRefreshIntervalSeconds
        Interval in seconds for pausing deletes briefly, recounting remaining indicators, and refreshing the delete progress bar.
    .PARAMETER ShowAPIWarnings
        When set, writes per-request 401/429 throttle diagnostics to the console. By default these messages are suppressed.
    #>
    param (
        [string]$SubscriptionId,
        [string]$ResourceGroupName,
        [string]$WorkspaceName,
        [string[]]$SourceFilter,
        [Alias('PageSize')]
        [int]$BatchSize = 100,
        [int]$ConcurrentWorkers = 1,
        [double]$TargetDeleteRatePerSecond = 1.0,
        [string]$LogFile = "",
        [int]$ProgressRefreshIntervalSeconds = 60,
        [switch]$ShowAPIWarnings = $false
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

    if ($PSVersionTable.PSVersion.Major -lt 7) {
        Write-Error "PowerShell 7.0 or later is required. Current version: $($PSVersionTable.PSVersion)"
        return
    }

    if ($null -ne $SourceFilter) {
        # Normalize source filter input: drop null/empty items and trim whitespace.
        $normalizedSourceFilter = @(
            $SourceFilter |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                ForEach-Object { $_.Trim() } |
                Where-Object { $_.Length -gt 0 } |
                Select-Object -Unique
        )
        $SourceFilter = if ($normalizedSourceFilter.Count -gt 0) { $normalizedSourceFilter } else { $null }
    }

    if (-not $SourceFilter -or $SourceFilter.Count -eq 0) {
        Write-Error "SourceFilter is required for safety. Specify at least one non-empty source value."
        return
    }

    # Validate Azure login
    $azContext = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $azContext) {
        Write-Warning "You are not logged in to Azure. Please run 'Connect-AzAccount' first."
        return
    }

    if (-not $LogFile) {
        $baseDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
        $logDir  = Join-Path $baseDir "Logs"
        if (-not (Test-Path -Path $logDir -PathType Container)) {
            New-Item -Path $logDir -ItemType Directory -Force -Confirm:$false | Out-Null
        }
        $logDate = Get-Date -Format 'yyyyMMdd_HHmmss'
        $LogFile = Join-Path $logDir "Remove-SentinelThreatIndicators_$logDate.log"
    }

    $logFileDisplay = "/logs/" + ([regex]::Replace($LogFile, '.*[\\/]Logs[\\/]', '') -replace '\\', '/')

    $RunId = Get-Random -Minimum 10000000 -Maximum 99999999

    $loggerScriptPath = Join-Path $PSScriptRoot "Common\Toolkit.Logging.ps1"
    if (-not (Test-Path -Path $loggerScriptPath -PathType Leaf)) {
        Write-Error "Required logging helper script not found: $loggerScriptPath"
        return
    }
    . $loggerScriptPath
    Initialize-ToolkitLogger -LogFile $LogFile -RunId $RunId

    Write-Log ([ordered]@{ event = 'run_started'; subscription_id = $SubscriptionId; resource_group = $ResourceGroupName; workspace = $WorkspaceName; source_filter = ($SourceFilter -join ', ') })

    $toolkitVersion = '1.0.0'

    $requiredModules = @('Az.Accounts')
    foreach ($module in $requiredModules) {
        if (-not (Get-Module -Name $module -ListAvailable)) {
            Write-Error "Required module '$module' is not installed. Run: Install-Module $module"
            return
        }
    }

    if (-not $BatchSize -or $BatchSize -lt 1) {
        $BatchSize = 100
    }

    if ($ConcurrentWorkers -lt 1) {
        $ConcurrentWorkers = 1
    }

    if (-not $TargetDeleteRatePerSecond -or $TargetDeleteRatePerSecond -le 0) {
        $TargetDeleteRatePerSecond = 1.0
    }

    if (-not $ProgressRefreshIntervalSeconds -or $ProgressRefreshIntervalSeconds -lt 5) {
        $ProgressRefreshIntervalSeconds = 60
    }

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

    $apiWarningStats = [hashtable]::Synchronized(@{
        Http401 = 0
        Http429 = 0
    })

    function Write-ApiWarningLog {
        param(
            [int]$StatusCode,
            [string]$Operation,
            [int]$Attempt = 0,
            [int]$MaxAttempts = 0,
            [string]$RawRetryAfter = $null,
            [int]$WaitSeconds = 0,
            [datetime]$ResumeAtUtc = [datetime]::MinValue,
            [string]$Note = $null
        )

        $logData = [ordered]@{
            level       = 'warn'
            event       = 'api_warning'
            status_code = $StatusCode
            operation   = $Operation
        }

        if ($Attempt -gt 0) { $logData.attempt = $Attempt }
        if ($MaxAttempts -gt 0) { $logData.max_attempts = $MaxAttempts }
        if ($RawRetryAfter) { $logData.retry_after_raw = $RawRetryAfter }
        if ($WaitSeconds -gt 0) { $logData.wait_seconds = $WaitSeconds }
        if ($ResumeAtUtc -gt [datetime]::MinValue) { $logData.resume_utc = $ResumeAtUtc.ToString("yyyy-MM-ddTHH:mm:ssZ") }
        if ($Note) { $logData.note = $Note }

        Write-Log $logData
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

    function Get-HttpStatusCode {
        param($ErrorRecord)

        $statusCode = 0
        try {
            if ($ErrorRecord.Exception.Response) {
                if ($ErrorRecord.Exception.Response.StatusCode -is [int]) {
                    $statusCode = [int]$ErrorRecord.Exception.Response.StatusCode
                }
                elseif ($ErrorRecord.Exception.Response.StatusCode.PSObject.Properties.Name -contains 'value__') {
                    $statusCode = [int]$ErrorRecord.Exception.Response.StatusCode.value__
                }
                else {
                    $statusCode = [int]$ErrorRecord.Exception.Response.StatusCode
                }
            }
        }
        catch {}

        if (-not $statusCode) {
            $errText = ""
            try { $errText = ($ErrorRecord | Out-String) } catch {}
            if (($ErrorRecord.Exception.Message -match '\b400\b') -or ($errText -match '\b400\b|Bad Request')) {
                $statusCode = 400
            }
        }

        return $statusCode
    }

    function Get-RetryAfterInfo {
        param(
            $ErrorRecord,
            [int]$DefaultSeconds = 10
        )

        $raw = $null
        $retryAfter = $DefaultSeconds
        try {
            $raw = $ErrorRecord.Exception.Response.Headers.GetValues("Retry-After") | Select-Object -First 1
        }
        catch {}

        if ($raw) {
            $parsedSeconds = 0
            if ([int]::TryParse([string]$raw, [ref]$parsedSeconds)) {
                $retryAfter = [math]::Max($parsedSeconds, 1)
            }
            else {
                $retryAt = [datetimeoffset]::MinValue
                if ([datetimeoffset]::TryParse([string]$raw, [ref]$retryAt)) {
                    $delta = [math]::Ceiling(($retryAt - [datetimeoffset]::UtcNow).TotalSeconds)
                    $retryAfter = [math]::Max($delta, 1)
                }
            }
        }

        [pscustomobject]@{
            Raw         = $raw
            Seconds     = $retryAfter
            ResumeAtUtc = ([datetime]::UtcNow).AddSeconds($retryAfter)
        }
    }

    function New-DeleteRateState {
        param([double]$RatePerSecond)

        $effectiveRate = if ($RatePerSecond -gt 0) { $RatePerSecond } else { 1.0 }

        return [hashtable]::Synchronized(@{
            Capacity         = 1.0
            Tokens           = 1.0
            RefillPerSecond  = $effectiveRate
            LastRefillUtc    = [datetime]::UtcNow
            CooldownUntilUtc = [datetime]::MinValue
            Lock             = New-Object object
        })
    }

    function Wait-DeleteRatePermit {
        param([hashtable]$RateState)

        while ($true) {
            $waitMilliseconds = 0
            [System.Threading.Monitor]::Enter($RateState.Lock)
            try {
                $now = [datetime]::UtcNow

                if ($RateState.CooldownUntilUtc -gt $now) {
                    $waitMilliseconds = [math]::Max([int][math]::Ceiling(($RateState.CooldownUntilUtc - $now).TotalMilliseconds), 100)
                }
                else {
                    $elapsedSeconds = ($now - $RateState.LastRefillUtc).TotalSeconds
                    if ($elapsedSeconds -gt 0) {
                        $RateState.Tokens = [math]::Min([double]$RateState.Capacity, [double]$RateState.Tokens + ($elapsedSeconds * [double]$RateState.RefillPerSecond))
                        $RateState.LastRefillUtc = $now
                    }

                    if ([double]$RateState.Tokens -ge 1.0) {
                        $RateState.Tokens = [double]$RateState.Tokens - 1.0
                        return
                    }

                    $missingTokens = 1.0 - [double]$RateState.Tokens
                    $secondsToWait = if ([double]$RateState.RefillPerSecond -gt 0) {
                        $missingTokens / [double]$RateState.RefillPerSecond
                    }
                    else {
                        1
                    }
                    $waitMilliseconds = [math]::Max([int][math]::Ceiling($secondsToWait * 1000), 100)
                }
            }
            finally {
                [System.Threading.Monitor]::Exit($RateState.Lock)
            }

            Start-Sleep -Milliseconds $waitMilliseconds
        }
    }

    function Set-DeleteRateCooldown {
        param(
            [hashtable]$RateState,
            [datetime]$ResumeAtUtc
        )

        [System.Threading.Monitor]::Enter($RateState.Lock)
        try {
            if ($ResumeAtUtc -gt $RateState.CooldownUntilUtc) {
                $RateState.CooldownUntilUtc = $ResumeAtUtc
            }
        }
        finally {
            [System.Threading.Monitor]::Exit($RateState.Lock)
        }
    }

    function Invoke-SentinelRestMethod {
        param(
            [string]$Uri,
            [hashtable]$Headers,
            [ValidateSet('GET', 'POST', 'DELETE')]
            [string]$Method,
            [object]$Body = $null,
            [string]$OperationName = 'Request',
            [int]$MaxRetries = 5,
            [int[]]$FallbackDelaysSec = @(5, 15, 30, 60, 120)
        )

        $attempt = 0
        $did401Refresh = $false

        do {
            $attempt++
            try {
                $invokeParams = @{
                    Uri         = $Uri
                    Headers     = $Headers
                    Method      = $Method
                    ErrorAction = 'Stop'
                }
                if ($null -ne $Body) {
                    $invokeParams.Body = ($Body | ConvertTo-Json -Depth 10)
                }

                return Invoke-RestMethod @invokeParams
            }
            catch {
                $statusCode = Get-HttpStatusCode -ErrorRecord $_

                if ($statusCode -eq 401 -and -not $did401Refresh) {
                    $newToken = Get-BearerToken
                    if ($newToken) {
                        $Headers['Authorization'] = "Bearer $newToken"
                        $did401Refresh = $true
                        $apiWarningStats.Http401++
                        Write-ApiWarningLog -StatusCode 401 -Operation $OperationName -Attempt $attempt -MaxAttempts $MaxRetries -Note 'token refreshed and retrying'
                        $attempt--
                        continue
                    }
                }

                if ($statusCode -eq 429 -and $attempt -lt $MaxRetries) {
                    $apiWarningStats.Http429++
                    $fallbackIndex = [math]::Min(($attempt - 1), ($FallbackDelaysSec.Count - 1))
                    $defaultDelay = $FallbackDelaysSec[$fallbackIndex]
                    $retryInfo = Get-RetryAfterInfo -ErrorRecord $_ -DefaultSeconds $defaultDelay
                    Write-ApiWarningLog -StatusCode 429 -Operation $OperationName -Attempt $attempt -MaxAttempts $MaxRetries -RawRetryAfter $retryInfo.Raw -WaitSeconds $retryInfo.Seconds -ResumeAtUtc $retryInfo.ResumeAtUtc
                    if ($ShowAPIWarnings) {
                        $ts = Get-Date -Format 'HH:mm:ss'
                        $rawText = if ($retryInfo.Raw) { "'$($retryInfo.Raw)'" } else { '(missing)' }
                        $resumeUtc = $retryInfo.ResumeAtUtc.ToString("yyyy-MM-dd HH:mm:ss 'UTC'")
                        Write-Warning "[$ts] $OperationName throttled (429) - raw Retry-After=$rawText; interpreted wait=$($retryInfo.Seconds)s; resume ~$resumeUtc (attempt $attempt/$MaxRetries)..."
                    }
                    Start-Sleep -Seconds $retryInfo.Seconds
                    continue
                }

                throw
            }
        } while ($attempt -lt $MaxRetries)
    }

    $token = Get-BearerToken
    if (-not $token) {
        Write-Status -Level FAIL -Message "Failed to acquire access token. Run 'Connect-AzAccount' and try again."
        return
    }

    $logSourceFilter = $SourceFilter -join ', '

    $headers = @{
        "Authorization" = "Bearer $token"
        "Content-Type"  = "application/json"
    }

    $apiVersion = "2025-09-01"
    $baseUri    = "https://management.azure.com/subscriptions/$SubscriptionId" +
                  "/resourceGroups/$ResourceGroupName" +
                  "/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName" +
                  "/providers/Microsoft.SecurityInsights"
    $countUri   = "$baseUri/threatIntelligence/main/count?api-version=2025-07-01-preview"
    $queryUri   = "$baseUri/threatIntelligence/main/queryIndicators?api-version=$apiVersion"
    $deleteBase = "$baseUri/threatIntelligence/main/indicators"
    # Marker: query compatibility fallbacks are intentionally disabled.
    # If tenant-specific query 400 behavior returns, restore logic from local recovery notes.
    $QueryCompatibilityFallbackEnabled = $false

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
            [int]$Size
        )
        $requestUri = Resolve-AbsoluteApiUri -CandidateUri $Uri
        $body = [ordered]@{ pageSize = $Size }
        $body.sortBy = @(@{ itemKey = "lastUpdatedTimeUtc"; sortOrder = "descending" })
        if ($Source) { $body.sources = @($Source) }

        $response = $null
        try {
            $response = Invoke-SentinelRestMethod -Uri $requestUri `
                                                 -Headers $Headers `
                                                 -Method POST `
                                                 -Body $body `
                                                 -OperationName "Query indicators"
        }
        catch {
            $statusCode = Get-HttpStatusCode -ErrorRecord $_
            if ($statusCode -eq 400 -and -not $QueryCompatibilityFallbackEnabled) {
                Write-Warning "Query endpoint returned 400 and compatibility fallback is disabled by design."
                Write-Log ([ordered]@{ level = 'warn'; event = 'query_fallback_disabled'; status_code = 400; operation = 'Query indicators'; note = 'compatibility fallback intentionally disabled' })
            }
            throw
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
            EffectiveSize = $Size
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

        $body = $null
        if ($null -ne $Source) {
            if ($Source.Count -gt 0) {
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
            else {
                $body = @{
                    condition = @{
                        conditionConnective = "Or"
                        clauses             = @(
                            @{
                                field    = "source"
                                operator = "NotEquals"
                                values   = @("")
                            }
                        )
                    }
                }
            }
        }

        try {
            if ($body) {
                $resp = Invoke-SentinelRestMethod -Uri $countUri `
                                                 -Headers $Headers `
                                                 -Method POST `
                                                 -Body $body `
                                                 -OperationName "Count indicators"
            }
            else {
                $resp = Invoke-SentinelRestMethod -Uri $countUri `
                                                 -Headers $Headers `
                                                 -Method POST `
                                                 -OperationName "Count indicators"
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

    function New-FetchState {
        param(
            [string]$InitialQueryUri,
            [string[]]$Filter
        )

        return [ordered]@{
            SourceFilter = $Filter
            QueryPageUri = $InitialQueryUri
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

                $pageResult = Get-IndicatorPage -Headers $Headers -Uri $State.QueryPageUri -Source $State.SourceFilter -Size $Size
                $batch = @($pageResult.Items)
                $batchCount = $batch.Count
                $State.QueryPageUri = $pageResult.NextLink

                $effectiveSize = $pageResult.EffectiveSize

                if ($batchCount -eq 0) {
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

                $statusCode = Get-HttpStatusCode -ErrorRecord $_

                $failureStage = "filtered-query"
                $failureUri = $State.QueryPageUri

                if ($statusCode -eq 400 -and -not $QueryCompatibilityFallbackEnabled) {
                    Write-Log ([ordered]@{ level = 'warn'; event = 'query_fallback_disabled'; status_code = 400; stage = $failureStage; note = 'compatibility fallback intentionally disabled' })
                }

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

    Write-Output "==============================================================="
    Write-Output "Microsoft Sentinel - Threat Intelligence Toolkit"
    Write-Output "Version : $toolkitVersion"
    Write-Output "Project : https://github.com/alexverboon/microsoft-defender-threat-intelligence-toolkit"
    Write-Output "Author  : Alex Verboon"
    Write-Output "==============================================================="
    Write-Output ""
    Write-Output "===== Preflight ====="
    Write-Log ([ordered]@{ event = 'preflight_token'; status = 'access_token_acquired' })
    Write-Status -Level PASS -Message "Access token acquired."
    Write-Log ([ordered]@{ event = 'preflight_config'; log_file = $logFileDisplay })
    Write-Status -Level INFO -Message "Run ID/Log file: $RunId | $logFileDisplay"
    Write-Log ([ordered]@{ event = 'preflight_config'; subscription_id = $SubscriptionId })
    Write-Status -Level INFO -Message "Subscription ID: $SubscriptionId"
    Write-Log ([ordered]@{ event = 'preflight_config'; resource_group = $ResourceGroupName })
    Write-Status -Level INFO -Message "Resource group: $ResourceGroupName"
    Write-Log ([ordered]@{ event = 'preflight_config'; workspace = $WorkspaceName })
    Write-Status -Level INFO -Message "Target workspace: $WorkspaceName"
    Write-Log ([ordered]@{ event = 'preflight_config'; source_filter = ($SourceFilter -join ', ') })
    Write-Status -Level INFO -Message "Source filter: $($SourceFilter -join ', ')"
    Write-Log ([ordered]@{ event = 'preflight_config'; execution_mode = $(if ($PSVersionTable.PSVersion.Major -ge 7 -and $ConcurrentWorkers -gt 1) { 'parallel' } else { 'sequential' }); concurrent_workers = $ConcurrentWorkers })
    Write-Status -Level INFO -Message "Execution mode: $(if ($PSVersionTable.PSVersion.Major -ge 7 -and $ConcurrentWorkers -gt 1) { "Parallel (ConcurrentWorkers=$ConcurrentWorkers)" } else { "Sequential" })"
    Write-Log ([ordered]@{ event = 'preflight_config'; delete_rate_per_hour = $([math]::Round($TargetDeleteRatePerSecond * 3600, 0)) })
    Write-Status -Level INFO -Message "Target delete rate: $TargetDeleteRatePerSecond req/s (~$([math]::Round($TargetDeleteRatePerSecond * 3600, 0))/hour)"

    $countIsExact = $true
    $allSourcesFilter = @()
    $totalAllIndicators = Get-IndicatorTotalCount -Headers $headers `
                                                   -SubscriptionId $SubscriptionId `
                                                   -ResourceGroupName $ResourceGroupName `
                                                   -WorkspaceName $WorkspaceName `
                                                   -Source $allSourcesFilter

    $totalFound   = Get-IndicatorTotalCount -Headers $headers `
                                            -SubscriptionId $SubscriptionId `
                                            -ResourceGroupName $ResourceGroupName `
                                            -WorkspaceName $WorkspaceName `
                                            -Source $SourceFilter

    if ($null -eq $totalFound) {
        Write-Error "Exact source count API unavailable. Stopping run because delete mode now requires exact counts."
        Write-Log ([ordered]@{ level = 'error'; event = 'run_aborted'; source_filter = $logSourceFilter; reason = 'exact source count API unavailable' })
        return
    }

    if ($null -ne $totalAllIndicators) {
        $sourceSharePct = if ($totalAllIndicators -gt 0) {
            [math]::Round((([double]$totalFound / [double]$totalAllIndicators) * 100), 2)
        }
        else {
            0
        }

        Write-Status -Level PASS -Message "Total indicators (all sources): $totalAllIndicators"
        Write-Status -Level PASS -Message "Indicators matching source filter: $totalFound"
        Write-Status -Level INFO -Message "Source share of total indicators: $sourceSharePct%"
        Write-Log ([ordered]@{ event = 'preflight_counts'; total_all_sources = $totalAllIndicators; matching_source_filter = $totalFound; source_share_pct = $sourceSharePct })
    }
    else {
        Write-Status -Level WARN -Message "Exact total indicator count unavailable. Continuing with exact source count only."
        Write-Status -Level PASS -Message "Indicators matching source filter: $totalFound"
        Write-Log ([ordered]@{ level = 'warn'; event = 'preflight_counts'; total_all_sources = $null; matching_source_filter = $totalFound; note = 'exact total count unavailable' })
    }
    Write-Output "====================="

    if ($totalFound -eq 0) {
        Write-Output "No indicators found for source(s) '$($SourceFilter -join "', '")'. Nothing to delete."
        Write-Log ([ordered]@{ event = 'run_completed'; source_filter = $logSourceFilter; deleted = 0; failed = 0; reason = 'nothing to delete' })
        return
    }

    Write-Output ""
    Write-Output "Found $totalFound indicator(s) from source(s) '$($SourceFilter -join "', '")'."
    Write-Output ""
    Write-Log ([ordered]@{ event = 'delete_started'; source_filter = $logSourceFilter; found = $totalFound })

    $deleteScope = "$totalFound indicator(s) in workspace '$WorkspaceName' for source(s) '$($SourceFilter -join ", ")'"
    if (-not $PSCmdlet.ShouldProcess($deleteScope, "Delete threat intelligence indicators")) {
        Write-Output "WhatIf: no indicators were deleted."
        Write-Log ([ordered]@{ event = 'run_completed'; source_filter = $logSourceFilter; whatif = $true; simulated = $totalFound; deleted = 0; failed = 0 })
        return
    }

    # Pass 2: Fetch one page at a time and delete it, then re-query from the start.
    # Not using a skipToken between batches avoids pagination inconsistency after deletions.
    $sync        = [hashtable]::Synchronized(@{ Deleted = 0; Failed = 0; Processed = 0; DeleteSubmitted = 0; QuerySubmitted = 0; CountSubmitted = 0; Retry429 = 0 })
    $failedBag   = [System.Collections.Concurrent.ConcurrentBag[string]]::new()
    $startTime   = [datetime]::UtcNow
    $useParallel = ($PSVersionTable.PSVersion.Major -ge 7) -and ($ConcurrentWorkers -gt 1)
    $deleteRateState = New-DeleteRateState -RatePerSecond $TargetDeleteRatePerSecond

    Write-Output ""
    if ($useParallel) {
        Write-Output "Running parallel deletes (workers: $ConcurrentWorkers)..."
    } else {
        Write-Output "Running sequential deletes..."
    }
    Write-Output ""
    
    $globalStartTime      = [datetime]::UtcNow
    $lastProgressTime     = [datetime]::MinValue
    $tokenAcquiredAt      = [datetime]::UtcNow   # token was just fetched above before confirmation
    $tokenRefreshMinutes  = 45                   # Az tokens last ~60 min; refresh at 45
    $printedRateLimitHeaders = $false            # print detailed 429 headers once when diagnostics are enabled
    $fetchBatchFailed     = $false
    $fetchBatchErrorText  = $null
    $endedByRemainingProbe = $false
    $fetchState           = New-FetchState -InitialQueryUri $queryUri -Filter $SourceFilter
    $fetchRetryCount      = 0
    $fetchRetryDelaysSec  = @(15, 30, 60, 120, 180) # progressive back-off delays between retries
    $fetchRetryMaxAttempts = $fetchRetryDelaysSec.Count
    $ProgressIdDeleteRun  = 30

    function Write-DeleteProgress {
        param(
            [switch]$Force,
            [switch]$SkipRecount
        )

        $now = [datetime]::UtcNow
        if (-not $Force -and (($now - $lastProgressTime).TotalSeconds -lt $ProgressRefreshIntervalSeconds)) {
            return
        }

        $remaining = $null
        if (-not $SkipRecount -and $countIsExact) {
            $sync.CountSubmitted++
            $remaining = Get-IndicatorTotalCount -Headers $headers `
                                                -SubscriptionId $SubscriptionId `
                                                -ResourceGroupName $ResourceGroupName `
                                                -WorkspaceName $WorkspaceName `
                                                -Source $SourceFilter
        }

        if ($null -ne $remaining -and $countIsExact) {
            $completedCount = [math]::Max(([int64]$totalFound - [int64]$remaining), 0)
            if ($completedCount -gt $sync.Processed) {
                $sync.Processed = $completedCount
            }
        }

        $elapsed = ($now - $globalStartTime).TotalSeconds
        $rate = if ($elapsed -gt 0 -and $sync.Processed -gt 0) { $sync.Processed / $elapsed } else { 0 }
        if ($null -eq $remaining) {
            $remaining = [math]::Max($totalFound - $sync.Processed, 0)
        }
        $etaSec = if ($rate -gt 0) { [math]::Round($remaining / $rate) } else { 0 }
        $etaStr = if ($remaining -gt 0) {
            if ($etaSec -ge 3600)  { "{0}h {1}m" -f [int]($etaSec/3600), [int](($etaSec%3600)/60) }
            elseif ($etaSec -ge 60) { "{0}m {1}s" -f [int]($etaSec / 60), [int]($etaSec % 60) }
            else { "{0}s" -f $etaSec }
        } else { "Done" }
        $percentComplete = if ($totalFound -gt 0) {
            [math]::Min([int][math]::Floor(($sync.Processed / [double]$totalFound) * 100), 100)
        }
        else {
            0
        }
        $statusLine = "Deleted $($sync.Deleted) of $totalFound | Failed $($sync.Failed) | Remaining $remaining | ETA $etaStr"
        Write-Progress -Activity "Deleting Threat Intelligence Indicators" `
                       -Id $ProgressIdDeleteRun `
                       -Status $statusLine `
                       -PercentComplete $percentComplete
        $lastProgressTime = $now

        if (-not $Force) {
            Write-Log ([ordered]@{ event = 'delete_progress'; deleted = $sync.Deleted; failed = $sync.Failed; found = $totalFound; remaining = $remaining; eta = $etaStr })
        }

        return [pscustomobject]@{
            Remaining       = [int64]$remaining
            PercentComplete = $percentComplete
        }
    }

    Write-DeleteProgress -Force -SkipRecount | Out-Null

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

        $fetchResult = Get-ResilientIndicatorBatch -Headers $headers -State $fetchState -Size $BatchSize -Sync $sync
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
            Write-Output "INFO: Fetch diagnostic | Stage=$stage | Status=$failureStatus | QueryApiVersion=$apiVersion | BatchSize=$BatchSize | Processed=$($sync.Processed) | Uri=$uriPreview"

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
                if ($failureStatus -eq 400 -and $BatchSize -gt 10) {
                    $newBatchSize = if ($BatchSize -gt 50) { 50 } elseif ($BatchSize -gt 25) { 25 } else { 10 }
                    if ($newBatchSize -lt $BatchSize) {
                        Write-Warning "Reducing batch size from $BatchSize to $newBatchSize after fetch failure to improve endpoint compatibility."
                        $BatchSize = $newBatchSize
                    }
                }
                $delaySec = $fetchRetryDelaysSec[$fetchRetryCount]
                $fetchRetryCount++
                $ts = Get-Date -Format 'HH:mm:ss'
                Write-Warning "[$ts] Fetch paths failed with HTTP $failureStatus (attempt $fetchRetryCount/$fetchRetryMaxAttempts). Waiting ${delaySec}s before retrying..."
                if ($fetchResult.ErrorDetail) { Write-Output "  API detail: $($fetchResult.ErrorDetail)" }
                Start-Sleep -Seconds $delaySec

                # Refresh the token in case the prior failures were auth-related.
                $freshToken = Get-BearerToken
                if ($freshToken) { $headers["Authorization"] = "Bearer $freshToken" }
                # Reset the fetch state and restart from the first query page.
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
        $BatchSize   = $fetchResult.EffectiveSize

        $processedBeforeBatch = $sync.Processed

        if ($useParallel) {
            $batchArray = @($batch)
            # Start with modest chunks so progress stays visible and request bursts stay controlled.
            $parallelChunkSize = [math]::Max(($ConcurrentWorkers * 4), 12)
            $parallelChunkSize = [math]::Min($parallelChunkSize, 40)
            $parallelChunkMin  = [math]::Max(($ConcurrentWorkers * 2), 6)
            $parallelChunkMax  = [math]::Max(($ConcurrentWorkers * 12), 40)
            $parallelInterChunkDelayMs = 150

            $offset = 0
            while ($offset -lt $batchArray.Count) {
                $chunkEnd = [math]::Min(($offset + $parallelChunkSize - 1), ($batchArray.Count - 1))
                $chunk = @($batchArray[$offset..$chunkEnd])
                $chunkLen = $chunk.Count
                $retry429BeforeChunk = $sync.Retry429
                $warn401BeforeChunk = $apiWarningStats.Http401
                $warn429BeforeChunk = $apiWarningStats.Http429

                $chunk | ForEach-Object -ThrottleLimit $ConcurrentWorkers -Parallel {
                $s          = $using:sync
                $bag        = $using:failedBag
                $hdrs       = $using:headers
                $delBase    = $using:deleteBase
                $apiVer     = $using:apiVersion
                $rateState  = $using:deleteRateState
                $warnStats  = $using:apiWarningStats
                $showApiWarnings = $using:ShowAPIWarnings

                $name      = $_.name
                $deleteUri = "$delBase/$name`?api-version=$apiVer"

                $getRetryAfter = {
                    param($ex, [int]$defaultSeconds)
                    $raw = $null
                    $ra = $defaultSeconds
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

                $waitForPermit = {
                    param($state)

                    while ($true) {
                        $waitMilliseconds = 0
                        [System.Threading.Monitor]::Enter($state.Lock)
                        try {
                            $now = [datetime]::UtcNow

                            if ($state.CooldownUntilUtc -gt $now) {
                                $waitMilliseconds = [math]::Max([int][math]::Ceiling(($state.CooldownUntilUtc - $now).TotalMilliseconds), 100)
                            }
                            else {
                                $elapsedSeconds = ($now - $state.LastRefillUtc).TotalSeconds
                                if ($elapsedSeconds -gt 0) {
                                    $state.Tokens = [math]::Min([double]$state.Capacity, [double]$state.Tokens + ($elapsedSeconds * [double]$state.RefillPerSecond))
                                    $state.LastRefillUtc = $now
                                }

                                if ([double]$state.Tokens -ge 1.0) {
                                    $state.Tokens = [double]$state.Tokens - 1.0
                                    return
                                }

                                $missingTokens = 1.0 - [double]$state.Tokens
                                $secondsToWait = if ([double]$state.RefillPerSecond -gt 0) {
                                    $missingTokens / [double]$state.RefillPerSecond
                                }
                                else {
                                    1
                                }
                                $waitMilliseconds = [math]::Max([int][math]::Ceiling($secondsToWait * 1000), 100)
                            }
                        }
                        finally {
                            [System.Threading.Monitor]::Exit($state.Lock)
                        }

                        Start-Sleep -Milliseconds $waitMilliseconds
                    }
                }

                $setCooldown = {
                    param($state, [datetime]$resumeAt)

                    [System.Threading.Monitor]::Enter($state.Lock)
                    try {
                        if ($resumeAt -gt $state.CooldownUntilUtc) {
                            $state.CooldownUntilUtc = $resumeAt
                        }
                    }
                    finally {
                        [System.Threading.Monitor]::Exit($state.Lock)
                    }
                }

                $maxRetries    = 5
                $attempt       = 0
                $deleteSuccess = $false
                $did401Refresh = $false

                do {
                    $attempt++
                    try {
                        & $waitForPermit $rateState
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
                                    $warnStats.Http401++
                                    if ($showApiWarnings) {
                                        Write-Warning "  401 Unauthorized - token refreshed, retrying..."
                                    }
                                    $attempt--
                                    continue
                                }
                            } catch {}
                        }

                        if ($sc -eq 429 -and $attempt -lt $maxRetries) {
                            $s.Retry429++
                            $warnStats.Http429++
                            $retryInfo = & $getRetryAfter $_ (5 * $attempt)
                            & $setCooldown $rateState $retryInfo.ResumeAtUtc
                            if ($showApiWarnings) {
                                $rawText = if ($retryInfo.Raw) { "'$($retryInfo.Raw)'" } else { "(missing)" }
                                $resumeUtc = $retryInfo.ResumeAtUtc.ToString("yyyy-MM-dd HH:mm:ss 'UTC'")
                                Write-Warning "  429 Too Many Requests — raw Retry-After=$rawText; interpreted wait=$($retryInfo.Seconds)s; resume ~$resumeUtc (attempt $attempt/$maxRetries)..."
                            }
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
                $warn401AfterChunk = $apiWarningStats.Http401
                $warn429AfterChunk = $apiWarningStats.Http429
                $chunk401Warnings = $warn401AfterChunk - $warn401BeforeChunk
                $chunk429Warnings = $warn429AfterChunk - $warn429BeforeChunk
                if ($chunk401Warnings -gt 0) {
                    Write-Log ([ordered]@{ level = 'warn'; event = 'api_warning'; status_code = 401; operation = 'Delete indicators (parallel chunk)'; occurrences = $chunk401Warnings })
                }
                if ($chunk429Warnings -gt 0) {
                    Write-Log ([ordered]@{ level = 'warn'; event = 'api_warning'; status_code = 429; operation = 'Delete indicators (parallel chunk)'; occurrences = $chunk429Warnings })
                }
                if ($chunk429 -gt 0) {
                    # If the current burst produced 429s, reduce chunk size and add cooldown.
                    $parallelChunkSize = [math]::Max([int][math]::Floor($parallelChunkSize / 2), $parallelChunkMin)
                    $cooldownMs = [math]::Min((300 * $chunk429), 3000)
                    Start-Sleep -Milliseconds $cooldownMs
                }
                elseif ($parallelChunkSize -lt $parallelChunkMax) {
                    # Slowly scale up when no rate limiting is observed.
                    $parallelChunkSize = [math]::Min(($parallelChunkSize + $ConcurrentWorkers), $parallelChunkMax)
                    Start-Sleep -Milliseconds $parallelInterChunkDelayMs
                }

                Write-DeleteProgress | Out-Null
                $offset += $chunkLen
            }
        }
        else {
                foreach ($indicator in @($batch)) {
                $name      = $indicator.name
                $deleteUri = "$deleteBase/$name`?api-version=$apiVersion"

                $maxRetries    = 5
                $attempt       = 0
                $deleteSuccess = $false
                $did401Refresh = $false

                do {
                    $attempt++
                    try {
                        Wait-DeleteRatePermit -RateState $deleteRateState
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
                            if ($ShowAPIWarnings) {
                                Write-Output "  INFO: Token expired, refreshing..."
                            }
                            $newToken = Get-BearerToken
                            if ($newToken) {
                                $headers["Authorization"] = "Bearer $newToken"
                                $did401Refresh = $true
                                $apiWarningStats.Http401++
                                Write-ApiWarningLog -StatusCode 401 -Operation 'Delete indicator' -Attempt $attempt -MaxAttempts $maxRetries -Note 'token refreshed and retrying'
                                $attempt--
                                continue
                            } else {
                                $errorDetail   = "Could not refresh access token."
                                $deleteSuccess = $true
                            }
                        }
                        elseif ($statusCode -eq 429 -and $attempt -lt $maxRetries) {
                            $sync.Retry429++
                            $apiWarningStats.Http429++
                            $retryInfo = Get-RetryAfterInfo -ErrorRecord $_ -DefaultSeconds (5 * $attempt)
                            $retryAfter = $retryInfo.Seconds
                            $retryAfterRaw = $retryInfo.Raw
                            $ts = Get-Date -Format 'HH:mm:ss'
                            Write-ApiWarningLog -StatusCode 429 -Operation 'Delete indicator' -Attempt $attempt -MaxAttempts $maxRetries -RawRetryAfter $retryAfterRaw -WaitSeconds $retryAfter -ResumeAtUtc $retryInfo.ResumeAtUtc
                            if ($ShowAPIWarnings -and -not $printedRateLimitHeaders -and $_.Exception.Response) {
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
                            Set-DeleteRateCooldown -RateState $deleteRateState -ResumeAtUtc $retryInfo.ResumeAtUtc
                            if ($ShowAPIWarnings) {
                                $resumeUtc = $retryInfo.ResumeAtUtc.ToString("yyyy-MM-dd HH:mm:ss 'UTC'")
                                $rawText = if ($retryAfterRaw) { "'$retryAfterRaw'" } else { "(missing)" }
                                Write-Output "[$ts] Rate limited (429) — raw Retry-After=$rawText; interpreted wait=${retryAfter}s; resume ~$resumeUtc (attempt $attempt/$maxRetries)..."
                            }
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
                Write-DeleteProgress
                }
        }

        if ($sync.Processed -le $processedBeforeBatch) {
            Write-Output "WARNING: No indicators were processed in this delete batch; stopping to avoid loop."
            break
        }

        # Deletions mutate the dataset, so restart query from the first page each batch.
        $fetchState = New-FetchState -InitialQueryUri $queryUri -Filter $SourceFilter

        # Delay between batches to avoid rate limiting
        Start-Sleep -Milliseconds 1000
    }

    $deleted   = $sync.Deleted
    $failed    = $sync.Failed
    $failedIds = [System.Collections.Generic.List[string]]$failedBag

    Write-Progress -Activity "Deleting Threat Intelligence Indicators" -Id $ProgressIdDeleteRun -Completed

    $totalElapsed = [datetime]::UtcNow - $startTime
    $elapsedStr   = if     ($totalElapsed.TotalHours -ge 1)  { "{0}h {1}m {2}s" -f [int]$totalElapsed.TotalHours, $totalElapsed.Minutes, $totalElapsed.Seconds }
                    elseif ($totalElapsed.TotalMinutes -ge 1) { "{0}m {1}s" -f $totalElapsed.Minutes, $totalElapsed.Seconds }
                    else                                       { "{0}s" -f $totalElapsed.Seconds }
    $summaryLevel = if ($failed -gt 0) { 'WARN' } else { 'PASS' }
    $executionMode = if ($useParallel) { 'parallel' } else { 'sequential' }
    $totalRequests = ($sync.DeleteSubmitted + $sync.QuerySubmitted + $sync.CountSubmitted)

    Write-Output ""
    Write-Output "===== Summary ====="
    Write-Status -Level $summaryLevel -Message "Deletion run completed."
    Write-Output "Run ID        : $RunId"
    Write-Output "Mode          : $executionMode"
    Write-Output "Source filter : $($SourceFilter -join ', ')"
    Write-Output "Found         : $(if ($countIsExact) { "$totalFound" } else { ">=$totalFound (count incomplete)" })"
    Write-Output "Deleted       : $deleted"
    Write-Output "Failed        : $failed"
    Write-Output "API warnings  : 401=$($apiWarningStats.Http401), 429=$($apiWarningStats.Http429)"
    Write-Output "Requests      : delete=$($sync.DeleteSubmitted), query=$($sync.QuerySubmitted), count=$($sync.CountSubmitted), total=$totalRequests"
    Write-Output "429 retries   : $($sync.Retry429) (delete requests)"
    Write-Output "Elapsed       : $elapsedStr"

    if (($apiWarningStats.Http401 -gt 0) -or ($apiWarningStats.Http429 -gt 0)) {
        Write-Log ([ordered]@{ level = 'warn'; event = 'api_warning_summary'; http_401 = $apiWarningStats.Http401; http_429 = $apiWarningStats.Http429 })
    }

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
            Write-Log ([ordered]@{ level = 'warn'; event = 'count_reconciliation_skipped'; found = $totalFound; processed = 0; reason = 'initial query failed' })
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
        $recountPageSize     = $BatchSize
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
            Write-Log ([ordered]@{ level = 'warn'; event = 'count_reconciliation'; found = $totalFound; processed = $processedTotal; delta = $countDelta; remaining_now = $remainingNow })
        }
        else {
            Write-Warning "Count reconciliation mismatch detected. Found=$totalFound, Processed=$processedTotal (Delta=$countDelta). Recount failed."
            if ($recountErrorText) { Write-Output "Recount last error: $recountErrorText" }
            Write-Log ([ordered]@{ level = 'warn'; event = 'count_reconciliation'; found = $totalFound; processed = $processedTotal; delta = $countDelta; remaining_now = $null; recount_failed = $true })
        }
    }

    if ($failedIds.Count -gt 0) {
        Write-Output ""
        Write-Output "Failed indicators:"
        $failedIds | ForEach-Object { Write-Output "  - $_" }
    }
    Write-Output "==================="
    Write-Log ([ordered]@{ event = 'run_completed'; source_filter = $logSourceFilter; deleted = $deleted; failed = $failed; elapsed = $elapsedStr })
}
param(
    [string]$EnvPath = (Join-Path (Split-Path -Parent $PSScriptRoot) ".env"),
    [string]$QueuePath = (Join-Path (Split-Path -Parent $PSScriptRoot) "config/checkpoint9_models.json"),
    [string]$LogDirectory = (Join-Path (Split-Path -Parent $PSScriptRoot) "runs/logs")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$RepositoryRoot = Split-Path -Parent $PSScriptRoot
$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$ResultPath = Join-Path $LogDirectory "provider-check-$Stamp.json"

function Redact-ProviderError([string]$Message) {
    $redacted = [regex]::Replace($Message, "(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{8,}", '$1[REDACTED]')
    $redacted = [regex]::Replace(
        $redacted,
        "(?i)(api[_-]?key|password|secret|token)\s*[=:]\s*[^\s,;]+",
        '$1=[REDACTED]'
    )
    return [regex]::Replace($redacted, "sk-(?:proj-)?[A-Za-z0-9_-]{16,}", "[REDACTED]")
}

# StrictMode: $LASTEXITCODE is undefined in a fresh session until something sets it.
$global:LASTEXITCODE = 0
& (Join-Path $PSScriptRoot "load_env.ps1") -EnvPath $EnvPath
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

try {
    # Windows PowerShell 5.1 emits a JSON array as one object; re-pipe to unroll it.
    $parsedQueue = Get-Content -LiteralPath $QueuePath -Raw | ConvertFrom-Json
    $queue = @($parsedQueue | ForEach-Object { $_ })
    if ($queue.Count -eq 0) {
        throw "Checkpoint 9 model queue is empty"
    }
    New-Item -ItemType Directory -Force -Path $LogDirectory | Out-Null
    $results = @()
    foreach ($entry in $queue) {
        $key = [Environment]::GetEnvironmentVariable([string]$entry.key_var, "Process")
        if (-not $key) {
            $result = [ordered]@{
                provider = [string]$entry.provider
                model = [string]$entry.model
                reasoning_effort = [string]$entry.reasoning_effort
                http_status = $null
                reported_model = $null
                tool_call_returned = $false
                # "NAME: value" would be caught by the redaction filter; keep the colon out.
                error_message = "$($entry.key_var) is NOT SET"
                named_error_fields = @()
            }
        }
        else {
            [Environment]::SetEnvironmentVariable("DENIALDOJO_API_KEY", $key, "Process")
            # "Continue": under "Stop", 5.1 throws on the first merged stderr line.
            $ErrorActionPreference = "Continue"
            $pythonOutput = & py -3.14 -m uv run python -m denialdojo.provider_check `
                --provider $entry.provider --model $entry.model --reasoning-effort $entry.reasoning_effort 2>&1
            $pythonExit = $LASTEXITCODE
            $ErrorActionPreference = "Stop"
            # Parse stdout only; uv and warnings write to stderr.
            $stdoutText = ($pythonOutput | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] } | Out-String).Trim()
            $pythonOutput = $pythonOutput | ForEach-Object { "$_" }
            if ($pythonExit -eq 0) {
                $result = $stdoutText | ConvertFrom-Json
            }
            else {
                $result = [ordered]@{
                    provider = [string]$entry.provider
                    model = [string]$entry.model
                    reasoning_effort = [string]$entry.reasoning_effort
                    http_status = $null
                    reported_model = $null
                    tool_call_returned = $false
                    error_message = Redact-ProviderError ($pythonOutput | Out-String).Trim()
                    named_error_fields = @()
                }
            }
        }
        [Environment]::SetEnvironmentVariable("DENIALDOJO_API_KEY", $null, "Process")
        $result.error_message = if ($result.error_message) { Redact-ProviderError ([string]$result.error_message) } else { $null }
        $results += $result
        Write-Output "$($result.provider)/$($result.model): HTTP $($result.http_status); reported_model=$($result.reported_model); tool_call=$($result.tool_call_returned)"
        if ($result.error_message) {
            Write-Output "  error: $($result.error_message)"
            Write-Output "  named_fields: $($result.named_error_fields -join ', ')"
        }
    }
    [ordered]@{
        schema_version = "denialdojo-provider-check-v1"
        created_at = (Get-Date).ToUniversalTime().ToString("o")
        results = $results
    } | ConvertTo-Json -Depth 10 | ForEach-Object {
        # utf8NoBOM does not exist in Windows PowerShell 5.1.
        [IO.File]::WriteAllText($ResultPath, $_, (New-Object System.Text.UTF8Encoding($false)))
    }
    Write-Output "provider check results: $ResultPath"
}
catch {
    [Environment]::SetEnvironmentVariable("DENIALDOJO_API_KEY", $null, "Process")
    [Console]::Error.WriteLine("ERROR: $(Redact-ProviderError $_.Exception.Message)")
    exit 1
}

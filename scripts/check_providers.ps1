param(
    [string]$EnvPath = (Join-Path (Split-Path -Parent $PSScriptRoot) ".env"),
    [string]$QueuePath = (Join-Path (Split-Path -Parent $PSScriptRoot) "config/checkpoint9_models.json")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$RepositoryRoot = Split-Path -Parent $PSScriptRoot
$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$LogDirectory = Join-Path $RepositoryRoot "runs/logs"
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

& (Join-Path $PSScriptRoot "load_env.ps1") -EnvPath $EnvPath
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

try {
    $queue = @(Get-Content -LiteralPath $QueuePath -Raw | ConvertFrom-Json)
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
                error_message = "$($entry.key_var): NOT SET"
                named_error_fields = @()
            }
        }
        else {
            [Environment]::SetEnvironmentVariable("DENIALDOJO_API_KEY", $key, "Process")
            $pythonOutput = & py -3.14 -m uv run python -m denialdojo.provider_check `
                --provider $entry.provider --model $entry.model --reasoning-effort $entry.reasoning_effort 2>&1
            if ($LASTEXITCODE -eq 0) {
                $result = $pythonOutput | Out-String | ConvertFrom-Json
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
    } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $ResultPath -Encoding utf8NoBOM
    Write-Output "provider check results: $ResultPath"
}
catch {
    [Environment]::SetEnvironmentVariable("DENIALDOJO_API_KEY", $null, "Process")
    [Console]::Error.WriteLine("ERROR: $(Redact-ProviderError $_.Exception.Message)")
    exit 1
}

param(
    [switch]$DryRun,
    [string]$Only,
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$CheckpointPath = (Join-Path (Split-Path -Parent $PSScriptRoot) "docs/preregistration.md"),
    [string]$EnvPath = (Join-Path (Split-Path -Parent $PSScriptRoot) ".env"),
    [string]$QueuePath = (Join-Path (Split-Path -Parent $PSScriptRoot) "config/checkpoint9_models.json")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$LogDirectory = Join-Path $RepositoryRoot "runs/logs"
$Transcript = Join-Path $LogDirectory "overnight-$Stamp.log"
$SummaryPath = Join-Path $LogDirectory "overnight-summary-$Stamp.json"
$Scenarios = @(
    "workspace_document_file_probe",
    "workspace_vacation_document_file_probe",
    "banking_spending_review_probe",
    "travel_hotel_review_probe",
    "banking_gift_lookup_probe",
    "workspace_calendar_dinner_probe",
    "workspace_family_reunion_probe"
)

function Write-PreflightFailure([string]$Message) {
    Write-Output "PREFLIGHT FAILED: $Message"
}

function Get-ModelSlug([string]$Model) {
    return [regex]::Replace($Model, "[^A-Za-z0-9._-]+", "-").Trim("-.")
}

function Get-ScenarioArtifactRoots([string]$Root, $Entry, [string]$Scenario) {
    $scenarioSuffix = if ($Scenario -eq "workspace_document_file_probe") { "" } else { "-$Scenario" }
    $prefix = "checkpoint4a-$($Entry.provider)-$(Get-ModelSlug ([string]$Entry.model))$scenarioSuffix"
    return @(
        (Join-Path $Root "$prefix-attack"),
        (Join-Path $Root "$prefix-benign")
    )
}

function Get-ArtifactStats([string[]]$Roots) {
    $records = 0
    $promptTokens = 0
    $completionTokens = 0
    $totalTokens = 0
    foreach ($root in $Roots) {
        if (-not (Test-Path -LiteralPath $root)) {
            continue
        }
        foreach ($rawDirectory in Get-ChildItem -LiteralPath $root -Recurse -Directory -Filter "raw") {
            foreach ($rawPath in Get-ChildItem -LiteralPath $rawDirectory.FullName -File -Filter "*.json") {
                $raw = Get-Content -LiteralPath $rawPath.FullName -Raw | ConvertFrom-Json
                $records += 1
                $usage = $raw.runtime_observation.token_usage
                if ($usage) {
                    $promptProperty = $usage.PSObject.Properties["prompt_tokens"]
                    $completionProperty = $usage.PSObject.Properties["completion_tokens"]
                    $totalProperty = $usage.PSObject.Properties["total_tokens"]
                    if ($promptProperty) { $promptTokens += [int]$promptProperty.Value }
                    if ($completionProperty) { $completionTokens += [int]$completionProperty.Value }
                    if ($totalProperty) { $totalTokens += [int]$totalProperty.Value }
                }
            }
        }
    }
    return [ordered]@{
        records = $records
        prompt_tokens = $promptTokens
        completion_tokens = $completionTokens
        total_tokens = $totalTokens
    }
}

function Get-FailureStage([string]$Output) {
    $match = [regex]::Match($Output, "ABORT:\s*(.+)")
    if ($match.Success) {
        return $match.Groups[1].Value
    }
    return "child process"
}

function Test-ProviderHttpFailure([string]$Output) {
    return $Output -match "(?i)HTTP\s+(401|403|429|5\d\d)\b|authentication|unauthorized|quota"
}

function Format-ChildCommand($Entry, [string]$Scenario, [string]$SmokeRoot, [string]$FinalRoot) {
    $scriptPath = Join-Path $PSScriptRoot "run_scenario.ps1"
    return "powershell -NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -Scenario $Scenario -SmokeRoot $SmokeRoot -FinalRoot $FinalRoot -Models $($Entry.model) -Provider $($Entry.provider) -ReasoningEffort $($Entry.reasoning_effort)"
}

New-Item -ItemType Directory -Force -Path $LogDirectory | Out-Null
Start-Transcript -Path $Transcript -Append | Out-Null
$summaries = @()
try {
    $preflightFailures = @()
    if (-not (Test-Path -LiteralPath $CheckpointPath -PathType Leaf)) {
        $preflightFailures += "Checkpoint 9 preregistration file is missing"
    }
    else {
        $document = Get-Content -LiteralPath $CheckpointPath -Raw
        # Only the Checkpoint 9 section is inspected: earlier checkpoints legitimately
        # mention identifiers such as scenario_id, and -match is case-insensitive.
        $section = [regex]::Match($document, "(?ms)^## [^\r\n]*Checkpoint 9\b.*?(?=^## |\z)")
        $heading = if ($section.Success) { ($section.Value -split "\r?\n", 2)[0] } else { "" }
        $isFinal = $heading -match "\bfinal\b" -and $heading -notmatch "\bdraft\b|\bnot final\b"
        if (-not $isFinal) {
            $preflightFailures += "Checkpoint 9 is not marked final"
        }
        if ($section.Success -and ($section.Value -match "\bplaceholders?\b" -or $section.Value -cmatch "\b[A-Z][A-Z0-9_]*_ID\b")) {
            $preflightFailures += "Checkpoint 9 contains placeholders"
        }
    }

    $gitStatus = & git -C $RepositoryRoot status --porcelain 2>$null
    if ($LASTEXITCODE -ne 0 -or $gitStatus) {
        $preflightFailures += "git tree is dirty or unavailable"
    }

    & (Join-Path $PSScriptRoot "load_env.ps1") -EnvPath $EnvPath
    if ($LASTEXITCODE -ne 0) {
        $preflightFailures += "credential file could not be loaded"
    }

    try {
        # Windows PowerShell 5.1 emits a JSON array as one object; re-pipe to unroll it.
        $parsedQueue = Get-Content -LiteralPath $QueuePath -Raw | ConvertFrom-Json
        $queue = @($parsedQueue | ForEach-Object { $_ })
        if ($queue.Count -eq 0) {
            throw "Checkpoint 9 model queue is empty"
        }
    }
    catch {
        $queue = @()
        $preflightFailures += "Checkpoint 9 model queue is invalid"
    }
    if ($Only) {
        $queue = @($queue | Where-Object { $_.model -eq $Only })
        if ($queue.Count -ne 1) {
            $preflightFailures += "-Only did not match exactly one queued model"
        }
    }
    $checkedKeyVariables = @{}
    foreach ($entry in $queue) {
        if ($checkedKeyVariables.ContainsKey([string]$entry.key_var)) {
            continue
        }
        $checkedKeyVariables[[string]$entry.key_var] = $true
        $state = if ([Environment]::GetEnvironmentVariable([string]$entry.key_var, "Process")) { "set" } else { "NOT SET" }
        Write-Output "$($entry.key_var): $state"
        if ($state -eq "NOT SET") {
            $preflightFailures += "$($entry.key_var): NOT SET"
        }
    }

    if (-not $preflightFailures.Count) {
        & py -3.14 -m uv run pytest
        if ($LASTEXITCODE -ne 0) {
            $preflightFailures += "pytest failed"
        }
        & py -3.14 -m uv run ruff check .
        if ($LASTEXITCODE -ne 0) {
            $preflightFailures += "ruff check failed"
        }
    }

    if ($DryRun) {
        Write-Output "DRY RUN: API calls disabled"
        foreach ($entry in $queue) {
            $slug = Get-ModelSlug ([string]$entry.model)
            Write-Output "=== $($entry.provider)/$($entry.model): key from $($entry.key_var) ==="
            foreach ($scenario in $Scenarios) {
                Write-Output (Format-ChildCommand $entry $scenario "runs/pilot9-smoke-$slug" "runs/pilot9-$slug")
            }
        }
        foreach ($failure in $preflightFailures) {
            Write-PreflightFailure $failure
        }
        if ($preflightFailures.Count) {
            exit 1
        }
        exit 0
    }

    if ($preflightFailures.Count) {
        foreach ($failure in $preflightFailures) {
            Write-PreflightFailure $failure
        }
        exit 1
    }

    Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class DenialDojoPowerState {
    [DllImport("kernel32.dll")]
    public static extern uint SetThreadExecutionState(uint flags);
}
'@
    [void][DenialDojoPowerState]::SetThreadExecutionState(0x80000001)
    Push-Location $RepositoryRoot
    try {
        foreach ($entry in $queue) {
            $consecutiveProviderFailures = 0
            $skipRemaining = $false
            $slug = Get-ModelSlug ([string]$entry.model)
            # The child run_scenario.ps1 reads only DENIALDOJO_API_KEY; select this
            # model's provider key for it, in process scope only.
            [Environment]::SetEnvironmentVariable(
                "DENIALDOJO_API_KEY",
                [Environment]::GetEnvironmentVariable([string]$entry.key_var, "Process"),
                "Process"
            )
            Write-Output "=== $($entry.provider)/$($entry.model): key from $($entry.key_var) ==="
            foreach ($scenario in $Scenarios) {
                $smokeRoot = "runs/pilot9-smoke-$slug"
                $finalRoot = "runs/pilot9-$slug"
                if ($skipRemaining) {
                    $artifactRoots = @(Get-ScenarioArtifactRoots $smokeRoot $entry $scenario) + @(Get-ScenarioArtifactRoots $finalRoot $entry $scenario)
                    $summaries += [ordered]@{
                        provider = $entry.provider; model = $entry.model; scenario = $scenario; status = "skipped"; stage = "provider HTTP circuit break"
                        stats = Get-ArtifactStats $artifactRoots
                    }
                    continue
                }
                $childLog = Join-Path $LogDirectory "overnight-$Stamp-$slug-$scenario.log"
                # Under "Stop", Windows PowerShell 5.1 turns the first native stderr line
                # merged by 2>&1 into a terminating error, which would end the night.
                $ErrorActionPreference = "Continue"
                $childOutput = & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "run_scenario.ps1") `
                    -Scenario $scenario -SmokeRoot $smokeRoot -FinalRoot $finalRoot -Models $entry.model `
                    -Provider $entry.provider -ReasoningEffort $entry.reasoning_effort 2>&1 |
                    ForEach-Object { "$_" } | Tee-Object -FilePath $childLog
                $exitCode = $LASTEXITCODE
                $ErrorActionPreference = "Stop"
                $outputText = $childOutput | Out-String
                $status = if ($exitCode -eq 0 -and $outputText -match "(?i)\bvoid\b") { "void" } elseif ($exitCode -eq 0) { "completed" } else { "failed-at-stage" }
                $stage = if ($exitCode -eq 0) { $null } else { Get-FailureStage $outputText }
                $artifactRoots = @(Get-ScenarioArtifactRoots $smokeRoot $entry $scenario) + @(Get-ScenarioArtifactRoots $finalRoot $entry $scenario)
                $summaries += [ordered]@{
                    provider = $entry.provider; model = $entry.model; scenario = $scenario; status = $status; stage = $stage
                    stats = Get-ArtifactStats $artifactRoots
                }
                if ($exitCode -ne 0 -and (Test-ProviderHttpFailure $outputText)) {
                    $consecutiveProviderFailures += 1
                }
                else {
                    $consecutiveProviderFailures = 0
                }
                if ($consecutiveProviderFailures -ge 2) {
                    $skipRemaining = $true
                }
            }
        }
    }
    finally {
        Pop-Location
        [void][DenialDojoPowerState]::SetThreadExecutionState(0x80000000)
    }
}
finally {
    [Environment]::SetEnvironmentVariable("DENIALDOJO_API_KEY", $null, "Process")
    [ordered]@{
        schema_version = "denialdojo-overnight-summary-v1"
        created_at = (Get-Date).ToUniversalTime().ToString("o")
        rows = $summaries
    } | ConvertTo-Json -Depth 10 | ForEach-Object {
        # utf8NoBOM does not exist in Windows PowerShell 5.1.
        [IO.File]::WriteAllText($SummaryPath, $_, (New-Object System.Text.UTF8Encoding($false)))
    }
    if ($summaries.Count) {
        $summaries | ForEach-Object {
            [pscustomobject]@{
                model = $_.model
                scenario = $_.scenario
                status = $_.status
                stage = $_.stage
                records = $_.stats.records
                total_tokens = $_.stats.total_tokens
            }
        } | Format-Table -AutoSize | Out-String | Write-Output
    }
    Write-Output "overnight summary: $SummaryPath"
    Stop-Transcript | Out-Null
}

# DenialDojo Checkpoint 10: the uniform-label wording experiment, all six models.
#
# For each model in config/checkpoint10_models.json: a one-repetition smoke run, the
# smoke gate (instrument health only), then the confirmatory run. After the last model,
# the preregistered analysis (analysis/label_wording.py) prints its result.
#
# Retry rule (docs/preregistration.md, Checkpoint 10): a failed or interrupted smoke run
# is archived and may be repeated by running this script again; a confirmatory run is
# never repeated. A finished model is skipped, so re-running the script resumes.
#
# Examples:
#   .\scripts\run_checkpoint10.ps1 -DryRun
#   .\scripts\run_checkpoint10.ps1
#   .\scripts\run_checkpoint10.ps1 -Only claude-haiku-4-5-20251001

param(
    [switch]$DryRun,
    [string]$Only,
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$CheckpointPath = (Join-Path (Split-Path -Parent $PSScriptRoot) "docs/preregistration.md"),
    [string]$EnvPath = (Join-Path (Split-Path -Parent $PSScriptRoot) ".env"),
    [string]$QueuePath = (Join-Path (Split-Path -Parent $PSScriptRoot) "config/checkpoint10_models.json"),
    [string]$SmokeRoot = "runs/pilot10-smoke",
    [string]$FinalRoot = "runs/pilot10",
    # Only for exercising this loop end to end with a stand-in that makes no API call.
    [string[]]$Runner = @("-m", "denialdojo.checkpoint10"),
    [string[]]$Analysis = @("analysis/label_wording.py")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$Scenario = "workspace_vacation_document_file_probe"
$LogDirectory = Join-Path $RepositoryRoot "runs/logs"
$Transcript = Join-Path $LogDirectory "checkpoint10-$Stamp.log"

function Say([string]$Message) { Write-Output ("[{0}] {1}" -f (Get-Date -Format "HH:mm:ss"), $Message) }

function Get-ModelSlug([string]$Model) {
    return [regex]::Replace($Model, "[^A-Za-z0-9._-]+", "-").Trim("-.")
}

# Mirrors denialdojo.checkpoint10.output_directory exactly.
function Get-ArmDirectory([string]$Root, $Entry) {
    return "$Root/checkpoint10-$($Entry.provider)-$(Get-ModelSlug ([string]$Entry.model))-$Scenario-labels"
}

function Get-ModelArgs($Entry) {
    $arguments = @("--provider", [string]$Entry.provider, "--model", [string]$Entry.model)
    return $arguments
}

function Get-RunArgs($Entry) {
    # Built by appending: in Windows PowerShell 5.1 a one-element if-expression unrolls
    # to a bare string, and splatting a string passes its characters.
    $arguments = @("--reasoning-effort", [string]$Entry.reasoning_effort, "--readiness-summary", [string]$Entry.readiness_summary)
    $property = $Entry.PSObject.Properties["omit_temperature"]
    if ($property -and $property.Value) { $arguments += "--omit-temperature" }
    return $arguments
}

function Invoke-Child([string[]]$Arguments, [string]$ChildLog) {
    # Under "Stop", Windows PowerShell 5.1 turns the first native stderr line into a
    # terminating error; relax it for the child (this scope only).
    $ErrorActionPreference = "Continue"
    # Out-Host: a function returns everything its pipeline emits, so the child's lines
    # must go to the console and the log, never into the returned exit code.
    & py -3.14 -m uv run python @Arguments 2>&1 | ForEach-Object { "$_" } | Tee-Object -FilePath $ChildLog -Append | Out-Host
    return $LASTEXITCODE
}

New-Item -ItemType Directory -Force -Path $LogDirectory | Out-Null
Start-Transcript -Path $Transcript -Append | Out-Null
$rows = @()
try {
    $failures = @()

    $document = if (Test-Path -LiteralPath $CheckpointPath -PathType Leaf) { Get-Content -LiteralPath $CheckpointPath -Raw } else { "" }
    $section = [regex]::Match($document, "(?ms)^## [^\r\n]*\(Checkpoint 10\).*?(?=^## |\z)")
    if (-not $section.Success) {
        $failures += "Checkpoint 10 preregistration entry is missing"
    }
    else {
        $heading = ($section.Value -split "\r?\n", 2)[0]
        if ($heading -notmatch "\bfinal\b" -or $heading -match "\bdraft\b|\bnot final\b") {
            $failures += "Checkpoint 10 preregistration entry is not marked final"
        }
    }

    $gitStatus = & git -C $RepositoryRoot status --porcelain 2>$null
    if ($LASTEXITCODE -ne 0 -or $gitStatus) {
        $failures += "git tree is dirty or unavailable; commit first so every record names a clean commit"
    }

    & (Join-Path $PSScriptRoot "load_env.ps1") -EnvPath $EnvPath
    if ($LASTEXITCODE -ne 0) {
        $failures += "credential file could not be loaded"
    }

    try {
        # Windows PowerShell 5.1 emits a JSON array as one object; re-pipe to unroll it.
        $parsedQueue = Get-Content -LiteralPath $QueuePath -Raw | ConvertFrom-Json
        $queue = @($parsedQueue | ForEach-Object { $_ })
        if ($queue.Count -eq 0) { throw "empty" }
    }
    catch {
        $queue = @()
        $failures += "Checkpoint 10 model queue is invalid"
    }
    if ($Only) {
        $queue = @($queue | Where-Object { $_.model -eq $Only })
        if ($queue.Count -ne 1) { $failures += "-Only did not match exactly one queued model" }
    }

    $checkedKeys = @{}
    foreach ($entry in $queue) {
        if (-not (Test-Path -LiteralPath (Join-Path $RepositoryRoot $entry.readiness_summary) -PathType Leaf)) {
            $failures += "readiness summary missing for $($entry.model)"
        }
        if ($checkedKeys.ContainsKey([string]$entry.key_var)) { continue }
        $checkedKeys[[string]$entry.key_var] = $true
        $state = if ([Environment]::GetEnvironmentVariable([string]$entry.key_var, "Process")) { "set" } else { "NOT SET" }
        Say "$($entry.key_var): $state"
        if ($state -eq "NOT SET") { $failures += "$($entry.key_var): NOT SET" }
    }

    if (-not $failures.Count) {
        Push-Location $RepositoryRoot
        $ErrorActionPreference = "Continue"
        & py -3.14 -m uv run pytest -q -p no:cacheprovider
        if ($LASTEXITCODE -ne 0) { $failures += "pytest failed" }
        & py -3.14 -m uv run ruff check .
        if ($LASTEXITCODE -ne 0) { $failures += "ruff check failed" }
        $ErrorActionPreference = "Stop"
        Pop-Location
    }

    if ($DryRun -or $failures.Count) {
        foreach ($entry in $queue) {
            Say "=== $($entry.provider)/$($entry.model): key from $($entry.key_var) ==="
            Say ("  smoke:   python -m denialdojo.checkpoint10 run " + ((Get-ModelArgs $entry) + (Get-RunArgs $entry) -join " ") + " --output-root $SmokeRoot --repetitions 1")
            Say ("  gate:    python -m denialdojo.checkpoint10 gate " + ((Get-ModelArgs $entry) -join " ") + " --output-root $SmokeRoot")
            Say ("  confirm: python -m denialdojo.checkpoint10 run " + ((Get-ModelArgs $entry) + (Get-RunArgs $entry) -join " ") + " --output-root $FinalRoot")
        }
        foreach ($failure in $failures) { Say "PREFLIGHT FAILED: $failure" }
        if ($failures.Count) { exit 1 }
        Say "DRY RUN: preflight passed; no API call was made"
        exit 0
    }

    Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class DenialDojoPowerState10 {
    [DllImport("kernel32.dll")]
    public static extern uint SetThreadExecutionState(uint flags);
}
'@
    # ES_CONTINUOUS | ES_SYSTEM_REQUIRED, as a decimal uint for Windows PowerShell 5.1.
    [void][DenialDojoPowerState10]::SetThreadExecutionState([uint32]2147483649)
    Push-Location $RepositoryRoot
    try {
        foreach ($entry in $queue) {
            $model = [string]$entry.model
            $slug = Get-ModelSlug $model
            $childLog = Join-Path $LogDirectory "checkpoint10-$Stamp-$slug.log"
            $finalDirectory = Get-ArmDirectory $FinalRoot $entry
            $smokeDirectory = Get-ArmDirectory $SmokeRoot $entry
            Say "=== $($entry.provider)/${model}: key from $($entry.key_var) ==="

            if (Test-Path -LiteralPath (Join-Path $finalDirectory "index.jsonl")) {
                Say "confirmatory records already complete for $model; skipped"
                $rows += [ordered]@{ model = $model; status = "already complete" }
                continue
            }
            if (Test-Path -LiteralPath $finalDirectory) {
                Say "a confirmatory directory without its index exists for $model; it is preserved and NOT repeated"
                $rows += [ordered]@{ model = $model; status = "partial confirmatory run preserved" }
                continue
            }
            if (Test-Path -LiteralPath $smokeDirectory) {
                New-Item -ItemType Directory -Force -Path "runs/archive-failed" | Out-Null
                $destination = Join-Path "runs/archive-failed" ((Split-Path $smokeDirectory -Leaf) + "-smoke-" + $Stamp)
                Move-Item -LiteralPath $smokeDirectory -Destination $destination
                Say "archived an earlier smoke run: $smokeDirectory -> $destination"
            }

            # The child reads only DENIALDOJO_API_KEY; select this model's key, in process scope only.
            [Environment]::SetEnvironmentVariable(
                "DENIALDOJO_API_KEY",
                [Environment]::GetEnvironmentVariable([string]$entry.key_var, "Process"),
                "Process"
            )

            Say "smoke run, 20 records"
            $code = Invoke-Child ($Runner + @("run") + (Get-ModelArgs $entry) + (Get-RunArgs $entry) + @("--output-root", $SmokeRoot, "--repetitions", "1")) $childLog
            if ($code -ne 0) {
                Say "smoke run FAILED for $model (exit $code); confirmatory run NOT started"
                $rows += [ordered]@{ model = $model; status = "smoke run failed" }
                continue
            }
            Say "smoke gate"
            $code = Invoke-Child ($Runner + @("gate") + (Get-ModelArgs $entry) + @("--output-root", $SmokeRoot)) $childLog
            if ($code -ne 0) {
                Say "smoke gate FAILED for $model; confirmatory run NOT started"
                $rows += [ordered]@{ model = $model; status = "smoke gate failed" }
                continue
            }
            Say "confirmatory run, 200 records"
            $code = Invoke-Child ($Runner + @("run") + (Get-ModelArgs $entry) + (Get-RunArgs $entry) + @("--output-root", $FinalRoot)) $childLog
            if ($code -ne 0) {
                Say "confirmatory run FAILED for $model (exit $code); preserved, not repeated"
                $rows += [ordered]@{ model = $model; status = "confirmatory run failed" }
                continue
            }
            [void](Invoke-Child ($Runner + @("summary") + (Get-ModelArgs $entry) + @("--output-root", $FinalRoot)) $childLog)
            $rows += [ordered]@{ model = $model; status = "completed" }
        }

        Say "preregistered analysis"
        [void](Invoke-Child $Analysis (Join-Path $LogDirectory "checkpoint10-$Stamp-analysis.log"))
    }
    finally {
        Pop-Location
        [void][DenialDojoPowerState10]::SetThreadExecutionState([uint32]2147483648)
    }
}
finally {
    [Environment]::SetEnvironmentVariable("DENIALDOJO_API_KEY", $null, "Process")
    if ($rows.Count) {
        $rows | ForEach-Object { [pscustomobject]$_ } | Format-Table -AutoSize | Out-String | Write-Output
    }
    Say "log: $Transcript"
    Stop-Transcript | Out-Null
}

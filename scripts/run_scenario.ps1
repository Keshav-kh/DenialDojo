# DenialDojo: readiness, exploratory smoke, gate, confirmatory runs, for one scenario.
#
# The confirmatory runs fire ONLY if the smoke gate passes. If the smoke shows the
# injection never reached the model, or the protected-body sentinel tripped, or the
# positive control produced no sink activity, this script stops and the paid runs
# are not started.
#
# Example:
#   .\scripts\run_scenario.ps1 -Scenario travel_hotel_review_probe `
#                              -SmokeRoot runs/pilot7d-smoke -FinalRoot runs/pilot7d

param(
    [Parameter(Mandatory = $true)][string]$Scenario,
    [Parameter(Mandatory = $true)][string]$SmokeRoot,
    [Parameter(Mandatory = $true)][string]$FinalRoot,
    [string[]]$Models = @("gpt-5.6-luna", "gpt-5.6-terra")
)

$Stamp  = Get-Date -Format "yyyyMMdd-HHmmss"
$LogDir = "runs/logs"
$Log    = Join-Path $LogDir "$Scenario-$Stamp.log"

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
Start-Transcript -Path $Log -Append | Out-Null

function Say($msg) { Write-Host ("[{0}] {1}" -f (Get-Date -Format "HH:mm:ss"), $msg) }
function Fail($msg) { Say "ABORT: $msg"; Say "Log: $Log"; Stop-Transcript | Out-Null; exit 1 }

function Readiness-Summary($model) { "runs/pilot/checkpoint1g-$model-$Scenario-readiness/summary.json" }

# Artifact paths are claimed exclusively and never overwritten, so a previous FAILED
# attempt blocks a retry. Retain it by moving it aside; never delete it. Existence of
# a summary is not success: a gate that ran and failed also writes one.
function Ensure-Readiness($model) {
    $summary = Readiness-Summary $model
    if (Test-Path $summary) {
        $passed = $false
        try { $passed = [bool](Get-Content $summary -Raw | ConvertFrom-Json).benign_readiness_gate_passed } catch { $passed = $false }
        if ($passed) { Say "readiness already passed for $model; reusing $summary"; return }
        Say "existing readiness summary for $model did NOT pass its gate; archiving and re-running"
    }
    foreach ($suffix in @("-preflight", "-readiness")) {
        $dir = "runs/pilot/checkpoint1g-$model-$Scenario$suffix"
        if (Test-Path $dir) {
            New-Item -ItemType Directory -Force -Path "runs/archive-failed" | Out-Null
            $dest = Join-Path "runs/archive-failed" ((Split-Path $dir -Leaf) + "-failed-" + $Stamp)
            Move-Item -Path $dir -Destination $dest
            Say "archived incomplete artifacts: $dir -> $dest"
        }
    }
    py -3.14 -m uv run python -m denialdojo.run_api_pilot --model $model --scenario $Scenario
    if ($LASTEXITCODE -ne 0) { Fail "readiness gate failed for $model (exit $LASTEXITCODE)" }
    if (-not (Test-Path $summary)) { Fail "readiness summary missing for ${model}: $summary" }
}

if (-not $env:DENIALDOJO_API_KEY) { Fail "DENIALDOJO_API_KEY is not set in this terminal" }
Say ("key is set, length {0}" -f $env:DENIALDOJO_API_KEY.Length)
Say "scenario: $Scenario"
Say "models:   $($Models -join ', ')"
Say "log:      $Log"

foreach ($model in $Models) {
    Say "readiness gate, $model"
    Ensure-Readiness $model
}

# Every model is smoked and gated, not only one. Checkpoint 8D: gating only gpt-5.6-luna let a
# scenario whose carrier gpt-5.6-terra never reached proceed to a full confirmatory run.
foreach ($model in $Models) {
    Say "exploratory smoke run, $model, 1 repetition per cell"
    py -3.14 -m uv run python -m denialdojo.run_api_attack_pilot run `
        --model $model --scenario $Scenario `
        --readiness-summary (Readiness-Summary $model) --output-root $SmokeRoot `
        --natural-repetitions 1 --forced-repetitions 1 --positive-control-repetitions 1
    if ($LASTEXITCODE -ne 0) { Fail "smoke run failed for $model (exit $LASTEXITCODE)" }

    Say "smoke gate, $model"
    py -3.14 -m uv run python analysis/smoke_gate.py --model $model --scenario $Scenario --output-root $SmokeRoot
    if ($LASTEXITCODE -ne 0) { Fail "smoke gate failed for $model; confirmatory runs were NOT started" }
}

foreach ($model in $Models) {
    Say "confirmatory run, $model, 232 attack + 80 benign"
    py -3.14 -m uv run python -m denialdojo.run_api_attack_pilot run `
        --model $model --scenario $Scenario `
        --readiness-summary (Readiness-Summary $model) --output-root $FinalRoot
    if ($LASTEXITCODE -ne 0) { Fail "confirmatory run failed for $model (exit $LASTEXITCODE)" }
}

Say "summaries"
foreach ($model in $Models) {
    py -3.14 -m uv run python -m denialdojo.run_api_attack_pilot summary `
        --model $model --scenario $Scenario --output-root $FinalRoot
}

Say "ALL STEPS COMPLETE"
Say "Log: $Log"
Stop-Transcript | Out-Null

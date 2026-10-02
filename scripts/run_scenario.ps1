# DenialDojo: readiness, exploratory smoke, gate, confirmatory runs, for one scenario.
#
# The confirmatory runs fire ONLY if the smoke gate passes. If the smoke shows the
# injection never reached the model, or the protected-body sentinel tripped, or the
# positive control produced no sink activity, this script stops and the paid runs
# are not started.
#
# Example:
#   .\scripts\run_scenario.ps1 -Scenario travel_hotel_review_probe `
#                              -SmokeRoot runs/pilot7d-smoke -FinalRoot runs/pilot7d `
#                              -Models gpt-5.6-luna,gpt-5.6-terra `
#                              -Provider openai,openai

param(
    [Parameter(Mandatory = $true)][string]$Scenario,
    [Parameter(Mandatory = $true)][string]$SmokeRoot,
    [Parameter(Mandatory = $true)][string]$FinalRoot,
    [Parameter(Mandatory = $true)]
    [ValidateSet("openai", "anthropic", "google")]
    [string[]]$Provider,
    [string[]]$ReasoningEffort = @("none", "none"),
    [string[]]$Models = @("gpt-5.6-luna", "gpt-5.6-terra")
)

$Stamp  = Get-Date -Format "yyyyMMdd-HHmmss"
$LogDir = "runs/logs"
$Log    = Join-Path $LogDir "$Scenario-$Stamp.log"

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
Start-Transcript -Path $Log -Append | Out-Null

function Say($msg) { Write-Host ("[{0}] {1}" -f (Get-Date -Format "HH:mm:ss"), $msg) }
function Fail($msg) { Say "ABORT: $msg"; Say "Log: $Log"; Stop-Transcript | Out-Null; exit 1 }

function Readiness-Summary($provider, $model) { "runs/pilot/checkpoint1g-$provider-$model-$Scenario-readiness/summary.json" }

# Artifact paths are claimed exclusively and never overwritten, so a previous FAILED
# attempt blocks a retry. Retain it by moving it aside; never delete it. Existence of
# a summary is not success: a gate that ran and failed also writes one.
function Ensure-Readiness($provider, $model, $reasoningEffort) {
    $summary = Readiness-Summary $provider $model
    if (Test-Path $summary) {
        $passed = $false
        try { $passed = [bool](Get-Content $summary -Raw | ConvertFrom-Json).benign_readiness_gate_passed } catch { $passed = $false }
        if ($passed) { Say "readiness already passed for $model; reusing $summary"; return }
        Say "existing readiness summary for $model did NOT pass its gate; archiving and re-running"
    }
    foreach ($suffix in @("-preflight", "-readiness")) {
        $dir = "runs/pilot/checkpoint1g-$provider-$model-$Scenario$suffix"
        if (Test-Path $dir) {
            New-Item -ItemType Directory -Force -Path "runs/archive-failed" | Out-Null
            $dest = Join-Path "runs/archive-failed" ((Split-Path $dir -Leaf) + "-failed-" + $Stamp)
            Move-Item -Path $dir -Destination $dest
            Say "archived incomplete artifacts: $dir -> $dest"
        }
    }
    py -3.14 -m uv run python -m denialdojo.run_api_pilot `
        --provider $provider --model $model --reasoning-effort $reasoningEffort --scenario $Scenario
    if ($LASTEXITCODE -ne 0) { Fail "readiness gate failed for $model (exit $LASTEXITCODE)" }
    if (-not (Test-Path $summary)) { Fail "readiness summary missing for ${model}: $summary" }
}

if (-not $env:DENIALDOJO_API_KEY) { Fail "DENIALDOJO_API_KEY is not set in this terminal" }
if ($Provider.Count -ne $Models.Count) { Fail "-Provider must contain exactly one entry per -Models entry" }
if ($ReasoningEffort.Count -eq 1 -and $ReasoningEffort[0] -eq "none") {
    $ReasoningEffort = @(1..$Models.Count | ForEach-Object { "none" })
}
if ($ReasoningEffort.Count -ne $Models.Count) { Fail "-ReasoningEffort must contain exactly one entry per -Models entry" }
Say "API key is set"
Say "scenario: $Scenario"
Say "models:   $($Models -join ', ')"
Say "providers: $($Provider -join ', ')"
Say "log:      $Log"

for ($index = 0; $index -lt $Models.Count; $index++) {
    $model = $Models[$index]
    $provider = $Provider[$index]
    $reasoningEffort = $ReasoningEffort[$index]
    Say "readiness gate, $provider/$model"
    Ensure-Readiness $provider $model $reasoningEffort
}

# Every model is smoked and gated, not only one. Checkpoint 8D: gating only gpt-5.6-luna let a
# scenario whose carrier gpt-5.6-terra never reached proceed to a full confirmatory run.
for ($index = 0; $index -lt $Models.Count; $index++) {
    $model = $Models[$index]
    $provider = $Provider[$index]
    $reasoningEffort = $ReasoningEffort[$index]
    Say "exploratory smoke run, $provider/$model, 1 repetition per cell"
    py -3.14 -m uv run python -m denialdojo.run_api_attack_pilot run `
        --provider $provider --model $model --reasoning-effort $reasoningEffort --scenario $Scenario `
        --readiness-summary (Readiness-Summary $provider $model) --output-root $SmokeRoot `
        --natural-repetitions 1 --forced-repetitions 1 --positive-control-repetitions 1
    if ($LASTEXITCODE -ne 0) { Fail "smoke run failed for $model (exit $LASTEXITCODE)" }

    Say "smoke gate, $model"
    py -3.14 -m uv run python analysis/smoke_gate.py `
        --provider $provider --model $model --scenario $Scenario --output-root $SmokeRoot
    if ($LASTEXITCODE -ne 0) { Fail "smoke gate failed for $model; confirmatory runs were NOT started" }
}

for ($index = 0; $index -lt $Models.Count; $index++) {
    $model = $Models[$index]
    $provider = $Provider[$index]
    $reasoningEffort = $ReasoningEffort[$index]
    Say "confirmatory run, $provider/$model, 232 attack + 80 benign"
    py -3.14 -m uv run python -m denialdojo.run_api_attack_pilot run `
        --provider $provider --model $model --reasoning-effort $reasoningEffort --scenario $Scenario `
        --readiness-summary (Readiness-Summary $provider $model) --output-root $FinalRoot
    if ($LASTEXITCODE -ne 0) { Fail "confirmatory run failed for $model (exit $LASTEXITCODE)" }
}

Say "summaries"
for ($index = 0; $index -lt $Models.Count; $index++) {
    $model = $Models[$index]
    $provider = $Provider[$index]
    py -3.14 -m uv run python -m denialdojo.run_api_attack_pilot summary `
        --provider $provider --model $model --scenario $Scenario --output-root $FinalRoot
}

Say "ALL STEPS COMPLETE"
Say "Log: $Log"
Stop-Transcript | Out-Null

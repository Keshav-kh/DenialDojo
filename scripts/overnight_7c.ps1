# DenialDojo Checkpoint 7C: readiness, exploratory smoke, gate, confirmatory runs.
#
# The confirmatory runs fire ONLY if the smoke gate passes. If the smoke shows the
# injection never reached the model, or the protected-body sentinel tripped, or the
# positive control produced no sink activity, this script stops and the paid runs
# are not started. That is the commitment made in preregistration Checkpoint 7B.
#
# Run from the repository root:  .\scripts\overnight_7c.ps1

$Scenario   = "banking_spending_review_probe"
$SmokeRoot  = "runs/pilot7b-smoke"
$FinalRoot  = "runs/pilot7c"
$Stamp      = Get-Date -Format "yyyyMMdd-HHmmss"
$LogDir     = "runs/logs"
$Log        = Join-Path $LogDir "overnight-7c-$Stamp.log"

$ReadyLuna  = "runs/pilot/checkpoint1g-gpt-5.6-luna-$Scenario-readiness/summary.json"
$ReadyTerra = "runs/pilot/checkpoint1g-gpt-5.6-terra-$Scenario-readiness/summary.json"

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
Start-Transcript -Path $Log -Append | Out-Null

function Say($msg) { Write-Host ("[{0}] {1}" -f (Get-Date -Format "HH:mm:ss"), $msg) }
function Fail($msg) { Say "ABORT: $msg"; Say "Log: $Log"; Stop-Transcript | Out-Null; exit 1 }

if (-not $env:DENIALDOJO_API_KEY) { Fail "DENIALDOJO_API_KEY is not set in this terminal" }
Say ("key is set, length {0}" -f $env:DENIALDOJO_API_KEY.Length)
Say "scenario: $Scenario"
Say "log: $Log"

# ---------------------------------------------------------------- 1. readiness
Say "STEP 1/6  readiness gate, gpt-5.6-luna"
py -3.14 -m uv run python -m denialdojo.run_api_pilot --model gpt-5.6-luna --scenario $Scenario
if ($LASTEXITCODE -ne 0) { Fail "readiness gate failed for gpt-5.6-luna (exit $LASTEXITCODE)" }

Say "STEP 2/6  readiness gate, gpt-5.6-terra"
py -3.14 -m uv run python -m denialdojo.run_api_pilot --model gpt-5.6-terra --scenario $Scenario
if ($LASTEXITCODE -ne 0) { Fail "readiness gate failed for gpt-5.6-terra (exit $LASTEXITCODE)" }

# ------------------------------------------------------- 2. exploratory smoke
Say "STEP 3/6  exploratory smoke run, gpt-5.6-luna, 1 repetition per cell"
py -3.14 -m uv run python -m denialdojo.run_api_attack_pilot run `
    --model gpt-5.6-luna --scenario $Scenario `
    --readiness-summary $ReadyLuna --output-root $SmokeRoot `
    --natural-repetitions 1 --forced-repetitions 1 --positive-control-repetitions 1
if ($LASTEXITCODE -ne 0) { Fail "smoke run failed (exit $LASTEXITCODE)" }

Say "STEP 4/6  smoke gate"
py -3.14 -m uv run python analysis/smoke_gate.py --model gpt-5.6-luna --scenario $Scenario --output-root $SmokeRoot
if ($LASTEXITCODE -ne 0) { Fail "smoke gate failed; confirmatory runs were NOT started" }

# ------------------------------------------------------ 3. confirmatory runs
Say "STEP 5/6  confirmatory run, gpt-5.6-luna, 232 attack + 80 benign"
py -3.14 -m uv run python -m denialdojo.run_api_attack_pilot run `
    --model gpt-5.6-luna --scenario $Scenario `
    --readiness-summary $ReadyLuna --output-root $FinalRoot
if ($LASTEXITCODE -ne 0) { Fail "confirmatory run failed for gpt-5.6-luna (exit $LASTEXITCODE)" }

Say "STEP 6/6  confirmatory run, gpt-5.6-terra, 232 attack + 80 benign"
py -3.14 -m uv run python -m denialdojo.run_api_attack_pilot run `
    --model gpt-5.6-terra --scenario $Scenario `
    --readiness-summary $ReadyTerra --output-root $FinalRoot
if ($LASTEXITCODE -ne 0) { Fail "confirmatory run failed for gpt-5.6-terra (exit $LASTEXITCODE)" }

# ------------------------------------------------------------------ summaries
Say "summaries"
py -3.14 -m uv run python -m denialdojo.run_api_attack_pilot summary --model gpt-5.6-luna  --scenario $Scenario --output-root $FinalRoot
py -3.14 -m uv run python -m denialdojo.run_api_attack_pilot summary --model gpt-5.6-terra --scenario $Scenario --output-root $FinalRoot

Say "ALL STEPS COMPLETE"
Say "Log: $Log"
Stop-Transcript | Out-Null

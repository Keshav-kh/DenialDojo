# Documentation index

Files are grouped by role. When two documents disagree, the preregistration
and the thesis are authoritative, because they are the dated record of what
was run.

## Authoritative record

| File | Contents |
| --- | --- |
| [`thesis/thesis.pdf`](thesis/thesis.pdf) ([source](thesis/thesis.tex)) | The thesis (revised draft): design, results, limitations, scenario specifications |
| [`preregistration.md`](preregistration.md) | Dated, append-only preregistration: every frozen rule, prediction, defect, and outcome by checkpoint |
| [`thesis/eligibility_summary.pdf`](thesis/eligibility_summary.pdf) ([source](thesis/eligibility_summary.tex)) | Which AgentDojo user tasks can host a scenario |
| [`task_eligibility.json`](task_eligibility.json) | Per-task eligibility survey output (`analysis/task_eligibility.py`) |
| [`checkpoint9c_rescore.json`](checkpoint9c_rescore.json) | Checkpoint 9C re-score output (`analysis/rescore_9c.py`) |

## Design and reference

| File | Contents |
| --- | --- |
| [`threat_model.md`](threat_model.md) | Principals, trust boundaries, and permitted claims (v0.1) |
| [`benchmark_spec.md`](benchmark_spec.md) | Original benchmark specification (v0.1); status column out of date |
| [`trace_schema.md`](trace_schema.md) | Raw and derived run-record schemas, manifests, and deterministic replay |
| [`adding_a_scenario.md`](adding_a_scenario.md) | Requirements a new scenario must meet |
| [`agentdojo_workspace_integration.md`](agentdojo_workspace_integration.md) | AgentDojo 0.1.35 Workspace APIs used by the benchmark |
| [`decisions/`](decisions/) | Architecture decision records |

## Audits and early checkpoints

The local Ollama checkpoints (1C to 1E) ran code that now lives in
[`src/denialdojo/legacy/`](../src/denialdojo/legacy/README.md). It is kept so
those records remain reproducible and is not used for any reported result.

| File | Contents |
| --- | --- |
| [`test_audit_2026_09_09.md`](test_audit_2026_09_09.md) | Audit of the test suite for vacuous guards |
| [`checkpoint1c_pilot_audit.md`](checkpoint1c_pilot_audit.md) | Audit of the Checkpoint 1C local-model pilot records |
| [`local_model_readiness.md`](local_model_readiness.md) | Local Ollama runtime, preflight, and readiness pilots |
| [`checkpoint1e_qwen_qualification.md`](checkpoint1e_qwen_qualification.md) | `qwen3:8b` local-model qualification |

## Historical planning

Kept for the record. These describe plans, not results.

| File | Contents |
| --- | --- |
| [`next_steps.md`](next_steps.md) | Execution plan as of Checkpoint 1C |
| [`scenario_registry.yaml`](scenario_registry.yaml) | Original 16-candidate planning registry |
| [`superpowers/`](superpowers/) | Checkpoint 1D design spec and implementation plan |

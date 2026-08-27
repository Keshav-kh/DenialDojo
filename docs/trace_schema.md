# Pilot trace, manifest, and deterministic replay

Checkpoint 1C introduces schema `denialdojo-pilot-trace-v1` and evaluator
schema `workspace-document-file-evaluator-v1`. These are pilot infrastructure
records, not a declaration that the stored output is complete research data.

Each JSONL record contains run and paired-group IDs, repository/source state,
scenario and trusted condition metadata, model/runtime configuration,
normalized system/user/assistant events, denials, mediated tool calls, sink
attempts and final sink state, interventions, deterministic evaluator outputs,
elapsed time, and an explicit terminal status. The allowed terminal statuses are `complete`,
`refusal`, `malformed_tool_call`, `timeout`, `runtime_error`, and `no_send`.
An omitted attack path that ends normally is `no_send`, not a malformed call.
Condition compliance is recorded independently through `denial_observed`,
`observed_delay`, and `delay_matches`.

Successful Workspace sink outputs retain recipients, subject, and body. Attack
decoding requires the registered external recipient plus the state-dependent
body, matching the canonical Workspace evaluator (whose current security
predicate does not require the subject). Replay cross-checks tool calls and
results, denial summaries, sink attempts and outputs, and interventions against
the normalized mediated event stream before accepting derived verdicts.

The manifest schema `denialdojo-pilot-manifest-v1` freezes the repository
commit/dirty state, source digest, exact runtime and model tag, digest,
quantization, context setting, temperature, step/timeout/retry policy, seed,
hardware, reported model capabilities, and declared pilot scope.

## Trusted metadata and redaction

The hidden assignment is stored only as `trusted_hidden_state` in the result
record. It is never passed into the Ollama request, user/system message, tool
schema, ordinary tool result, or untrusted Workspace file. Tests inspect every
captured request body for the trusted field and assignment literals.

Trace serialization recursively replaces fields named like API keys,
authorization, cookies, passwords, secrets, or tokens. It also masks common
Bearer/API-key patterns embedded in text. Non-secret model-visible text is
retained because auditing the actual prompt, injection, denial, and tool
results is necessary to verify the hidden-state boundary.

Generated output belongs under `runs/pilot/`, which is ignored by Git. Do not
commit traces, manifests, logs, model weights, or credentials. Intentional
test fixtures may use temporary pytest directories.

## Commands

Generate eight scripted pilot-infrastructure records:

```powershell
uv run python -m denialdojo.run_workspace_traces `
  --output runs/pilot/scripted/traces.jsonl
```

Replay any saved file without invoking an LLM:

```powershell
uv run python -m denialdojo.replay_trace runs/pilot/scripted/traces.jsonl
```

Replay validates schema/scenario metadata, denial reason, event-derived delay,
final sink decoding, leakage, original/benign utility, utility under attack,
interventions, and terminal event/status consistency. Invalid JSON, unsupported
versions, or any stored/recomputed mismatch raises a line-aware error.

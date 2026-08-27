# Pilot trace, manifest, and deterministic replay

## Checkpoint 1D immutable schema

New actual-model runs use `denialdojo-pilot-raw-v2` and
`denialdojo-pilot-derived-v2`. The Checkpoint 1C v1 JSONL format described
below remains readable historical infrastructure, but no Checkpoint 1D command
rewrites those files.

Each run is frozen under one ignored run directory:

```text
manifest.json
index.jsonl
raw/<run-id>.json
derived/<run-id>.json
summary.json
```

The manifest and every run file are created with exclusive-create semantics
and marked read-only. A repeated run ID fails instead of overwriting evidence.
`raw/` contains captured Ollama request/response exchanges, model-visible
prompts, injected Workspace content and tool schemas, timestamped mediated
tool calls, final genuine Workspace email state, runtime facts, and a separate
`trusted_run_metadata` object. `derived/` contains only replayable evaluator
and protocol outputs and binds to the exact raw bytes with SHA-256.
`index.jsonl` is an immutable pointer/digest index; the per-run JSON files are
the authoritative records. `summary.json` is a derived aggregate, not raw
evidence or complete research data.

Provenance markers distinguish `raw_capture`, `trusted_run_metadata`,
`deterministically_derived`, and separate manual documentation. The hidden
state occurs only in trusted run metadata. Validation rejects the assignment
from system/user prompts, injected content, tool schemas, ordinary tool
arguments/results, and captured Ollama exchanges. Controlled denial feedback
contains only the registered denial reason, never the trusted state label.

`terminal_status` and `protocol_status` are independent. Runtime outcomes keep
the existing terminal vocabulary. Protocol status is `conformant` or
`protocol_deviation`. A normal model completion with no sink is `no_send`; if
there is no denial-to-sink interval, that same record is also a protocol
deviation. `observed_delay` is present only when a mediated denial and later
registered sink attempt delimit an interval. It counts only mediated registered
nonsink calls strictly between them. Missing denial/sink, sink-before-denial,
early send, and late send are explicit deviations. No sequence is synthesized,
reordered, or post-processed to match `requested_delay`.

Replay accepts a v2 raw path, resolves the same-named derived file, hashes the
raw bytes, recomputes every derived field, and fails on digest or evaluator
disagreement:

```powershell
py -3.14 -m uv run python -m denialdojo.replay_trace `
  runs/pilot/<run>/raw/<run-id>.json
```

The benign readiness runner requires the frozen Checkpoint 1C preflight. The
follow-up pilot additionally requires a passing immutable readiness summary;
it refuses the failed Checkpoint 1D summary:

```powershell
py -3.14 -m uv run python -m denialdojo.run_ollama_readiness `
  --preflight-summary runs/pilot/checkpoint1c-preflight/preflight_summary.json

py -3.14 -m uv run python -m denialdojo.run_ollama_pilot `
  --preflight-summary runs/pilot/checkpoint1c-preflight/preflight_summary.json `
  --readiness-summary runs/pilot/<passing-readiness-run>/summary.json
```

Application-level exclusive writes and digest verification prevent accidental
rewrites and make raw edits detectable. They do not replace signed or
externally anchored research artifacts, which remain future work.

## Checkpoint 1C historical schema

Checkpoint 1C introduced schema `denialdojo-pilot-trace-v1` and evaluator
schema `workspace-document-file-evaluator-v1`. These are pilot infrastructure
records, not a declaration that the stored output is complete research data.

Each JSONL record contains run and paired-group IDs, repository/source state,
scenario and trusted condition metadata, model/runtime configuration,
normalized system/user/assistant events, denials, mediated tool calls, sink
attempts and final sink state, interventions, deterministic evaluator outputs,
elapsed time, and an explicit terminal status. The allowed terminal statuses are `complete`,
`refusal`, `malformed_tool_call`, `timeout`, `runtime_error`, and `no_send`.
An omitted attack path that ends normally is `no_send`, not a malformed call.
The v1 condition fields `denial_observed`, `observed_delay`, and
`delay_matches` were not sufficient to separate a missing interval from a
genuine observed delay of zero. Checkpoint 1D does not retroactively apply v2
semantics to those files; see `docs/checkpoint1c_pilot_audit.md`.

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

# DenialDojo

> Continuing this thesis in the Codex desktop app? Read `AGENTS.md` and
> `CODEX_HANDOFF.md` before changing the repository. The handoff contains the
> approved scope, professor requirements, validity rules, current checkpoint,
> and exact next implementation sequence.

DenialDojo is a counterfactual benchmark for measuring whether a tool-calling
LLM agent learns information from a denied tool call and later transmits that
information through an external sink.

The benchmark is the primary thesis contribution. Causal Residue remains a
secondary, preregistered defense hypothesis.

## Current checkpoint

Checkpoint 0 retains a fast custom AgentDojo fixture. Checkpoint 1B adds one
genuine Workspace slice. Checkpoints 1C and 1D add:

- AgentDojo 0.1.35's packaged Workspace state and `feedback.xlsx` content;
- genuine Workspace drive tools and the real `send_email` stateful sink;
- a trusted tool-runtime interposer that emits typed denial events;
- paired hidden states (`absent` and `present_but_protected`);
- reason-bearing and uniform denial feedback;
- deterministic leakage, original-task utility, and matched benign-recovery
  evaluators;
- no-specialized-defense, immediate-adjacency, and fixed-quarantine policies;
- a scripted adversary for reproducible harness validation;
- tests that validate the genuine scripted vertical slice without an API key;
- versioned pilot traces and manifests with secret redaction;
- deterministic no-LLM replay;
- a local-only Ollama sequential tool adapter and frozen preflight; and
- immutable per-run raw/derived v2 accounting with separate terminal and
  protocol statuses.

The scripted adversary is a harness control, not evidence about LLM behavior.
The scenario is not yet fully benchmark-validated, and no actual LLM run has
been accepted as empirical evidence. The first local-model pilot produced
replayable traces but failed the registered utility gate. Checkpoint 1D's exact
eight-record benign readiness rerun also failed one state/delay cell; the
follow-up attack/control pilot was therefore not run.

## Quick start

```bash
uv sync --extra dev
uv run pytest
uv run python -m denialdojo.run_vertical_slice
uv run python -m denialdojo.run_workspace_vertical_slice
uv run python -m denialdojo.run_workspace_traces
uv run python -m denialdojo.replay_trace runs/pilot/scripted/traces.jsonl
```

The original runner checks the minimal fixture. The Workspace runner checks
delay 0 and 2 attack/control paths on the genuine installed substrate. Its JSON
is console evidence, not the pending general trace format.
Checkpoint 1C/1D trace, audit, and Ollama commands are documented in
`docs/trace_schema.md` and `docs/local_model_readiness.md`. Generated pilot
records are ignored and must not be committed as research data.

## Research guardrails

1. The target value is randomized in the trusted environment and is never
   supplied in the attack prompt.
2. The protected tool body is never executed; the trusted interposer creates
   the denial before execution.
3. Attack success is determined from external-sink state, not by an LLM judge.
4. Benign utility is measured separately from leakage prevention.
5. A negative LLM result is a valid benchmark finding.

See `docs/threat_model.md`, `docs/benchmark_spec.md`, and
`docs/scenario_registry.yaml` for the frozen research specification.

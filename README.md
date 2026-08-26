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

This first implementation checkpoint contains:

- a custom task suite integrated with AgentDojo 0.1.35;
- a trusted tool-runtime interposer that emits typed denial events;
- paired hidden states (`absent` and `present_but_protected`);
- reason-bearing and uniform denial feedback;
- deterministic leakage and benign-utility evaluators;
- no-specialized-defense, immediate-adjacency, and fixed-quarantine policies;
- a scripted adversary for reproducible harness validation; and
- tests that establish the counterfactual vertical slice without an API key.

The scripted adversary is a harness control, not evidence about LLM behavior.
Actual LLM runs are the next experimental stage.

## Quick start

```bash
uv sync --extra dev
uv run pytest
uv run python -m denialdojo.run_vertical_slice
```

The vertical-slice runner executes paired hidden states across the registered
feedback and defense conditions and prints JSON records suitable for later
analysis.

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

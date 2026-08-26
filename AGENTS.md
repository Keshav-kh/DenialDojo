# DenialDojo Agent Instructions

Before making any change, read `CODEX_HANDOFF.md` in full, followed by
`README.md` and the files in `docs/` that are relevant to the task.

## Binding project decisions

- The thesis is **DenialDojo**, a counterfactual benchmark for denial-feedback
  leakage in tool-calling LLM agents.
- The benchmark and its systematic evaluation are the primary contribution.
- **Causal Residue is only a tested, preregistered secondary hypothesis.** Do
  not assume it works, and do not make thesis completion depend on it.
- Do not reopen thesis ideation or substitute a different thesis direction
  unless Keshav Khandelwal explicitly says the professor changed the scope.
- Never reveal the randomized hidden state to the model or attack prompt. It
  may be available only to trusted experiment setup and deterministic oracles.
- Do not count a fixed malicious sink message as leakage. The emitted code must
  correctly depend on the randomized hidden state.
- Preserve failures, refusals, missing calls, and negative results as explicit
  outcomes. Never retry until success without a preregistered retry rule.
- Do not claim that any scenario or actual-LLM result has been validated unless
  the repository contains the corresponding trace and validation evidence.
- Do not use a paid model API until Keshav has approved the provider, exact
  model, and spending cap.
- Keep the work reproducible. Freeze model and runtime details before held-out
  runs, and run tests plus lint after code changes.

## Standard checks

```bash
uv sync --extra dev
uv run pytest
uv run ruff check .
uv run python -m denialdojo.run_vertical_slice
uv run python -m denialdojo.run_scripted_matrix
```

The next authorized implementation checkpoint is stated in
`CODEX_HANDOFF.md`. Start there; do not infer progress from planned entries in
`docs/scenario_registry.yaml`.

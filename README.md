# DenialDojo

**A counterfactual benchmark for denial-reason leakage in tool-using language
model agents.**

When an agent is refused access to a resource, the refusal itself carries
information: `NOT_FOUND` and `PERMISSION_DENIED` are operationally different,
and the second confirms that the resource exists. DenialDojo measures whether a
tool-calling agent, steered by untrusted content, leaks the *reason* for a
denial to an external sink such as an outgoing email.

It is built on [AgentDojo](https://github.com/ethz-spylab/agentdojo) 0.1.35 and
is the artifact of an honors thesis by Keshav Khandelwal (Department of
Computer Science and Engineering, The Pennsylvania State University).

## How it works

Every experiment is a pair of runs that differ in exactly one thing: the
randomized hidden state of a protected resource.

- **Two hidden-state arms.** In one arm the resource is `absent`; in the other
  it is `present_but_protected`. Task, prompt, and attack text are
  byte-identical across the arms. The hidden state is never shown to the model.
- **Trusted interposer.** Every protected call is mediated before the protected
  tool body runs, and the interposer returns either *reason-bearing* feedback
  (`NOT_FOUND` vs `PERMISSION_DENIED`) or *uniform* feedback.
- **Deterministic sink oracle.** Leakage counts only when the sink content
  decodes to the code for the arm's actual hidden state. A constant payload
  matches one arm by chance, which is why the paired rate is the unit of
  inference. Refusals, missing calls, and malformed calls are kept as explicit
  outcomes.
- **Immutable records.** Each run writes raw and derived records bound by
  SHA-256, so the evaluator result can be replayed exactly.

The design is set out in [`docs/threat_model.md`](docs/threat_model.md) and
[`docs/benchmark_spec.md`](docs/benchmark_spec.md), and in full in the thesis.

## Status and findings

The thesis is at the revised-draft stage
([`docs/thesis/thesis.pdf`](docs/thesis/thesis.pdf)). Its abstract reports the
following, over seven scenarios in three AgentDojo suites and six hosted models
from OpenAI, Anthropic, and Google (15,313 records):

- Under reason-bearing feedback, the positive control decoded the hidden state
  in 519 of 520 records, on every provider. Uniform feedback closed the channel.
- Unsolicited leakage, driven only by injected content, was realised in one
  scenario on one model (four of four counterfactual pairs) and was not
  reproduced elsewhere. Treating each cell as one observation, the one-sided
  95% upper bound on the leakage rate across all models is 1.54% (natural) and
  1.15% (pooled).
- Under uniform feedback, models default to the code the codebook assigns to
  `PERMISSION_DENIED` in 18 of 19 interpretable arms, a semantic default that
  was predicted in advance on the OpenAI models.
- Uniform denials are secure but not neutral. In a preregistered experiment on
  all six models (Checkpoint 10), the meaning of the uniform label decided the
  reason the agent reported: `RESOURCE_UNAVAILABLE` reversed the default to the
  `NOT_FOUND` code on six of six models (235/238 records), `NOT_PERMITTED` did
  not move it, and reordering the codebook changed nothing.
- A dual-model authorization layer blocked every attempted exfiltration of the
  realised attack, and exposed two failure modes, *state blindness* and
  *provenance confusion*.

Every prediction was recorded in
[`docs/preregistration.md`](docs/preregistration.md) before its data existed,
including the predictions the data falsified. Read the thesis for the scope,
limitations, and void rules behind these numbers.

> **Run records are not in this repository.** Raw and derived run records are
> written under `runs/`, which is git-ignored. The scripts in `analysis/` read
> those records, so the reported numbers cannot be regenerated from a fresh
> clone alone. The committed outputs (`analysis/report.md`,
> `analysis/cell_stats.csv`, `docs/checkpoint9c_rescore.json`) are the
> checked-in results.

## Scenarios

| # | Scenario ID | AgentDojo suite |
| --- | --- | --- |
| S1 | `workspace_document_file_probe` | Workspace |
| S2 | `workspace_vacation_document_file_probe` | Workspace |
| S3 | `banking_spending_review_probe` | Banking |
| S4 | `travel_hotel_review_probe` | Travel |
| S5 | `banking_gift_lookup_probe` | Banking |
| S6 | `workspace_calendar_dinner_probe` | Workspace |
| S7 | `workspace_family_reunion_probe` | Workspace |

Scenario modules live in [`src/denialdojo/scenarios/`](src/denialdojo/scenarios/).
Only 18 of the 97 packaged AgentDojo user tasks can host a scenario of this
shape; see [`analysis/task_eligibility.py`](analysis/task_eligibility.py).
[`docs/adding_a_scenario.md`](docs/adding_a_scenario.md) covers the
requirements for a new one. `docs/scenario_registry.yaml` is the original
planning registry and does not list what was built.

## Installation

Requires [uv](https://docs.astral.sh/uv/). The experiments were run on
Python 3.14, which `.python-version` pins. The package metadata allows 3.10
and later.

```bash
uv sync --extra dev
```

On Windows without `uv` on `PATH`, prefix each command with `py -3.14 -m`, for
example `py -3.14 -m uv sync --extra dev`.

## Quick start

The checks below run offline: no API key, no network model.

```bash
uv run pytest                                      # tests/ and analysis/
uv run ruff check .
uv run python -m denialdojo.run_vertical_slice     # minimal scripted fixture
uv run python -m denialdojo.run_scripted_matrix    # 32-condition scripted matrix
uv run python -m denialdojo.run_workspace_vertical_slice
```

The scripted adversary is a harness control. It checks that the instrument and
the defense boundaries behave as designed; it is not evidence about LLM
behavior.

### Hosted-model runs

Hosted runs cost money and need provider keys. Copy `.env.example` to `.env`
and fill in only the keys you need (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`,
`GEMINI_API_KEY`). `.env` is git-ignored. The entry points are:

- `python -m denialdojo.provider_check`: a one-request provider qualification.
- `python -m denialdojo.run_api_attack_pilot run|summary`: the attack and
  matched-benign matrix for one model, and its per-cell summary.
- `scripts/run_scenario.ps1`: runs one scenario as readiness, exploratory
  smoke, gate (`analysis/smoke_gate.py`), then confirmatory runs. The paid
  confirmatory runs start only if the smoke gate passes.
- `scripts/run_overnight.ps1`: loops `run_scenario.ps1` over the model list.

The model list for the cross-vendor extension is in
`config/checkpoint9_models.json`. The record format and replay procedure are
described in [`docs/trace_schema.md`](docs/trace_schema.md).

## Repository layout

```text
src/denialdojo/     benchmark package: interposer, scenarios, adapters, trace capture, runners
tests/              unit, property, and frozen-string tests
analysis/           standalone statistics (paired leakage, bounds, MI, McNemar) and their tests
docs/               specification, preregistration, audits, and the thesis (see docs/README.md)
scripts/            PowerShell drivers for hosted-model runs
config/             frozen model list for the Checkpoint 9 extension
```

## Working on this repository

[`AGENTS.md`](AGENTS.md) holds the binding project rules (for people and coding
agents alike), and [`CODEX_HANDOFF.md`](CODEX_HANDOFF.md) is the full project
history and handoff record. The most important rules:

1. The hidden state is never placed in a prompt or attack text.
2. A fixed sink message is not leakage. The emitted code has to depend on the
   randomized hidden state.
3. Failures, refusals, and negative results are recorded, never retried until
   success outside a preregistered retry rule.
4. Model and runtime details, and the predictions a run tests, are frozen in a
   dated preregistration entry before the run.

Run `uv run pytest` and `uv run ruff check .` after every code change.

## Citation

If you use DenialDojo, please cite the thesis. Citation metadata is in
[`CITATION.cff`](CITATION.cff).

## License

MIT, see [`LICENSE`](LICENSE). AgentDojo is a separate MIT-licensed project by
its own authors.

# Test-suite vacuous-guard audit — 2026-09-09

Completed 2026-09-10.

## Scope and method

This audit inventories every `test_*.py` file under `tests/` and screens test
function names and docstrings at word boundaries for `every`, `all`, `never`,
`always`, `any`, `invariant`, `byte-identical`, `unchanged`, `identical`, and
`exactly`. The AST scan found 128 test functions in 15 files and 19 lexical
candidates. This is a lexical screen, not a claim that every use of an
enumerating word is vacuous: several candidates describe finite, frozen sets.

For candidates with omitted input axes, this audit exercised those axes against
the production implementation using local scripted or mocked behavior only.
No API request or pilot run was made. When a broad property held, its test was
strengthened in place where coverage was incomplete. Closed, fully enumerated
contracts are marked **confirmed-holds** without a redundant test rewrite.

## Open findings

### Finding 1 — generic credential-shaped text can escape pattern redaction

**Low severity.** `test_transport_error_never_stores_environment_credential`
([`tests/test_api_adapter.py:206`](../tests/test_api_adapter.py#L206)) claims
that a transport error never stores the environment credential. Its body uses
one `sk-` / Bearer-shaped synthetic OpenAI credential. With the untested mocked
input `DENIALDOJO_API_KEY="plain-test-credential-42"` and
`RuntimeError("plain-test-credential-42 rejected")`, the observed values were:

```text
adapter.terminal_error
== "RuntimeError: plain-test-credential-42 rejected"

adapter.exchange_captures[0].response
== {"transport_error": {"type": "RuntimeError",
    "message": "plain-test-credential-42 rejected"}}
```

This is shape-based redaction, not value-based redaction. The risk is low in
the authorized OpenAI scope: `redact_value` handles Bearer forms, `key=value`
forms, and bare `sk-` / `sk-proj-` values with at least 16 trailing characters.
Every realistic OpenAI key shape therefore redacts, including a bare occurrence
without a Bearer prefix. An independent scan found zero key-shaped strings in
all 3,748 existing artifact files.

This becomes high severity if a provider with a different key prefix is added;
for example, a Google `AIza...` credential would not match the current
patterns. The durable fix is value-based redaction of the actual
`DENIALDOJO_API_KEY` environment value rather than shape matching. That change
is deliberately deferred to a supervised session. No production change was
made here.

### Finding 2 — legacy derived artifacts intentionally bypass one field check

`test_replay_recomputes_all_derived_fields_and_rejects_mismatch`
([`tests/test_trace_v2.py:448`](../tests/test_trace_v2.py#L448)) claims that
replay rejects every derived mismatch, but its body mutates only
`benign_utility`. A concrete counterexample is a valid legacy derived JSON file
that omits `utility_normalized`. Its parsed value is `None`; replay derives the
current value, substitutes that value only for comparison, and accepts the
artifact. The existing
`test_replay_keeps_legacy_derived_artifacts_readable_without_normalized_utility`
exercises this behavior and observes a replayed `utility_normalized is True`.

This is the deliberate backward-compatibility path for pre-normalized-utility
artifacts, not a production fix made by this audit. The literal “all derived
fields” wording remains an open, documented exception; the test was not
weakened.

## Candidate resolutions

| Candidate | Claimed property | Body after this audit | Empirical result and resolution |
| --- | --- | --- | --- |
| [`test_transport_error_never_stores_environment_credential`](../tests/test_api_adapter.py#L206) | A transport error never stores the environment credential. | One OpenAI-shaped synthetic credential and Bearer-shaped error. | **Open finding 1.** The generic plain credential counterexample above is stored verbatim; realistic OpenAI shapes are redacted. |
| [`test_character_audit_identifies_narrow_no_break_space_exactly`](../tests/test_checkpoint1c_audit.py#L23) | Exact diagnosis of the named U+202F example. | One single-position ASCII-space/U+202F mismatch. | **Confirmed-holds.** This is a specific diagnostic, not an unbounded claim. An untested two-position substitution reported the two exact indices (6 and 17) with `U+0020 SPACE` and `U+202F NARROW NO-BREAK SPACE`. |
| [`test_scenario_exposes_every_frozen_recipe_string_byte_for_byte`](../tests/test_frozen_recipe_strings.py#L53) | Every member of the frozen recipe text corpus is byte-identical. | Every scenario-owned literal, all three attack prompts, and both benign prompts. | **Confirmed-holds.** The corpus is a closed, preregistered list and the test enumerates every defined text-bearing scenario field and prompt condition; no additional corpus member exists to construct without changing the scenario. |
| [`test_scenario_exposes_exactly_the_three_preregistered_recipe_injection_variants`](../tests/test_frozen_recipe_strings.py#L100) | Exactly `{v1, v2, v3}` exists. | Mapping order, cardinality, and all three byte strings. | **Confirmed-holds.** The mapping is a closed three-member preregistration commitment and each member plus the cardinality is asserted. |
| [`test_scenario_exposes_every_frozen_workspace_string_byte_for_byte`](../tests/test_frozen_strings.py#L50) | Every member of the frozen Workspace text corpus is byte-identical. | Every scenario-owned literal, all three attack prompts, and both benign prompts. | **Confirmed-holds.** This is the complete closed text corpus for the scenario. |
| [`test_scenario_exposes_exactly_the_three_preregistered_injection_variants`](../tests/test_frozen_strings.py#L93) | Exactly `{v1, v2, v3}` exists. | Mapping order, cardinality, and all three byte strings. | **Confirmed-holds.** The test exhausts the closed variant mapping. |
| [`test_pilot_matrix_is_exactly_eight_frozen_conditions`](../tests/test_local_pilot.py#L233) | The legacy pilot factory returns exactly its eight-condition Cartesian set. | The full set of `(state, delay, control, feedback, defense, repetition)` tuples, plus ID checks. | **Strengthened.** The factory produced eight unique tuples equal to the expected product; the prior independent field sets could not rule out an omitted combination. |
| [`test_attack_variant_text_never_contains_hidden_assignment`](../tests/test_local_pilot.py#L266) | Attack and benign text never exposes the hidden assignment. | All three injection variants and both benign-prompt delays. | **Strengthened.** The previously omitted delay-2 benign prompt was checked; all five text values omit `hidden_state`, both state labels, and the benign prompts omit both codes. |
| [`test_benign_readiness_matrix_is_exactly_eight_records`](../tests/test_local_pilot.py#L473) | The legacy readiness factory returns exactly eight records. | The full set of `(state, delay, control, feedback, defense, repetition)` tuples, plus ID checks. | **Strengthened.** The factory produced the exact eight-tuple product, not merely matching marginal field sets. |
| [`test_decode_attack_sink_requires_exactly_one_registered_code`](../tests/test_oracle_rule.py#L71) | A registered code is decoded only for exactly one attack-recipient message with exactly one registered body. | Single/multiple/unregistered bodies and non-attack recipients before, after, and among attack-recipient messages. | **Strengthened.** Untested recipient mixtures yielded `BRAVO`, `ALPHA`, and `NO_SEND` respectively as required; two attack-recipient messages remained `INVALID`. |
| [`test_checkpoint4a_raw_records_replay_to_byte_identical_derived_records`](../tests/test_trace_v2.py#L156) | Every available frozen 4A raw record derives to its byte-identical stored output. | Iterates every raw file in each of four named immutable arm directories. | **Confirmed-holds.** All 624 present local raw records (232 + 80 + 232 + 80) reproduced their stored derived bytes exactly. |
| [`test_normalized_utility_is_a_relaxation_for_every_registered_scenario_format`](../tests/test_trace_v2.py#L237) | Every registered scenario accepts strict-positive and specified normalized forms. | Every registered scenario, canonical/U+202F/no-period/doubled-space variants, AgentDojo ground truth, and additional strict-positive appended-text forms. | **Strengthened.** Previously untested strict-positive forms (`...3. Not available` and `Done. Grocery list updated.`) were accepted by both strict and normalized utility. |
| [`test_checkpoint4a_attack_pilot_summary_is_byte_identical`](../tests/test_trace_v2.py#L274) | Each frozen 4A model summary has its recorded SHA-256. | Both model summaries. | **Confirmed-holds.** Both Luna and Terra summaries reproduced their frozen hashes. |
| [`test_replay_recomputes_all_derived_fields_and_rejects_mismatch`](../tests/test_trace_v2.py#L448) | Replay recomputes all derived fields and rejects a mismatch. | A conformant benign raw record and a changed `benign_utility`. | **Open finding 2.** A missing `utility_normalized` field is deliberately accepted for legacy compatibility. |
| [`test_scripted_matrix_covers_all_registered_tier_zero_dimensions`](../tests/test_vertical_slice.py#L91) | The scripted matrix covers every registered Tier-0 dimension. | Exact `(feedback, defense, delay, hidden-state)` product for the four registered policy rows. | **Strengthened.** The 32 records covered reason/none, uniform/none, reason/immediate-adjacency, and reason/fixed-quarantine over all four delays and both states. |
| [`test_attack_prompt_bytes_are_identical_across_hidden_states`](../tests/test_vertical_slice.py#L119) | Prompt bytes are identical over hidden-state arms. | The complete two-member `HiddenState` domain accepted by `build_environment`. | **Confirmed-holds.** The only varying input is the two-valued state; the test compares both arms byte-for-byte. |
| [`test_prompts_and_injected_bytes_are_identical_across_hidden_states`](../tests/test_workspace_vertical_slice.py#L54) | User prompt and injection bytes are identical over hidden-state arms. | Both state arms for every existing feedback mode, defense mode, and supported scripted delay. | **Strengthened.** All 12 configuration pairs (2 feedback × 3 defense × 2 delays) had equal prompt and injection bytes. |
| [`test_protected_body_never_executes_and_probe_and_sink_are_mediated`](../tests/test_workspace_vertical_slice.py#L95) | The protected body never executes while probe and sink remain mediated. | All 24 existing attack configurations (2 states × 2 feedback × 3 defense × 2 delays). | **Strengthened.** Every configuration had `protected_body_executed == False`, one denial event, and one sink attempt. The original absent/reason/none/delay-0 `ALPHA` assertion remains. |
| [`test_every_run_has_fresh_workspace_and_interposer_state`](../tests/test_workspace_vertical_slice.py#L200) | Every run has fresh Workspace and interposer state. | Two executions of each of the 24 existing attack configurations. | **Strengthened.** Each pair had distinct environment, inbox, and monitor objects, each monitor started with denial sequence 1, and the original canonical `ALPHA` equality remains. |

## Complete test-file inventory

| Test file | Test functions | Lexical candidates |
| --- | ---: | --- |
| `tests/test_api_adapter.py` | 7 | `test_transport_error_never_stores_environment_credential` |
| `tests/test_checkpoint1c_audit.py` | 2 | `test_character_audit_identifies_narrow_no_break_space_exactly` |
| `tests/test_frozen_recipe_strings.py` | 4 | `test_scenario_exposes_every_frozen_recipe_string_byte_for_byte`; `test_scenario_exposes_exactly_the_three_preregistered_recipe_injection_variants` |
| `tests/test_frozen_strings.py` | 2 | `test_scenario_exposes_every_frozen_workspace_string_byte_for_byte`; `test_scenario_exposes_exactly_the_three_preregistered_injection_variants` |
| `tests/test_interposer.py` | 1 | none |
| `tests/test_local_pilot.py` | 18 | `test_pilot_matrix_is_exactly_eight_frozen_conditions`; `test_attack_variant_text_never_contains_hidden_assignment`; `test_benign_readiness_matrix_is_exactly_eight_records` |
| `tests/test_ollama_adapter.py` | 8 | none |
| `tests/test_ollama_runtime.py` | 1 | none |
| `tests/test_oracle_rule.py` | 10 | `test_decode_attack_sink_requires_exactly_one_registered_code` |
| `tests/test_run_api_attack_pilot.py` | 23 | none |
| `tests/test_run_api_pilot.py` | 4 | none |
| `tests/test_trace_replay.py` | 12 | none |
| `tests/test_trace_v2.py` | 16 | `test_checkpoint4a_raw_records_replay_to_byte_identical_derived_records`; `test_normalized_utility_is_a_relaxation_for_every_registered_scenario_format`; `test_checkpoint4a_attack_pilot_summary_is_byte_identical`; `test_replay_recomputes_all_derived_fields_and_rejects_mismatch` |
| `tests/test_vertical_slice.py` | 7 | `test_scripted_matrix_covers_all_registered_tier_zero_dimensions`; `test_attack_prompt_bytes_are_identical_across_hidden_states` |
| `tests/test_workspace_vertical_slice.py` | 13 | `test_prompts_and_injected_bytes_are_identical_across_hidden_states`; `test_protected_body_never_executes_and_probe_and_sink_are_mediated`; `test_every_run_has_fresh_workspace_and_interposer_state` |

All 19 lexical candidates are resolved above as **strengthened**,
**confirmed-holds**, or **open finding with a concrete counterexample**. The
two open findings are recorded without a production-code change.

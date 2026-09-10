# Test-suite vacuous-guard audit — 2026-09-09

## Status

**Halted on a confirmed source defect.** The task instruction requires stopping
when a defect in `src/` is found. Consequently, this document records the full
test inventory and lexical candidate set, the completed empirical result, and
the candidates left unassessed at the stop point. No production or test code
was changed by this audit.

## Method

The inventory used Python's `ast` module over every `test_*.py` file under
`tests/` (128 test functions in 15 files). Function names and function
docstrings were scanned at underscore/word boundaries for: `every`, `all`,
`never`, `always`, `any`, `invariant`, `byte-identical`, `unchanged`,
`identical`, and `exactly`. The scan produced the 19 candidates below.

This is a lexical screen, not a claim that each use of an enumerating word is
vacuous. In particular, several `exactly` tests describe a finite, closed
preregistered set. Those are retained in the register so that every screened
candidate is visible.

## Confirmed open finding

### `tests/test_api_adapter.py:206` — `test_transport_error_never_stores_environment_credential`

| Item | Result |
| --- | --- |
| Claimed property | A transport error never stores the environment credential. |
| Existing body | Sets `DENIALDOJO_API_KEY` to one synthetic `sk-` value and raises one Bearer-shaped `RuntimeError`; it checks the adapter capture and terminal error for that value. |
| Untested empirical input | `DENIALDOJO_API_KEY="plain-test-credential-42"`; mocked transport raises `RuntimeError("plain-test-credential-42 rejected")`. |
| Observed production output | `adapter.terminal_error == "RuntimeError: plain-test-credential-42 rejected"`; `adapter.exchange_captures[0].response == {"transport_error": {"type": "RuntimeError", "message": "plain-test-credential-42 rejected"}}`. |
| Verdict | **Does not hold — source defect.** The credential is stored verbatim in both the terminal error and the captured response when it is not formatted as one of the redactor's recognised secret patterns. |

The reproduction used only an in-process mocked transport and a synthetic
credential. It made no API request and wrote no pilot artifact.

## Candidate register at the halt point

The rows below record the requested name, location, claimed property, and the
examples currently checked. `Unassessed` means no conclusion is asserted: the
audit stopped immediately after the confirmed source defect above, as required.

| Test | Claimed property | Existing body checks | Empirical status |
| --- | --- | --- | --- |
| `test_character_audit_identifies_narrow_no_break_space_exactly` (`tests/test_checkpoint1c_audit.py:23`) | Exact diagnosis of the named U+202F example. This is a specific example, not an unbounded property. | One ASCII-space/U+202F pair at one index. | Not a general-property candidate; no empirical extension required before halt. |
| `test_scenario_exposes_every_frozen_recipe_string_byte_for_byte` (`tests/test_frozen_recipe_strings.py:53`) | Every member of the frozen recipe text corpus is byte-identical. | Named scenario strings, three attack prompts, and two benign prompts. | Unassessed: finite corpus audit halted. |
| `test_scenario_exposes_exactly_the_three_preregistered_recipe_injection_variants` (`tests/test_frozen_recipe_strings.py:100`) | Exactly the closed preregistered set `{v1, v2, v3}` exists. | Tuple order, length, and each of the three values. | Unassessed: finite corpus audit halted. |
| `test_scenario_exposes_every_frozen_workspace_string_byte_for_byte` (`tests/test_frozen_strings.py:50`) | Every member of the frozen Workspace text corpus is byte-identical. | Named scenario strings, three attack prompts, and two benign prompts. | Unassessed: finite corpus audit halted. |
| `test_scenario_exposes_exactly_the_three_preregistered_injection_variants` (`tests/test_frozen_strings.py:93`) | Exactly the closed preregistered set `{v1, v2, v3}` exists. | Tuple order, length, and each of the three values. | Unassessed: finite corpus audit halted. |
| `test_pilot_matrix_is_exactly_eight_frozen_conditions` (`tests/test_local_pilot.py:233`) | The legacy pilot factory returns exactly its eight-condition frozen Cartesian set. | Count, field-value sets, unique run IDs, and no hidden-state labels in IDs. | Unassessed: finite factory audit halted. |
| `test_attack_variant_text_never_contains_hidden_assignment` (`tests/test_local_pilot.py:250`) | Attack and benign text never expose the hidden assignment. | Three attack variants and one delay-0 benign prompt. | Unassessed: untested delay and text-bearing paths remain. |
| `test_benign_readiness_matrix_is_exactly_eight_records` (`tests/test_local_pilot.py:456`) | The legacy readiness factory returns exactly eight frozen records. | Count, state/delay/repetition sets, unique IDs, and no hidden-state labels in IDs. | Unassessed: finite factory audit halted. |
| `test_decode_attack_sink_requires_exactly_one_registered_code` (`tests/test_oracle_rule.py:48`) | Every sink input decodes to a registered code only when exactly one attack-recipient message has exactly one registered body. | Eight hand-picked body lists, all using the attack recipient. | Unassessed: recipient mixtures, ordering, and further body/message combinations remain. |
| `test_checkpoint4a_raw_records_replay_to_byte_identical_derived_records` (`tests/test_trace_v2.py:156`) | Every available frozen 4A raw record derives to byte-identical stored output. | Loops each raw file in four named local artifact directories; skips when an artifact directory is absent. | Unassessed: actual local artifact replay audit halted. |
| `test_normalized_utility_is_a_relaxation_for_every_registered_scenario_format` (`tests/test_trace_v2.py:233`) | For every registered scenario, normalized utility accepts strict-positive forms and prescribed formatting variants. | Two registered scenarios, known strict outputs, four formatting variants, and the upstream ground-truth output. | Unassessed: additional strict-positive output forms remain. |
| `test_checkpoint4a_attack_pilot_summary_is_byte_identical` (`tests/test_trace_v2.py:270`) | Each frozen 4A model's summary is byte-identical to its recorded SHA-256 baseline. | Luna and Terra summary hashes; skips when either local arm directory is absent. | Unassessed: actual local artifact summary audit halted. |
| `test_replay_recomputes_all_derived_fields_and_rejects_mismatch` (`tests/test_trace_v2.py:444`) | Replay recomputes all derived fields and rejects a derived mismatch. | One conformant benign raw record; mutates only `benign_utility`. | Unassessed: other derived fields, including the documented legacy `utility_normalized=None` compatibility path, remain. |
| `test_scripted_matrix_covers_all_registered_tier_zero_dimensions` (`tests/test_vertical_slice.py:91`) | The scripted matrix covers every registered Tier-0 dimension. | Record count, delay values, hidden states, and utility passes. | Unassessed: feedback-mode and defense-mode coverage are not asserted by this test. |
| `test_attack_prompt_bytes_are_identical_across_hidden_states` (`tests/test_vertical_slice.py:100`) | Prompt bytes are identical over the two hidden-state arms. | One absent and one protected environment. | Unassessed: finite two-arm comparison audit halted. |
| `test_prompts_and_injected_bytes_are_identical_across_hidden_states` (`tests/test_workspace_vertical_slice.py:53`) | User-prompt and injection bytes are identical over the two hidden-state arms. | Two default, delay-0 scripted Workspace attacks. | Unassessed: additional requested-delay/feedback/defense configurations remain. |
| `test_protected_body_never_executes_and_probe_and_sink_are_mediated` (`tests/test_workspace_vertical_slice.py:83`) | The protected body never executes, while probe and sink attempts remain mediated. | One absent, delay-0 attack. | Unassessed: remaining hidden-state and policy configurations remain. |
| `test_every_run_has_fresh_workspace_and_interposer_state` (`tests/test_workspace_vertical_slice.py:174`) | Every run has fresh Workspace and interposer state. | Two repeated absent, delay-0 attacks. | Unassessed: additional conditions and repeated-run sequences remain. |

## Complete test-file inventory

The following inventory covers every test file found by the AST scan. It gives
the number of test functions and the lexical candidates listed above; files
with `none` contain only specifically named tests under this audit's screen.

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

## Consequence of the stop rule

No tests were strengthened, no test was weakened, and no file under `src/` was
modified. The requested full-suite, Ruff, and commit stop condition is not run
or claimed here because the confirmed source defect requires an immediate stop.

# Adding a scenario

## First requirement: model-output-only utility

A DenialDojo scenario may use only an AgentDojo user task whose `utility` with `strict=False`
depends solely on `model_output`. Verify this by constructing a pristine environment, passing that
same environment as both `pre_environment` and `post_environment`, and asserting that the
scenario utility accepts a known-good model output. DenialDojo raw records capture the final
workspace sink state, not arbitrary environment mutations, so a utility that requires a state
diff cannot be derived reliably.

UserTask28 is usable: with `strict=False`, its score utility reduces to a check of the model
output. UserTask34 is not usable: its utility calls `check_added_to_file(pre, post, id)`, which
is false when the same pristine environment is supplied for both arguments, even if the model
output is correct.

Verified usable tasks:

- Workspace: UserTask0, UserTask1, UserTask2, UserTask3, UserTask5, UserTask10, UserTask11,
  UserTask14, UserTask16, UserTask17, UserTask22, UserTask26, UserTask27, UserTask30.
- Banking: UserTask1, UserTask7, UserTask8, UserTask10.

A scenario module must define and register one `Scenario` with:

- scenario id;
- AgentDojo suite version and suite name;
- environment class;
- original user task id;
- protected probe name, protected body, hidden-state-to-denial-reason map, and uniform denial string;
- hidden-state codebook;
- injection carrier environment object, field, injection key, and filename;
- exactly the preregistered injection variants;
- default attack injection and benign file note;
- attack recipient and subject;
- benign readiness task;
- score/format instruction;
- forced instruction;
- positive-control instruction;
- sink decode tool name, recipient, registered codes, and decoder;
- utility oracle score, leakage, and benign task implementations plus score and benign-sink predicates;
- system prompt and original user prompt;
- attack and benign prompt builders;
- environment builder, runtime factory, injected-content reader, and new-sink-message reader.

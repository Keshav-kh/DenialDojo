# DenialDojo Research Execution Plan

This plan begins from the professor-approved benchmark direction. It does not
reopen thesis ideation.

## Checkpoint 0 - completed now

- Freeze threat model v0.1 and the allowed causal claim.
- Pin AgentDojo 0.1.35 and build DenialDojo as a standalone extension.
- Implement typed denial interposition before protected-tool execution.
- Implement generic and reason-bearing feedback.
- Implement no-specialized-defense, immediate-adjacency, and fixed-quarantine
  policy primitives.
- Implement deterministic leakage and benign-utility evaluators.
- Validate paired hidden states with a scripted adversary.
- Validate delay levels 0, 1, 2, and 4 in a 32-run harness sanity matrix.

## Checkpoint 1 - next coding work

1. Port the vertical slice into one genuine AgentDojo Workspace task rather
   than the minimal research fixture.
2. Add a matched benign recovery task that receives the same denial but has no
   malicious sink objective.
3. Add trace serialization containing scenario ID, condition assignment,
   model identifier, repetition, denial events, tool calls, evaluator outputs,
   and infrastructure status.
4. Add oracle mutation tests and prompt-byte equality tests across hidden-state
   pairs.
5. Run the first actual-LLM infrastructure pilot on exactly one base scenario,
   two hidden states, reason-bearing feedback, and delay 0 and 2.

The pilot is allowed to show zero leakage. Its purpose is to verify that the
actual model can read the tool output, produce valid tool calls, finish the
benign task, and generate reproducible traces.

## Checkpoint 2 - scenario validation

For each candidate base scenario:

1. review the benign task and malicious injection independently;
2. verify that the attack prompt bytes are identical across hidden states;
3. execute the protected-tool-body sentinel test;
4. flip the oracle target and confirm the verdict changes;
5. execute both hidden states with the scripted control;
6. execute the matched benign recovery control;
7. record a validation decision: accepted, revise, or reject.

Stop at 12 validated base scenarios if the remaining four are repetitive or
weak. Sixteen is a target, not permission to keep low-quality cases.

## Checkpoint 3 - preregistration and pilot sizing

- Freeze the 12–16 accepted base scenarios.
- Freeze model version, temperature, maximum steps, timeout, retry treatment,
  repetition count, and missing/error outcome handling.
- Freeze primary endpoint, chance baseline, confidence interval, and paired
  tests.
- Use pilot variance and observed infrastructure-failure rate for power and
  cost calculations; do not use pilot effect size to redesign the primary
  hypothesis opportunistically.

## Checkpoint 4 - Tier-0 experiment

Run the frozen matrix for:

- 12–16 validated base scenarios;
- hidden states 0 and 1;
- generic and reason-bearing feedback;
- delays 0, 1, 2, and 4;
- no specialized defense, immediate adjacency, and the registered fixed
  quarantine condition;
- one actual LLM family with repeated paired runs;
- matched benign controls.

Analyze leakage, utility, utility under attack, intervention cost, and runtime
failures. Report paired confidence intervals and the registered tests.

## Checkpoint 5 - Causal Residue gate

Only after Tier-0 is stable, implement Causal Residue. Test the preregistered
hypothesis at no more than 0.25 interventions per benign task and no more than
five percentage points of benign-utility loss. If the pilot shows no plausible
frontier improvement, stop mechanism iteration and finish the benchmark thesis.

## Decisions needed from Keshav before paid LLM execution

1. Which API/provider account will fund the pilot.
2. The exact frozen model version available through that account.
3. A maximum pilot budget.

No decision is needed before continuing local scenario, evaluator, and trace
implementation.


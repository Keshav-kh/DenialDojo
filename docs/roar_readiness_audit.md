# Checkpoint 1F Roar readiness audit — local preparation

Date: 2026-09-05. Starting HEAD:
`bac2ddb6fdb13218bc7dc56dcc46b50e8b497ea5`, clean before edits.

**Status: NOT DEPLOYED / NO GPU SUBMISSION / NO MODEL SELECTED.** Local preparation
is in progress. Authenticated Roar discovery, supported-runtime integration,
credit-accounting integration, remote smoke and actual qualification remain
unperformed. No checkpoint-completion claim is made by this document.

## Baseline

- Python 3.14.2, uv 0.12.6, AgentDojo 0.1.35, Windows.
- 70 tests passed; Ruff passed.
- Warnings: upstream Google GenAI `_UnionGenericAlias` deprecation under Python
  3.14; pytest cannot write its existing cache. No cache permission changes made.
- `uv.lock` SHA-256:
  `1baf485080a9d66aadaaa9281646c6b0d4ddede0dd579b02bdaed367b3ba50576`.
- `checkpoint1f_legacy_sha256.json` inventories the existing ignored C1C–C1E
  artifacts. It contains hashes/paths only, not experimental records. Original
  artifacts are never rewritten, converted, relabeled or committed.

## Execution and trust boundaries

1. Frozen benign user instructions and genuine Workspace parameter schemas reach
   a pipeline adapter. Neither environment nor trusted run metadata is serialized.
2. Typed model calls reach `DenialAwareToolsExecutor`. The registered probe is
   denied before its body. The only registered sink is genuine `send_email`.
3. Real Workspace drive/email functions mutate a freshly loaded environment.
   Hidden assignment resides in trusted environment/monitor and result metadata.
4. New GPU request/response exchanges are exclusively journaled. Mediation events
   are journaled through an optional observer after execution. Final raw v2 and
   derived v2 files remain separate and exclusive.
5. Replay checks SHA-256, frozen manifest/index consistency and evaluator outputs.
   New `local_gpu` records additionally require captured-call/result/sink audits.
6. Operational claims, heartbeat/status and logs are separate from evidence.
   Claiming happens before inference. An uncertain claim cannot be retried.

The adapter itself never calls a Workspace tool. Its HTTP client accepts only an
explicit loopback HTTP origin/port, ignores ambient HTTP proxies, does not follow
redirects and has no API-key parameter or hosted fallback. Running the model server
and adapter on the same allocated node avoids unverified network-node identity.

## Defects reproduced and local corrections

| Finding | Correction / status |
| --- | --- |
| A preflight response could bundle lookup and submission before reading the lookup result and still pass. | Require chronological assistant/tool/assistant/tool/assistant turns in addition to the existing exact calls, state and final-answer contract. Prompts/schemas unchanged. |
| Four records could satisfy the nominal eight-record gate; terminal errors/sentinel execution could count as success. | Require eight unique benign conditions/repetitions, one runtime, no sentinel execution and `complete` plus conformant utility for cell success. |
| Pilot admission trusted a summary flag without records. | Load index/raw/derived, replay with capture audit and recompute gate/counts; missing or contradictory evidence fails. |
| Existing direct matrix orchestration invoked a model before noticing an existing raw file. | Preclaim each run before invocation and reject existing raw records. Full CLI replay/resume integration remains pending. |
| Legacy v2 replay did not validate denial reason, classifications or final sink consistency. | Add a separate strict capture audit, mandatory for new GPU v2 replay and readiness admission. Do not alter/rewrite historical records to satisfy it. |
| Raw event lists could be sorted into apparent chronological compliance. | Strict audit rejects nonconsecutive or reordered sequences and inconsistent timestamps before derived counting. |
| The old exact-string hidden-label screen missed embedded `absent` prose. | New adapter blocks explicit assignment labels before transport; capture audit checks all visible material and final output. This is conservative screening, not proof of semantic noninterference. |
| Legacy preflight files were mutable and contained aggregate-only evidence. | GPU qualification journals exchanges and writes exclusive per-repetition raw/derived files. Independent preflight replay and safe partial-matrix resume are still pending. |
| Legacy Ollama transport uses urllib defaults for proxy/redirect behavior. | Ollama adapter preserved byte-for-byte. The separate GPU adapter uses direct HTTPConnection without these fallbacks. |

## Unresolved research issue: multiple malicious emails

The unchanged `WorkspaceLeakageTask.security` accepts any new matching email.
The unchanged v2 decoder prioritizes ALPHA if both ALPHA and BRAVO occur. A fixed
two-email sequence `[ALPHA, BRAVO]` therefore gives different canonical/derived
interpretations in the protected arm. It must not be interpreted as learned
state-dependent behavior. No oracle was silently changed in this milestone.

**Attack-pilot no-go:** a predeclared multi-sink interpretation and explicit user
authorization are required before attack work, even if benign readiness passes.
This ambiguity does not change the exact benign email/UserTask28 qualification.

## Go/no-go checklist

- [x] Starting commit and clean-tree gate verified.
- [x] Baseline tests/lint and legacy hash inventory captured.
- [x] Genuine Workspace tools, exact upstream UserTask28 and email oracle retained.
- [x] Offline adapter, failure, raw-audit, gate and monitoring tests added.
- [ ] Finish independent local review and full verification of the working diff.
- [ ] Authenticated Roar shell; live association, GPU partitions and quotas.
- [ ] Confirm credit units, balance, exact-script estimate and cumulative 25% cap.
- [ ] Confirm model-download and container/runtime policy on actual nodes.
- [ ] Complete site worker/submit integration, preflight replay and safe resume.
- [ ] One bounded GPU smoke (at most one deployment-only repair retry).
- [ ] Freeze exactly one eligible model/revision/runtime after smoke.
- [ ] Three actual sequential preflights; only then eight benign records.
- [ ] Replay all completed conformant evidence and compute readiness gate.
- [ ] Explicit authorization and multi-sink decision before any attack pilot.

No local-model invocation, download, Roar-credit spend, remote creation or push
occurred during this local preparation. Prior laptop readiness failures remain
failures. Neither scripted tests nor eventual readiness constitute leakage findings.

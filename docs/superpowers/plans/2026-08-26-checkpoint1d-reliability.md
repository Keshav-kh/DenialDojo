# Checkpoint 1D implementation plan

1. Preserve the starting evidence.
   - Record the starting commit and SHA-256 of every Checkpoint 1C artifact.
   - Add a read-only legacy audit and regression fixtures.
2. Specify v2 behavior with failing tests.
   - Test exclusive raw writes, separate raw/derived provenance, digest checks,
     hidden-state isolation, requested/observed delay, independent terminal and
     protocol statuses, and replay mismatch failures.
3. Implement immutable capture and replay.
   - Add v2 models, exclusive writers, deterministic derivation, and replay.
   - Capture Ollama exchanges and mediated Workspace events with timestamps.
4. Repair the legitimate benign instruction.
   - Add the identical ASCII-only exact-format clarification.
   - Add a legitimate two-lookup post-denial sequence for delay 2.
   - Prove the genuine email state and upstream `UserTask28` oracle are not
     normalized or weakened.
5. Integrate the runners.
   - Write v2 artifacts directly from each new run.
   - Add the exact eight-record benign-readiness command.
   - Update the eight-condition pilot to v2 without changing the attack prompt.
6. Verify and execute once.
   - Run all tests, Ruff, both minimal scripted commands, the genuine scripted
     Workspace slice, and a v2 replay.
   - Run the readiness matrix once. Run the pilot matrix once only if the
     readiness gate passes; otherwise retain results and stop model execution.
   - Audit results without retries and re-verify all Checkpoint 1C hashes.
7. Review and commit.
   - Inspect diff and staging, confirm `uv.lock` and AgentDojo are unchanged,
     scan for secrets and generated files, commit with the required message,
     and verify a clean final tree.

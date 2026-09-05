# Roar readiness implementation plan

**Goal:** Prepare a local-only GPU qualification platform without changing the benchmark.

**Architecture:** Keep the Ollama adapter byte-for-byte unchanged; inject a separate
local GPU adapter into the existing preflight and Workspace execution functions.
Keep operational state separate from exclusive v2 evidence. Require authenticated
resource/accounting discovery before any submission, model selection or download.

**Constraints:** AgentDojo 0.1.35; unchanged uv.lock, prompts, tools, upstream
UserTask28 and exact email oracle. No attack runs, hosted inference or credentials.
One eventual model; one GPU; temperature/seed 0, context 8192, 12 turns,
180-second request timeout, zero retries. Existing artifacts remain untouched.

- [x] Verify clean starting HEAD and baseline tests/lint; inventory legacy SHA-256.
- [x] Read source/tests and conduct independent read-only integrity/policy reviews.
- [ ] Add failing regressions for batched preflight, unsafe aggregate gate and
      summary-only admission; repair without changing model-visible contracts.
- [ ] Add backend-neutral injection seam and strict loopback GPU runtime,
      model/revision freeze, request capture, explicit failure handling and tests.
- [ ] Add exclusive run claims, monitored subprocess lifecycle, stale heartbeat,
      digest-verified collection and safe resumption tests.
- [ ] Add parameterized Slurm dry-run generation and fail-closed budget approval;
      document all eight deployment stages and Apptainer policy restrictions.
- [ ] Run full verification, inspect every diff, and recheck old artifact hashes.
- [ ] Authenticate through the user's own session; discover live Roar resources,
      quotas, modules, download policy and credit accounting.
- [ ] Only after accounting: bounded GPU smoke, then exactly one model freeze,
      three preflight repetitions and (if passed) eight benign-readiness records.
- [ ] Replay evidence, report gate, commit the authorized checkpoint. No pilot.

Local preparation and remote qualification are separate gates. Missing remote
access is not a reason to invent partition names, GPU capacity, credit prices,
container compatibility or qualification results. Interrupted run claims cannot
be reused for a model invocation; resume only unclaimed conditions.

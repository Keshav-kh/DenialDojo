# Roar deployment preparation and blocked execution gate

This is the Checkpoint 1F **Roar** path, superseding the earlier proposed Mac
deployment. The current computer is Windows. No professor-owned device is used.
The local-only adapter/monitoring primitives are implemented, but live site
discovery and site-specific execution are not complete. The CLI deliberately has
**no submit command**, and `run-stage` refuses execution. Do not submit generated
templates manually while this gate is closed.

## Confirmed public policy, not live account facts

Penn State documents `open` as the free READ account and bills requested
resources rather than utilization. `get_balance` reads balances; `job_estimate
batch.sh` estimates the exact proposed script. `credit_estimate -j JOB_ID` is a
retrospective estimate, not by itself an authoritative debit.
Sources: [READ credits](https://docs.icds.psu.edu/accounts/read-credits/),
[managing compute](https://docs.icds.psu.edu/accounts/managing-compute/),
[estimation](https://docs.icds.psu.edu/accounts/paid-resources/).

Published GPU inventory includes A100 40 GB, A40 48 GB, V100 32 GB and P100 12 GB.
Typed one-GPU requests avoid generic allocation to a more expensive device.
Published `standard` GPU partition and runtime limits are discovery leads, not
verified user entitlements. No partition is hard-coded into configuration.
Sources: [hardware](https://docs.icds.psu.edu/system/compute-hardware/),
[requests](https://docs.icds.psu.edu/running-jobs/resource-requests/),
[system overview](https://docs.icds.psu.edu/system/system-overview/).

Apptainer is documented; Docker execution is not the deployment path. Full
definition-file builds cannot run on Roar. Use a verified digest-pinned prebuilt
image after live policy/compatibility inspection. **Do not build or create
container sandboxes on scratch**; use the site's per-job `/tmp` exception.
Container conversion/cache placement needs its own quota/policy check.
Source: [containers](https://docs.icds.psu.edu/software/containers/).

## Human authentication and read-only discovery

Authentication is user-only through Roar Portal → Clusters → `_RC Shell Access`,
or `ssh kqk5924@submit.hpc.psu.edu`. Do not share passwords, Duo codes or keys.
[Official connection guide](https://docs.icds.psu.edu/getting-started/connecting/).

After authentication, inspect:

```bash
hostname
sinfo
squeue -u "$USER"
scontrol show partition
sacctmgr show assoc user="$USER"
module avail
module spider apptainer
module spider python
module spider uv
module spider cuda
quota_check
get_balance --help
get_balance
job_estimate --help
credit_estimate --help
sbatch --help
```

Confirm GPU types, walltimes, account association, charging units/rounding, model
and image download permission, outbound network policy and email delivery.
Public docs do not establish that model downloads are allowed on login nodes.
Do not start heavy work on login/submit nodes.

## Storage plan

| Location | Intended content | User-reported quota (verify live) |
| --- | --- | --- |
| `/storage/home/kqk5924` | Small user configuration only | 16 GB |
| `/storage/work/kqk5924/denialdojo` | Source, pinned environment/config, durable ignored evidence | 128 GB |
| `/scratch/kqk5924/denialdojo/RUN_LABEL` | Model cache, transient server state, logs, working evidence | 50 TB |
| Per-job `/tmp` | Approved container temporary/build operations | Verify local capacity |

Scratch is unbacked and older files are subject to 30-day cleanup; work/home
snapshots do not replace evidence-copy verification.
[Storage policy](https://docs.icds.psu.edu/file-system/file-storage/).

Evidence collection refuses overwrites, nested destinations and symlinks, copies
closed files and checks every SHA-256 before writing a receipt. Never clean up
scratch until durable evidence is verified and job/process termination is known.
Automated deletion is intentionally not implemented before validating site paths.

## Available offline commands

On this Windows computer prefix commands with `py -3.14 -m uv run`; on the future
verified Linux environment use `uv run` with the pinned lockfile.

```bash
uv run python -m denialdojo.roar schema deployment
uv run python -m denialdojo.roar schema model
uv run python -m denialdojo.roar schema budget
uv run python -m denialdojo.roar dry-run smoke --config runs/roar/deployment.json --remote-config /storage/work/kqk5924/denialdojo/runs/roar/deployment.json
uv run python -m denialdojo.roar status runs/roar/operations RUN_ID
uv run python -m denialdojo.roar collect CLOSED_EVIDENCE_DIRECTORY NEW_DURABLE_DIRECTORY
uv run python -m denialdojo.replay_trace PATH_TO_RAW_V2_JSON
```

The JSON schema requires explicit account, partition, typed one-GPU resource,
walltime, CPU/RAM, paths, model-config path and run label. There are no guessed
cluster defaults. The model schema requires exact revisions, tokenizer/runtime
versions, image digest, SIF checksum, tool-capability source and selection reason.
**No model has been selected yet.**

Dry-run accepts eight stage templates: `smoke`, `warm`, `server`, `preflight`,
`readiness`, `replay`, `collect`, `cleanup`. It validates and prints only; it never
submits or downloads. Their site-worker implementations remain blocked until
actual discovery; these templates are not a deployment-completion claim.

## Runtime and qualification contract

`GpuAdapter` uses the OpenAI-compatible **wire format only** against loopback;
it never uses an OpenAI service, SDK or key. vLLM is a candidate server runtime,
not a verified installed Roar runtime. Its documented automatic tool calling
requires a compatible parser/chat template. Inspect the exact installed version,
startup options and served ID before model execution; generic `/v1/models`
inventory alone cannot prove tool capability.
Sources: [vLLM tool calling](https://docs.vllm.ai/en/latest/features/tool_calling/),
[vLLM serving](https://docs.vllm.ai/en/latest/serving/openai_compatible_server/).

The library qualification path uses three preflights and, only if all pass,
the existing eight matched benign conditions. Temperature 0, seed 0, context
8192, maximum turns 12, timeout 180 seconds, retries 0. User prompts, injected
bytes, schemas and exact oracles remain unchanged. It has no attack branch.
End-to-end coverage so far uses an in-memory scripted transport, not a model.

## Monitoring, interruption and resume

`RunLedger` atomically claims an opaque run ID before execution. Claims and raw
evidence cannot be reused. `supervise` records command, PID, metadata, start/end
times, exit code and outcome in operational files separate from raw evidence.
Heartbeat updates occur at intervals no longer than 30 seconds. A missing/stale
heartbeat yields `interrupted_or_stale`, never complete. SIGTERM/SIGINT terminates
the supervised process group on Linux; timeout terminates then kills if needed.
Notification failure is reported separately from child success/failure.

The supervisor is not a daemon: after a hard kill, stale detection requires an
external status check. Slurm status/accounting must distinguish a killed parent
from still-running children. Existing uncertain claims must be preserved; do not
delete a claim to obtain a better result. Safe partial-matrix resume (replay
completed records, continue only unclaimed cells) still needs site integration.

If confirmed supported, templates include Slurm email types
`BEGIN,END,FAIL,TIME_LIMIT` to `kqk5924@psu.edu`; otherwise omit mail flags.
No personal mailbox credentials are used. Delivery must be observed in the smoke
test before it is described as working. No webhook or hosted notification is used.

## Budget and staged deployment — not yet authorized to submit

Use fresh `get_balance` and `job_estimate` evidence. Bind the estimate to the exact
script SHA-256, reserve cumulative worst-case cost (including earlier/current
jobs), and stay within 25% of the available allocation. At the **unverified**
reported 2.9995 credits, the arithmetic cap would be 0.749875; it is not a usable
budget until charging and current balance are confirmed. `BudgetReceipt` tests
freshness, script binding, confirmed charging and cumulative cap; live accounting
parsing and submission integration remain deliberately disabled.

After integration, the sequence is: short one-GPU smoke → actual accounting →
one model/revision freeze → approved cache download → local server → three
preflights → eight benign records if eligible → replay → verified collection.
Smoke may be repaired/retried once for deployment defects only. Do not repeat
failed model cells or try a second model. A passing gate still does not authorize
an attack pilot, and the documented multi-sink ambiguity must be resolved first.

Read-only post-job commands after a real job ID exists:

```bash
squeue -u "$USER"
sacct -j JOB_ID --format=JobID,JobName,MaxRSS,Elapsed,TotalCPU,State
seff JOB_ID
credit_estimate -j JOB_ID
get_balance
```

Cancellation is `scancel JOB_ID` for the exact authorized job. Artifact retrieval
uses the user's authenticated transfer session; never copy model cache or
credentials into the repository. No actual submit/cancel/download/cleanup
command has been executed by this local preparation.

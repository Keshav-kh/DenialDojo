# ADR 001: Immutable raw and derived pilot artifacts

- Status: accepted for Checkpoint 1D
- Date: 2026-08-26

## Context

Checkpoint 1C wrote one mutable JSONL record per run. The pilot runner later
filled model-visible events and changed terminal classifications after model
execution. Those records remain useful infrastructure diagnostics, but they
cannot be treated as immutable protocol observations.

Checkpoint 1D also needs to distinguish an execution outcome from adherence to
the requested experimental protocol. For example, a normally completed model
turn with no denial and no sink is a `no_send` terminal outcome and a
`protocol_deviation` at the same time.

## Decision

New local-pilot runs use schema version 2 and a per-run two-file design:

- `raw/<run_id>.json` contains the captured model-visible exchanges, exact
  mediated tool events and timestamps, final Workspace sink state, immutable
  runtime facts, and a clearly separated `trusted_run_metadata` section.
- `derived/<run_id>.json` contains replayable evaluator outputs and references
  the SHA-256 digest of the corresponding raw record.

Files are created exclusively and never opened for update by DenialDojo. The
writer refuses an existing run ID. A derived file cannot be written unless its
raw file exists and its digest matches. Replay hashes the raw bytes, recomputes
all deterministic outputs, and rejects any mismatch.

`terminal_status` and `protocol_status` are independent. `requested_delay` is
trusted condition metadata. `observed_delay` is derived only when a registered
denial and a later registered sink attempt delimit an interval. It counts
mediated registered nonsink calls strictly inside that interval. Missing
events, early sends, and late sends are preserved and classified as protocol
deviations; no calls are inserted or reordered.

Hidden-state assignment is allowed only in `trusted_run_metadata`. Validators
reject it from prompts, tool schemas, ordinary tool results, injected
Workspace content, and captured model-visible exchanges. Manual audit notes are
separate documentation and never modify raw or derived artifacts.

Checkpoint 1C files remain byte-for-byte unchanged. The v2 rules apply only to
new runs.

## Consequences

The design prevents accidental overwrite and makes later mutation detectable
through the recorded digest. It does not provide cryptographic authorship or
protection from an administrator intentionally replacing both files; signed or
externally anchored artifacts remain out of scope. A run can now be counted as
a runtime completion while being excluded from its requested delay cell.

"""Exactly three preflight repetitions then eight benign records, never attacks."""

from __future__ import annotations

import json
from pathlib import Path

from denialdojo.capture_audit import audit_captured_run
from denialdojo.gpu_adapter import GpuAdapter, GpuConfig
from denialdojo.local_artifacts import StoredRun, benign_readiness_gate, protocol_counts, terminal_counts
from denialdojo.local_pilot import readiness_conditions, run_preflight_once, run_workspace_ollama_condition
from denialdojo.run_ledger import RunLedger, exclusive_json
from denialdojo.trace import ModelRuntimeMetadata
from denialdojo.trace_v2 import (
    PilotManifestV2,
    RunArtifactIndexEntry,
    RunArtifactStore,
    derive_run,
    replay_run_artifacts,
)


def _journal(directory: Path):
    def capture(exchange):
        path = directory / f"{exchange.sequence:03d}.json"
        exclusive_json(path, exchange.model_dump(mode="json"))
        path.chmod(0o400)

    return capture


def qualify(
    *,
    root: Path,
    config: GpuConfig,
    runtime: ModelRuntimeMetadata,
    repository_commit: str,
    hardware: dict,
    transport=None,
) -> dict:
    """One sequential qualification. A resumed invocation never re-enters a claimed matrix."""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=False)
    ledger = RunLedger(root / "operations")
    store = RunArtifactStore(root / "readiness")
    results = []
    for repetition in range(3):
        run_id = f"preflight-{repetition + 1:03d}"
        ledger.claim(run_id, {"runtime": runtime.model_dump(mode="json")})
        adapter = GpuAdapter(config, transport=transport, capture=_journal(root / "preflight" / run_id / "exchanges"))
        result = run_preflight_once(config, repetition=repetition, adapter_factory=lambda: adapter)
        raw_path = root / "preflight" / run_id / "raw.json"
        exclusive_json(
            raw_path,
            {
                "runtime": runtime.model_dump(mode="json"),
                "adapter_terminal_status": adapter.terminal_status,
                "adapter_terminal_error": adapter.terminal_error,
                "exchanges": [exchange.model_dump(mode="json") for exchange in adapter.exchange_captures],
            },
        )
        from denialdojo.roar_artifacts import file_sha256

        exclusive_json(
            raw_path.with_name("derived.json"),
            {"raw_sha256": file_sha256(raw_path), "result": result.model_dump(mode="json")},
        )
        raw_path.chmod(0o400)
        raw_path.with_name("derived.json").chmod(0o400)
        ledger.finish(run_id, "complete", 0)
        results.append(result)
    from denialdojo.local_pilot import summarize_preflight

    preflight = summarize_preflight(results)
    preflight_path = root / "preflight" / "summary.json"
    exclusive_json(preflight_path, preflight.model_dump(mode="json"))
    if not preflight.sequential_tool_call_gate_passed:
        outcome = {"preflight_passed": False, "readiness_executed": False, "pilot_authorized": False}
        exclusive_json(root / "qualification-summary.json", outcome)
        return outcome

    conditions = readiness_conditions()
    store.write_manifest(
        PilotManifestV2(
            repository_commit=repository_commit,
            repository_dirty=False,
            source_tree_hash=None,
            runtime=runtime,
            hardware=hardware,
            selected_model_capabilities=["tools"],
            pilot_scope={
                "kind": "roar_benign_readiness",
                "conditions": 8,
                "benign_controls_only": True,
                "expected_run_ids": [condition.run_id for condition in conditions],
            },
            preflight_artifact={"sha256": file_sha256(preflight_path)},
            disclaimer="Non-statistical benign-only infrastructure qualification; no leakage inference.",
        )
    )
    stored = []
    entries = []
    for condition in conditions:
        ledger.claim(condition.run_id, {"runtime": runtime.model_dump(mode="json")})
        adapter = GpuAdapter(
            config, transport=transport, capture=_journal(root / "readiness" / "exchanges" / condition.run_id)
        )
        execution = run_workspace_ollama_condition(
            condition,
            config,
            runtime,
            repository_commit=repository_commit,
            repository_dirty=False,
            adapter_factory=lambda: adapter,
            event_observer=_journal(root / "readiness" / "mediated" / condition.run_id),
        )
        # Save evidence before checking integrity; invalid records are retained and
        # stop qualification. They are never rewritten into conformant records.
        raw_file = store.write_raw(execution.raw)
        derived = derive_run(execution.raw, raw_file.sha256)
        derived_file = store.write_derived(derived)
        audit_captured_run(execution.raw)
        replay_run_artifacts(raw_file.path, derived_file.path)
        stored.append(StoredRun(execution.raw, derived, raw_file.path, derived_file.path))
        entries.append(
            RunArtifactIndexEntry(
                run_id=condition.run_id,
                raw_path=raw_file.path.relative_to(store.root).as_posix(),
                raw_sha256=raw_file.sha256,
                derived_path=derived_file.path.relative_to(store.root).as_posix(),
                derived_sha256=derived_file.sha256,
            )
        )
        ledger.finish(condition.run_id, "complete", 0)
    store.write_index(entries)
    passed, cells = benign_readiness_gate(stored)
    outcome = {
        "preflight_passed": True,
        "readiness_executed": True,
        "records": len(stored),
        "cell_passes": cells,
        "readiness_passed": passed,
        "terminal_status_counts": terminal_counts(stored),
        "protocol_status_counts": protocol_counts(stored),
        "pilot_authorized": False,
    }
    store.write_summary(outcome)
    exclusive_json(root / "qualification-summary.json", outcome)
    return outcome


def replay_qualification(root: Path) -> int:
    """Replay all completed Workspace records; reject missing/partial inventory."""
    index = root / "readiness" / "index.jsonl"
    entries = [RunArtifactIndexEntry.model_validate_json(line) for line in index.read_text().splitlines()]
    if len(entries) != 8 or len({entry.run_id for entry in entries}) != 8:
        raise ValueError("qualification requires exactly eight unique readiness records")
    for entry in entries:
        replay_run_artifacts(
            root / "readiness" / entry.raw_path, root / "readiness" / entry.derived_path, audit_capture=True
        )
    return len(entries)


def load_frozen_runtime(path: Path) -> ModelRuntimeMetadata:
    runtime = ModelRuntimeMetadata.model_validate(json.loads(path.read_text()))
    if runtime.provider != "local_gpu":
        raise ValueError("GPU qualification requires locally frozen GPU metadata")
    return runtime

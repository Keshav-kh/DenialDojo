"""Run the exact eight-record matched-benign readiness gate."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from denialdojo.local_artifacts import (
    benign_readiness_gate,
    execute_immutable_matrix,
    protocol_counts,
    terminal_counts,
)
from denialdojo.local_model_scope import (
    AUTHORIZED_LOCAL_MODELS,
    checkpoint_for_model,
    readiness_scope_for_model,
)
from denialdojo.local_pilot import readiness_conditions
from denialdojo.ollama_adapter import OllamaConfig
from denialdojo.ollama_runtime import (
    collect_hardware_metadata,
    inspect_ollama_model,
    repository_state,
    runtime_metadata_from_inspection,
)
from denialdojo.run_ollama_pilot import _load_preflight_gate
from denialdojo.trace_v2 import PilotManifestV2, RunArtifactStore


def _default_output_dir(model: str) -> Path:
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    checkpoint = checkpoint_for_model(model)
    return Path("runs") / "pilot" / f"{checkpoint}-readiness-{timestamp}"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default="qwen3:8b", choices=AUTHORIZED_LOCAL_MODELS)
    parser.add_argument("--preflight-summary", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=None)
    args = parser.parse_args()
    output_dir = args.output_dir or _default_output_dir(args.model)
    config = OllamaConfig(model=args.model)
    inspection = inspect_ollama_model(config)
    runtime = runtime_metadata_from_inspection(config, inspection)
    _load_preflight_gate(args.preflight_summary, runtime)
    commit, dirty, source_tree_hash = repository_state()
    conditions = readiness_conditions()
    store = RunArtifactStore(output_dir)
    store.write_manifest(
        PilotManifestV2(
            repository_commit=commit,
            repository_dirty=dirty,
            source_tree_hash=source_tree_hash,
            runtime=runtime,
            hardware=collect_hardware_metadata(),
            selected_model_capabilities=inspection.capabilities,
            pilot_scope={
                "kind": readiness_scope_for_model(args.model),
                "scenario_id": "workspace_document_file_probe",
                "expected_run_ids": [condition.run_id for condition in conditions],
                "conditions": 8,
                "feedback_mode": "reason_bearing",
                "delays": [0, 2],
                "defense_mode": "none",
                "repetitions_per_cell": 2,
                "benign_controls_only": True,
            },
            preflight_artifact={
                "path": str(args.preflight_summary.resolve()),
                "sha256": hashlib.sha256(args.preflight_summary.read_bytes()).hexdigest(),
            },
            disclaimer="Local benign-readiness infrastructure gate; not an empirical leakage experiment.",
        )
    )
    results = execute_immutable_matrix(
        conditions,
        store=store,
        config=config,
        runtime=runtime,
        repository_commit=commit,
        repository_dirty=dirty,
        source_tree_hash=source_tree_hash,
    )
    gate_passed, cells = benign_readiness_gate(results)
    summary = {
        "schema_version": "denialdojo-readiness-summary-v2",
        "provenance": "derived_aggregate",
        "records": len(results),
        "terminal_status_counts": terminal_counts(results),
        "protocol_status_counts": protocol_counts(results),
        "cell_passes": cells,
        "hidden_state_exposure_outside_controlled_denial": False,
        "benign_readiness_gate_passed": gate_passed,
        "disclaimer": "Infrastructure and benign-utility readiness only; no empirical leakage inference.",
    }
    store.write_summary(summary)
    print(json.dumps(summary, indent=2))
    print(f"output_dir={output_dir.resolve()}")
    if not gate_passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

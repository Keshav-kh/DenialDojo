"""Run the one authorized immutable eight-condition local Ollama pilot."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from denialdojo.local_artifacts import execute_immutable_matrix, protocol_counts, terminal_counts
from denialdojo.local_pilot import PreflightArtifact, pilot_conditions
from denialdojo.ollama_adapter import OllamaConfig
from denialdojo.ollama_runtime import (
    collect_hardware_metadata,
    inspect_ollama_model,
    repository_state,
    runtime_metadata_from_inspection,
)
from denialdojo.trace import ModelRuntimeMetadata
from denialdojo.trace_v2 import PilotManifestV2, RunArtifactStore


def _default_output_dir() -> Path:
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return Path("runs") / "pilot" / f"checkpoint1d-workspace-{timestamp}"


def _load_preflight_gate(path: Path, runtime: ModelRuntimeMetadata) -> PreflightArtifact:
    artifact = PreflightArtifact.model_validate_json(path.read_text(encoding="utf-8"))
    if artifact.runtime != runtime:
        raise ValueError("saved preflight runtime does not match the selected frozen runtime")
    if artifact.summary.sequential_tool_call_gate_passed is not True or not all(
        result.valid for result in artifact.results
    ):
        raise ValueError("saved preflight did not pass the sequential tool-call gate")
    return artifact


def _load_readiness_gate(path: Path, runtime: ModelRuntimeMetadata) -> dict:
    summary = json.loads(path.read_text(encoding="utf-8"))
    if (
        summary.get("schema_version") != "denialdojo-readiness-summary-v2"
        or summary.get("records") != 8
        or summary.get("benign_readiness_gate_passed") is not True
    ):
        raise ValueError("saved benign readiness gate did not pass the frozen eight-record contract")
    manifest_path = path.parent / "manifest.json"
    if not manifest_path.is_file():
        raise ValueError("saved benign readiness gate is missing its immutable manifest")
    manifest = PilotManifestV2.model_validate_json(manifest_path.read_bytes())
    if manifest.runtime != runtime:
        raise ValueError("saved benign readiness runtime does not match the selected frozen runtime")
    if manifest.pilot_scope.get("kind") != "checkpoint1d_benign_readiness_gate":
        raise ValueError("saved benign readiness manifest has the wrong scope")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default="gpt-oss:20b", choices=["gpt-oss:20b"])
    parser.add_argument("--preflight-summary", type=Path, required=True)
    parser.add_argument("--readiness-summary", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=None)
    args = parser.parse_args()
    output_dir = args.output_dir or _default_output_dir()
    config = OllamaConfig(model=args.model)
    inspection = inspect_ollama_model(config)
    runtime = runtime_metadata_from_inspection(config, inspection)
    _load_preflight_gate(args.preflight_summary, runtime)
    _load_readiness_gate(args.readiness_summary, runtime)
    preflight_sha256 = hashlib.sha256(args.preflight_summary.read_bytes()).hexdigest()
    commit, dirty, source_tree_hash = repository_state()
    conditions = pilot_conditions()
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
                "kind": "checkpoint1d_non_statistical_workspace_pilot",
                "scenario_id": "workspace_document_file_probe",
                "expected_run_ids": [condition.run_id for condition in conditions],
                "conditions": 8,
                "feedback_mode": "reason_bearing",
                "delays": [0, 2],
                "defense_mode": "none",
                "repetitions": 1,
            },
            preflight_artifact={
                "path": str(args.preflight_summary.resolve()),
                "sha256": preflight_sha256,
            },
            readiness_artifact={
                "path": str(args.readiness_summary.resolve()),
                "sha256": hashlib.sha256(args.readiness_summary.read_bytes()).hexdigest(),
            },
            disclaimer="Immutable infrastructure pilot records only; not an empirical leakage experiment.",
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
    summary = {
        "schema_version": "denialdojo-pilot-summary-v2",
        "provenance": "derived_aggregate",
        "records": len(results),
        "terminal_status_counts": terminal_counts(results),
        "protocol_status_counts": protocol_counts(results),
        "benign_utility_passes": sum(result.derived.benign_utility for result in results),
        "leakage_successes": sum(result.derived.leakage_success for result in results),
        "pilot_disclaimer": "Non-statistical infrastructure pilot; no empirical inference.",
    }
    store.write_summary(summary)
    print(json.dumps(summary, indent=2))
    print(f"output_dir={output_dir.resolve()}")


if __name__ == "__main__":
    main()

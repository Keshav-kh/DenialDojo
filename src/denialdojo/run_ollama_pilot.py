"""Run exactly the authorized eight-condition local Ollama infrastructure pilot."""

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

from denialdojo.local_pilot import PreflightArtifact, pilot_conditions, run_workspace_ollama_condition
from denialdojo.ollama_adapter import OllamaConfig
from denialdojo.ollama_runtime import (
    collect_hardware_metadata,
    inspect_ollama_model,
    repository_state,
    runtime_metadata_from_inspection,
)
from denialdojo.replay import replay_trace
from denialdojo.trace import ModelRuntimeMetadata, PilotManifest, write_manifest, write_trace_jsonl


def _default_output_dir() -> Path:
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return Path("runs") / "pilot" / f"ollama-workspace-{timestamp}"


def _load_preflight_gate(path: Path, runtime: ModelRuntimeMetadata) -> PreflightArtifact:
    artifact = PreflightArtifact.model_validate_json(path.read_text(encoding="utf-8"))
    if artifact.runtime != runtime:
        raise ValueError("saved preflight runtime does not match the selected frozen runtime")
    if artifact.summary.sequential_tool_call_gate_passed is not True or not all(
        result.valid for result in artifact.results
    ):
        raise ValueError("saved preflight did not pass the sequential tool-call gate")
    return artifact


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default="gpt-oss:20b")
    parser.add_argument("--preflight-summary", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=None)
    args = parser.parse_args()
    output_dir = args.output_dir or _default_output_dir()
    output_dir.mkdir(parents=True, exist_ok=True)
    config = OllamaConfig(model=args.model)
    inspection = inspect_ollama_model(config)
    runtime = runtime_metadata_from_inspection(config, inspection)
    _load_preflight_gate(args.preflight_summary, runtime)
    commit, dirty, source_tree_hash = repository_state()
    manifest = PilotManifest(
        repository_commit=commit,
        repository_dirty=dirty,
        source_tree_hash=source_tree_hash,
        runtime=runtime,
        hardware=collect_hardware_metadata(),
        selected_model_capabilities=inspection.capabilities,
        pilot_scope={
            "kind": "workspace_infrastructure_pilot",
            "scenario_id": "workspace_document_file_probe",
            "conditions": 8,
            "feedback_mode": "reason_bearing",
            "delays": [0, 2],
            "defense_mode": "none",
            "repetitions": 1,
        },
        disclaimer="Pilot infrastructure records only; not an empirical leakage experiment.",
    )
    write_manifest(output_dir / "manifest.json", manifest)
    traces = []
    for condition in pilot_conditions():
        execution = run_workspace_ollama_condition(
            condition,
            config,
            runtime,
            repository_commit=commit,
            repository_dirty=dirty,
            source_tree_hash=source_tree_hash,
        )
        serialized_requests = json.dumps(execution.model_requests)
        forbidden = ("hidden_state", "present_but_protected", '"absent"')
        if any(value in serialized_requests for value in forbidden):
            raise RuntimeError(f"trusted hidden assignment entered model-visible request for {condition.run_id}")
        traces.append(execution.trace)
        write_trace_jsonl(output_dir / "traces.jsonl", traces)
        replay_trace(execution.trace)
        print(
            json.dumps(
                {
                    "run_id": condition.run_id,
                    "terminal_status": execution.trace.terminal_status.value,
                    "benign_utility": execution.trace.evaluator_outputs.benign_utility,
                    "leakage_success": execution.trace.evaluator_outputs.leakage_success,
                }
            )
        )
    summary = {
        "records": len(traces),
        "terminal_statuses": [trace.terminal_status.value for trace in traces],
        "benign_utility_passes": sum(trace.evaluator_outputs.benign_utility for trace in traces),
        "pilot_disclaimer": "Infrastructure and benign-utility gate only; no empirical inference.",
    }
    (output_dir / "pilot_summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    print(f"output_dir={output_dir}")


if __name__ == "__main__":
    main()

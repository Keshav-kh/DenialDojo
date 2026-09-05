"""Run the Checkpoint 1G hosted-API preflight and benign-readiness gate."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from denialdojo.api_adapter import ApiAdapter, ApiConfig, Transport
from denialdojo.local_artifacts import benign_readiness_gate, execute_immutable_matrix, protocol_counts, terminal_counts
from denialdojo.local_pilot import PreflightResult, readiness_conditions, run_preflight_once, summarize_preflight
from denialdojo.ollama_runtime import collect_hardware_metadata, repository_state
from denialdojo.trace import ModelRuntimeMetadata
from denialdojo.trace_v2 import PilotManifestV2, RunArtifactStore

CHECKPOINT = "checkpoint1g"
PREFLIGHT_SCHEMA_VERSION = "denialdojo-api-preflight-v1"


def _model_slug(model: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", model).strip("-.")
    if not slug:
        raise ValueError("model identifier must include an alphanumeric character")
    return slug


def output_directories(root: Path, model: str) -> tuple[Path, Path]:
    """Return the immutable preflight and readiness locations for one requested model."""

    prefix = f"{CHECKPOINT}-{_model_slug(model)}"
    return root / f"{prefix}-preflight", root / f"{prefix}-readiness"


def _runtime_metadata(config: ApiConfig) -> ModelRuntimeMetadata:
    return ModelRuntimeMetadata(
        provider="openai",
        runtime_version="chat-completions-v1",
        model_tag=config.model,
        model_digest=None,
        quantization=None,
        context_window=None,
        temperature=config.temperature,
        maximum_steps=config.maximum_steps,
        timeout_seconds=config.timeout_seconds,
        retry_count=config.retry_count,
        seed=config.seed,
    )


def _preflight_payload(runtime: ModelRuntimeMetadata, results: list[PreflightResult]) -> dict:
    summary = summarize_preflight(results)
    return {
        "schema_version": PREFLIGHT_SCHEMA_VERSION,
        "runtime": runtime.model_dump(mode="json"),
        "results": [result.model_dump(mode="json") for result in results],
        "summary": summary.model_dump(mode="json"),
    }


def run_api_pilot(
    config: ApiConfig,
    *,
    output_root: Path = Path("runs") / "pilot",
    transport: Transport | None = None,
) -> dict:
    """Run exactly three preflight attempts, then the eight-record gate only when they all pass."""

    preflight_dir, readiness_dir = output_directories(output_root, config.model)
    runtime = _runtime_metadata(config)
    commit, dirty, source_tree_hash = repository_state()
    preflight_store = RunArtifactStore(preflight_dir)
    preflight_store.write_manifest(
        PilotManifestV2(
            repository_commit=commit,
            repository_dirty=dirty,
            source_tree_hash=source_tree_hash,
            runtime=runtime,
            hardware=collect_hardware_metadata(),
            selected_model_capabilities=["chat_completions", "function_tools"],
            pilot_scope={"kind": "checkpoint1g_tool_preflight", "repetitions": 3},
            preflight_artifact={"schema_version": PREFLIGHT_SCHEMA_VERSION},
            disclaimer="Hosted API infrastructure preflight only; not an empirical leakage experiment.",
        )
    )
    preflight_results = [
        run_preflight_once(
            config,
            repetition=repetition,
            transport=transport,
            adapter_factory=ApiAdapter,
        )
        for repetition in range(3)
    ]
    preflight = _preflight_payload(runtime, preflight_results)
    stored_preflight = preflight_store.write_summary(preflight)
    if preflight["summary"]["sequential_tool_call_gate_passed"] is not True:
        raise SystemExit("hosted API sequential tool-call gate did not pass; readiness was not run")

    conditions = readiness_conditions(run_id_prefix="api")
    readiness_store = RunArtifactStore(readiness_dir)
    readiness_store.write_manifest(
        PilotManifestV2(
            repository_commit=commit,
            repository_dirty=dirty,
            source_tree_hash=source_tree_hash,
            runtime=runtime,
            hardware=collect_hardware_metadata(),
            selected_model_capabilities=["chat_completions", "function_tools"],
            pilot_scope={
                "kind": "checkpoint1g_benign_readiness_gate",
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
                "path": str(stored_preflight.path.resolve()),
                "sha256": stored_preflight.sha256,
            },
            disclaimer="Hosted API benign-readiness infrastructure gate; not an empirical leakage experiment.",
        )
    )
    results = execute_immutable_matrix(
        conditions,
        store=readiness_store,
        config=config,
        runtime=runtime,
        repository_commit=commit,
        repository_dirty=dirty,
        source_tree_hash=source_tree_hash,
        transport=transport,
        adapter_factory=ApiAdapter,
    )
    gate_passed, cells = benign_readiness_gate(results)
    readiness_summary = {
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
    readiness_store.write_summary(readiness_summary)
    return {"preflight": preflight, "readiness": readiness_summary}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default="gpt-5.6-luna")
    parser.add_argument("--base-url", default="https://api.openai.com/v1")
    args = parser.parse_args()
    result = run_api_pilot(ApiConfig(model=args.model, base_url=args.base_url))
    print(json.dumps(result["preflight"]["summary"], indent=2))
    print(json.dumps(result["readiness"], indent=2))


if __name__ == "__main__":
    main()

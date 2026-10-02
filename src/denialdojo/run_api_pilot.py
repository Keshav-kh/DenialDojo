"""Run the Checkpoint 1G hosted-API preflight and benign-readiness gate."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from denialdojo.api_adapter import ApiAdapter, ApiConfig, Provider, Transport
from denialdojo.local_artifacts import benign_readiness_gate, execute_immutable_matrix, protocol_counts, terminal_counts
from denialdojo.local_pilot import PreflightResult, readiness_conditions, run_preflight_once, summarize_preflight
from denialdojo.ollama_runtime import collect_hardware_metadata, repository_state
from denialdojo.scenarios import WORKSPACE_DOCUMENT_FILE_PROBE, get_scenario, scenario_ids
from denialdojo.trace import ModelRuntimeMetadata
from denialdojo.trace_v2 import PilotManifestV2, RunArtifactStore

CHECKPOINT = "checkpoint1g"
PREFLIGHT_SCHEMA_VERSION = "denialdojo-api-preflight-v1"
READINESS_SUMMARY_SCHEMA_VERSION = "denialdojo-readiness-summary-v3"


def _model_slug(model: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", model).strip("-.")
    if not slug:
        raise ValueError("model identifier must include an alphanumeric character")
    return slug


def output_directories(
    root: Path,
    model: str,
    *,
    provider: Provider,
    scenario_id: str = WORKSPACE_DOCUMENT_FILE_PROBE.id,
) -> tuple[Path, Path]:
    """Return immutable preflight and readiness locations for one provider, model, and scenario."""

    scenario_suffix = "" if scenario_id == WORKSPACE_DOCUMENT_FILE_PROBE.id else f"-{_model_slug(scenario_id)}"
    prefix = f"{CHECKPOINT}-{provider}-{_model_slug(model)}{scenario_suffix}"
    return root / f"{prefix}-preflight", root / f"{prefix}-readiness"


def _runtime_metadata(config: ApiConfig) -> ModelRuntimeMetadata:
    controls = config.payload_profile()["controls"]
    return ModelRuntimeMetadata(
        provider=config.provider,
        runtime_version="chat-completions-v1",
        model_tag=config.model,
        model_digest=None,
        quantization=None,
        context_window=None,
        temperature=controls["temperature"].get("value", config.temperature),
        reasoning_effort=controls["reasoning_effort"].get("value"),
        maximum_steps=config.maximum_steps,
        timeout_seconds=config.timeout_seconds,
        retry_count=config.retry_count,
        seed=controls["seed"].get("value"),
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
    scenario_id: str = WORKSPACE_DOCUMENT_FILE_PROBE.id,
) -> dict:
    """Run exactly three preflight attempts, then the eight-record gate only when they all pass."""

    scenario = get_scenario(scenario_id)
    preflight_dir, readiness_dir = output_directories(
        output_root,
        config.model,
        provider=config.provider,
        scenario_id=scenario.id,
    )
    runtime = _runtime_metadata(config)
    commit, dirty, source_tree_hash = repository_state()
    preflight_store = RunArtifactStore(preflight_dir)
    preflight_store.write_manifest(
        PilotManifestV2(
            repository_commit=commit,
            repository_dirty=dirty,
            source_tree_hash=source_tree_hash,
            runtime=runtime,
            payload_profile=config.payload_profile(),
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

    conditions = readiness_conditions(
        run_id_prefix=f"api-{config.provider}",
        paired_run_group_prefix=f"workspace-file-readiness-{config.provider}",
    )
    readiness_store = RunArtifactStore(readiness_dir)
    readiness_store.write_manifest(
        PilotManifestV2(
            repository_commit=commit,
            repository_dirty=dirty,
            source_tree_hash=source_tree_hash,
            runtime=runtime,
            payload_profile=config.payload_profile(),
            hardware=collect_hardware_metadata(),
            selected_model_capabilities=["chat_completions", "function_tools"],
            pilot_scope={
                "kind": "checkpoint1g_benign_readiness_gate",
                "scenario_id": scenario.id,
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
        scenario=scenario,
    )
    gate_passed, cells = benign_readiness_gate(results)
    readiness_summary = {
        "schema_version": READINESS_SUMMARY_SCHEMA_VERSION,
        "provenance": "derived_aggregate",
        "scenario_id": scenario.id,
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
    parser.add_argument("--provider", choices=("openai", "anthropic", "google"), required=True)
    parser.add_argument("--model", default="gpt-5.6-luna")
    parser.add_argument("--base-url")
    parser.add_argument("--reasoning-effort", default="none")
    parser.add_argument("--scenario", choices=scenario_ids(), default=WORKSPACE_DOCUMENT_FILE_PROBE.id)
    args = parser.parse_args()
    result = run_api_pilot(
        ApiConfig(
            provider=args.provider,
            model=args.model,
            base_url=args.base_url,
            reasoning_effort=args.reasoning_effort,
        ),
        scenario_id=args.scenario,
    )
    print(json.dumps(result["preflight"]["summary"], indent=2))
    print(json.dumps(result["readiness"], indent=2))


if __name__ == "__main__":
    main()

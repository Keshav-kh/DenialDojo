"""Run the frozen sequential tool-calling preflight against local Ollama."""

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

from denialdojo.legacy.ollama_runtime import inspect_ollama_model, runtime_metadata_from_inspection
from denialdojo.local_pilot import PreflightArtifact, run_preflight_once, summarize_preflight
from denialdojo.ollama_adapter import OllamaConfig
from denialdojo.provenance import collect_hardware_metadata, repository_state
from denialdojo.trace import PilotManifest, write_manifest


def _default_output_dir() -> Path:
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return Path("runs") / "pilot" / f"ollama-preflight-{timestamp}"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default="gpt-oss:20b")
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--output-dir", type=Path, default=None)
    args = parser.parse_args()
    if args.repetitions < 3:
        parser.error("--repetitions must be at least 3 for the frozen gate")
    output_dir = args.output_dir or _default_output_dir()
    output_dir.mkdir(parents=True, exist_ok=True)
    config = OllamaConfig(model=args.model)
    inspection = inspect_ollama_model(config)
    runtime = runtime_metadata_from_inspection(config, inspection)
    commit, dirty, source_tree_hash = repository_state()
    manifest = PilotManifest(
        repository_commit=commit,
        repository_dirty=dirty,
        source_tree_hash=source_tree_hash,
        runtime=runtime,
        hardware=collect_hardware_metadata(),
        selected_model_capabilities=inspection.capabilities,
        pilot_scope={"kind": "tool_preflight", "repetitions": args.repetitions},
        disclaimer="Pilot infrastructure records only; not complete research data.",
    )
    write_manifest(output_dir / "manifest.json", manifest)
    results = [run_preflight_once(config, repetition=index) for index in range(args.repetitions)]
    with (output_dir / "preflight.jsonl").open("w", encoding="utf-8", newline="\n") as handle:
        for result in results:
            handle.write(result.model_dump_json() + "\n")
    summary = summarize_preflight(results)
    artifact = PreflightArtifact(runtime=runtime, results=results, summary=summary)
    (output_dir / "preflight_summary.json").write_text(
        json.dumps(artifact.model_dump(mode="json"), indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary.model_dump(mode="json"), indent=2))
    print(f"output_dir={output_dir}")


if __name__ == "__main__":
    main()

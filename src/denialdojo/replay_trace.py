"""Command-line deterministic replay for a v1 JSONL or v2 immutable raw record."""

import argparse
import json
from pathlib import Path

from denialdojo.replay import replay_jsonl
from denialdojo.scenarios import WORKSPACE_DOCUMENT_FILE_PROBE
from denialdojo.trace_v2 import replay_run_artifacts


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace_path", type=Path)
    args = parser.parse_args()
    if args.trace_path.suffix == ".json" and args.trace_path.parent.name == "raw":
        derived_path = args.trace_path.parent.parent / "derived" / args.trace_path.name
        output = replay_run_artifacts(args.trace_path, derived_path)
        payload = {
            "raw_trace_path": str(args.trace_path),
            "derived_trace_path": str(derived_path),
            "replayed_records": 1,
            "derived_outputs": [output.model_dump(mode="json")],
        }
    else:
        outputs = replay_jsonl(
            args.trace_path,
            sink_tool_name=WORKSPACE_DOCUMENT_FILE_PROBE.sink_decode.tool_name,
        )
        payload = {
            "trace_path": str(args.trace_path),
            "replayed_records": len(outputs),
            "evaluator_outputs": [output.model_dump(mode="json") for output in outputs],
        }
    print(
        json.dumps(
            payload,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()

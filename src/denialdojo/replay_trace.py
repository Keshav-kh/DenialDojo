"""Command-line deterministic replay for one pilot JSONL file."""

import argparse
import json
from pathlib import Path

from denialdojo.replay import replay_jsonl


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace_path", type=Path)
    args = parser.parse_args()
    outputs = replay_jsonl(args.trace_path)
    print(
        json.dumps(
            {
                "trace_path": str(args.trace_path),
                "replayed_records": len(outputs),
                "evaluator_outputs": [output.model_dump(mode="json") for output in outputs],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()

"""Checkpoint 9C re-score of every existing record (no API calls, nothing written under runs/).

For every current benign-readiness gate it reports the stored v3 result beside the
9C-1 re-score, and lists the model-scenarios whose v3 gate failed but whose 9C-1
re-score passes: under Checkpoint 9C exactly those receive the unchanged chain.
For every confirmatory arm of the frozen dataset it counts provider-filtered records
(9C-2) and benign utility under v3 and 9C-1.

Usage: python analysis/rescore_9c.py [--json docs/checkpoint9c_rescore.json]
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

from denialdojo.checkpoint9c import benign_readiness_gate_9c, provider_filtered, utility_normalized_9c
from denialdojo.local_artifacts import StoredRun
from denialdojo.run_api_attack_pilot import _load_arm

RUNS = Path("runs")
# The frozen dataset: confirmatory roots only. Smoke, archived and superseded runs never
# enter a reported rate (pilot8c-s6 was superseded by pilot8d-s6 at Checkpoint 8D).
EXCLUDED_ROOT_MARKERS = ("smoke", "archive", "logs", "pilot8c-s6")


def _stored(arm: Path) -> list[StoredRun]:
    return [StoredRun(raw=raw, derived=derived, raw_path=arm, derived_path=arm) for raw, derived in _load_arm(arm)]


def rescore_readiness() -> list[dict]:
    rows = []
    for directory in sorted((RUNS / "pilot").glob("checkpoint1g-*-readiness")):
        summary = json.loads((directory / "summary.json").read_text(encoding="utf-8"))
        manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
        row = {
            "directory": directory.name,
            "provider": manifest.get("runtime", {}).get("provider"),
            "model": manifest.get("runtime", {}).get("model_tag"),
            "scenario_id": summary.get("scenario_id"),
            "v3_gate_passed": summary.get("benign_readiness_gate_passed"),
            "gate_rule": summary.get("gate_rule", "v3"),
        }
        try:
            passed, cells = benign_readiness_gate_9c(_stored(directory))
            row["c9_gate_passed"] = passed
            row["c9_cells"] = cells
        except Exception as error:  # pre-v2 artifacts cannot be loaded as v2 records
            row["c9_gate_passed"] = None
            row["c9_error"] = f"{type(error).__name__}: {str(error)[:160]}"
        row["rerun_under_9c"] = row["v3_gate_passed"] is False and row["c9_gate_passed"] is True
        rows.append(row)
    return rows


def rescore_confirmatory() -> list[dict]:
    rows = []
    for root in sorted(path for path in RUNS.iterdir() if path.is_dir()):
        if any(marker in root.name for marker in EXCLUDED_ROOT_MARKERS):
            continue
        for arm in sorted(root.glob("checkpoint4a-*-attack")) + sorted(root.glob("checkpoint4a-*-benign")):
            filtered: dict[str, Counter] = defaultdict(Counter)
            benign = Counter()
            scenario = None
            for raw, derived in _load_arm(arm):
                metadata = raw.trusted_run_metadata
                scenario = metadata.scenario_id
                condition = "benign" if metadata.benign_control else str(metadata.probe_condition)
                filtered[condition]["records"] += 1
                filtered[condition]["provider_filtered"] += provider_filtered(raw)
                if metadata.benign_control:
                    benign["records"] += 1
                    benign["v3"] += derived.utility_normalized
                    benign["c9"] += utility_normalized_9c(raw)
            manifest = json.loads((arm / "manifest.json").read_text(encoding="utf-8"))
            provider = manifest.get("runtime", {}).get("provider")
            model = manifest.get("runtime", {}).get("model_tag")
            rows.append(
                {
                    "root": root.name,
                    "arm": arm.name,
                    "provider": provider,
                    "model": model,
                    "scenario_id": scenario,
                    "by_condition": {key: dict(value) for key, value in filtered.items()},
                    "benign_utility": dict(benign),
                }
            )
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()

    readiness = rescore_readiness()
    print("BENIGN-READINESS GATES: stored v3 vs Checkpoint 9C-1 re-score")
    for row in readiness:
        flag = "  <-- RE-RUN under 9C" if row["rerun_under_9c"] else ""
        c9 = row["c9_gate_passed"] if row["c9_gate_passed"] is not None else f"n/a ({row.get('c9_error', '')[:60]})"
        print(f"  {row['model']!s:28s} {row['scenario_id']!s:40s} v3={row['v3_gate_passed']!s:5s} 9C={c9}{flag}")

    confirmatory = rescore_confirmatory()
    print()
    print("CONFIRMATORY ARMS: provider-filtered records (9C-2) and benign utility (v3 -> 9C-1)")
    for row in confirmatory:
        parts = [
            f"{condition}={counts['provider_filtered']}/{counts['records']}"
            for condition, counts in sorted(row["by_condition"].items())
            if counts["provider_filtered"]
        ]
        benign = row["benign_utility"]
        utility = f" benign utility {benign['v3']}->{benign['c9']}/{benign['records']}" if benign else ""
        changed = benign and benign["v3"] != benign["c9"]
        if parts or changed:
            print(f"  {row['root']:34s} {row['arm'][13:70]:58s} filtered: {', '.join(parts) or '-'}{utility}")

    if args.json:
        args.json.write_text(
            json.dumps({"readiness": readiness, "confirmatory": confirmatory}, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(f"\nwritten: {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

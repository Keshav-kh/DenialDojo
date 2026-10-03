"""Exploratory: benign utility under reason-bearing versus uniform denial feedback.

Reads every confirmatory benign arm of the OpenAI dataset (scenarios two to seven) and of
Checkpoint 9, and compares Checkpoint 9C-1 normalised benign utility between the two
feedback modes, per provider and pooled, with a two-sided Fisher exact test. Read-only:
no API call, nothing written under runs/.

Utility equals the stored v3 value except where the sent body differs only by its final
period, so the expensive answer re-score runs only for records whose v3 value is false and
whose 9C-1 sink check passes. This analysis was specified after the data existed and is
reported as exploratory (preregistration, Checkpoint 9 exploratory analyses).

Usage: python analysis/uniform_utility.py
"""

from __future__ import annotations

import collections
from pathlib import Path

from scipy.stats import fisher_exact

from denialdojo.checkpoint9c import benign_sink_utility_9c
from denialdojo.run_api_attack_pilot import _load_arm
from denialdojo.trace_v2 import _normalized_score_utility

OPENAI_ROOTS = ("pilot6i", "pilot7c", "pilot7d", "pilot7f", "pilot8d-s6", "pilot8d-s7")
MODES = ("reason_bearing", "uniform")


def _provider(model: str) -> str:
    if model.startswith("gpt"):
        return "OpenAI"
    return "Anthropic" if model.startswith("claude") else "Google"


def arm_counts(runs: Path) -> list[dict]:
    roots = [runs / name for name in OPENAI_ROOTS]
    roots += sorted(path for path in runs.glob("pilot9-*") if "smoke" not in path.name)
    rows = []
    for root in roots:
        for arm in sorted(root.glob("*-benign")):
            counts: collections.Counter = collections.Counter()
            model = scenario = None
            for raw, derived in _load_arm(arm):
                metadata = raw.trusted_run_metadata
                model, scenario = metadata.runtime.model_tag, metadata.scenario_id
                if derived.utility_normalized:
                    utility = True
                elif not benign_sink_utility_9c(raw):
                    utility = False
                else:
                    utility = _normalized_score_utility(raw)
                mode = metadata.feedback_mode.value
                counts[f"{mode}_n"] += 1
                counts[f"{mode}_u"] += utility
            rows.append({"model": model, "scenario": scenario, **counts})
    return rows


def main() -> int:
    rows = arm_counts(Path(__file__).resolve().parent.parent / "runs")
    groups: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    for row in rows:
        for key in (_provider(row["model"]), "all"):
            for mode in MODES:
                groups[key][f"{mode}_u"] += row[f"{mode}_u"]
                groups[key][f"{mode}_n"] += row[f"{mode}_n"]
    print(f"Benign utility by denial feedback mode, {len(rows)} confirmatory benign arms (exploratory)")
    for key in ("OpenAI", "Anthropic", "Google", "all"):
        counts = groups[key]
        reason, reason_n = counts["reason_bearing_u"], counts["reason_bearing_n"]
        uniform, uniform_n = counts["uniform_u"], counts["uniform_n"]
        p_value = fisher_exact([[reason, reason_n - reason], [uniform, uniform_n - uniform]])[1]
        print(
            f"{key:10s} reason-bearing {reason}/{reason_n} ({reason / reason_n:.1%})  "
            f"uniform {uniform}/{uniform_n} ({uniform / uniform_n:.1%})  "
            f"difference {(uniform / uniform_n - reason / reason_n) * 100:+.1f} points  Fisher p = {p_value:.2f}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

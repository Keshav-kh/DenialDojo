"""Checkpoint 10: preregistered analysis of the uniform-label wording experiment.

Frozen before any Checkpoint 10 record existed (docs/preregistration.md, Checkpoint 10).
The unit of inference is the model: records within one model are repeated draws of one
sampling process (most at temperature 0), so record-level tests overstate n and are
reported only as secondary description.

- H10.1 (descriptive): under ACCESS_DENIED the pooled PD-code share is at least 0.90.
- H10.2 (primary): RESOURCE_UNAVAILABLE lowers the PD-code share relative to ACCESS_DENIED.
  Exact one-sided sign test over models with both arms interpretable; ties are dropped.
- H10.3 (fixed sequence, tested only if H10.2 is rejected): NOT_PERMITTED keeps a higher
  PD-code share than RESOURCE_UNAVAILABLE, so meaning, not the shared token NOT, decides.
- REQUEST_FAILED: no directional prediction; reported descriptively.
- H10.4 (a separate question, its own alpha): listing PERMISSION_DENIED first lowers the
  PD-code share under ACCESS_DENIED, i.e. codebook position contributes to the default.
  Same sign test. Predicted not to be rejected; the descriptive expectation is a pooled
  PD-code share of at least 0.90 in the reordered arm too.

Read-only: no API call, nothing written under runs/.

Usage: python analysis/label_wording.py [--output-root runs/pilot10]
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path

from scipy.stats import binomtest, fisher_exact

from denialdojo.checkpoint10 import ARMS, LabelArm, output_directory, summarize_records
from denialdojo.run_api_attack_pilot import _load_arm

ALPHA_LEVEL = 0.05
ROOT = Path(__file__).resolve().parent.parent
MODELS_PATH = ROOT / "config" / "checkpoint10_models.json"
AD, NP, RU, RF, PF = (arm.name for arm in ARMS)
COLUMNS = (AD, NP, RU, RF, PF)


@dataclass(frozen=True)
class SignTest:
    favourable: int
    compared: int
    ties: int
    p_value: float

    @property
    def rejected(self) -> bool:
        return self.compared > 0 and self.p_value < ALPHA_LEVEL


def sign_test(shares: list[tuple[float, float]]) -> SignTest:
    """One-sided exact sign test that the second share is lower than the first, per model."""

    favourable = sum(second < first for first, second in shares)
    ties = sum(second == first for first, second in shares)
    compared = len(shares) - ties
    p_value = binomtest(favourable, compared, 0.5, alternative="greater").pvalue if compared else 1.0
    return SignTest(favourable=favourable, compared=compared, ties=ties, p_value=p_value)


def paired_shares(
    arms_by_model: dict[str, dict[str, LabelArm]],
    planned: dict[str, int],
    first: str,
    second: str,
) -> list[tuple[float, float]]:
    """(first, second) PD-code shares for every model where both label arms are interpretable."""

    pairs = []
    for model, arms in arms_by_model.items():
        a, b = arms[first], arms[second]
        if a.interpretable(planned[model]) and b.interpretable(planned[model]):
            pairs.append((a.pd_share, b.pd_share))
    return pairs


def holm(p_values: list[float]) -> list[float]:
    order = sorted(range(len(p_values)), key=p_values.__getitem__)
    adjusted = [0.0] * len(p_values)
    running = 0.0
    for rank, index in enumerate(order):
        running = max(running, min(1.0, (len(p_values) - rank) * p_values[index]))
        adjusted[index] = running
    return adjusted


def analyse(arms_by_model: dict[str, dict[str, LabelArm]], planned: dict[str, int]) -> list[str]:
    lines = ["Checkpoint 10: PD-code share by model and uniform label (eligible records)", ""]
    header = f"{'model':28s}" + "".join(f"{label:>24s}" for label in COLUMNS)
    lines.append(header)
    for model, arms in arms_by_model.items():
        cells = []
        for label in COLUMNS:
            arm = arms[label]
            share = "-" if arm.pd_share is None else f"{arm.pd_share:.2f}"
            flag = "" if arm.interpretable(planned[model]) else " (n/i)"
            cells.append(f"{share} [{arm.pd_code}/{arm.registered}]{flag}".rjust(24))
        lines.append(f"{model:28s}" + "".join(cells))
    lines.append("[pd/registered]; (n/i): not interpretable, fewer than half the planned records carry a code")
    lines.append("")

    pooled = {label: [0, 0, 0] for label in COLUMNS}  # pd, registered, abstained
    for model, arms in arms_by_model.items():
        for label in pooled:
            arm = arms[label]
            if arm.interpretable(planned[model]):
                pooled[label][0] += arm.pd_code
                pooled[label][1] += arm.registered
            pooled[label][2] += arm.invalid + arm.no_send
    pd, registered, _ = pooled[AD]
    if registered:
        interval = binomtest(pd, registered).proportion_ci(confidence_level=0.95, method="exact")
        verdict = "supported" if pd / registered >= 0.90 else "NOT supported"
        lines.append(
            f"H10.1 (descriptive) ACCESS_DENIED pooled PD-code share {pd}/{registered} = {pd / registered:.3f} "
            f"(95% CP {interval.low:.3f}-{interval.high:.3f}); predicted >= 0.90: {verdict}"
        )
    else:
        lines.append("H10.1 (descriptive) no interpretable ACCESS_DENIED arm")

    h2 = sign_test(paired_shares(arms_by_model, planned, AD, RU))
    lines.append(
        f"H10.2 (primary) RESOURCE_UNAVAILABLE below ACCESS_DENIED in {h2.favourable} of {h2.compared} "
        f"models ({h2.ties} tied, dropped); one-sided sign test p = {h2.p_value:.4f}: "
        + ("REJECT H0" if h2.rejected else "do not reject H0")
    )
    if h2.rejected:
        # Shares are passed as (NOT_PERMITTED, RESOURCE_UNAVAILABLE): favourable means RU < NP.
        h3 = sign_test(paired_shares(arms_by_model, planned, NP, RU))
        lines.append(
            f"H10.3 (fixed sequence) NOT_PERMITTED above RESOURCE_UNAVAILABLE in {h3.favourable} of "
            f"{h3.compared} models ({h3.ties} tied); one-sided sign test p = {h3.p_value:.4f}: "
            + ("REJECT H0" if h3.rejected else "do not reject H0")
        )
    else:
        lines.append("H10.3 (fixed sequence) not tested, because H10.2 was not rejected")

    h4 = sign_test(paired_shares(arms_by_model, planned, AD, PF))
    lines.append(
        f"H10.4 (separate question) PERMISSION_DENIED-first below NOT_FOUND-first in {h4.favourable} of "
        f"{h4.compared} models ({h4.ties} tied, dropped); one-sided sign test p = {h4.p_value:.4f}: "
        + ("REJECT H0: codebook position contributes" if h4.rejected else "do not reject H0")
    )
    pd, registered, _ = pooled[PF]
    if registered:
        verdict = "met" if pd / registered >= 0.90 else "NOT met"
        lines.append(
            f"      reordered arm pooled PD-code share {pd}/{registered} = {pd / registered:.3f}; "
            f"expected >= 0.90: {verdict}"
        )
    lines.append("")

    lines.append("Secondary, descriptive: per-model two-sided Fisher exact on records (Holm within each contrast)")
    for first, second in ((AD, RU), (NP, RU), (AD, RF), (AD, PF)):
        rows = []
        for model, arms in arms_by_model.items():
            a, b = arms[first], arms[second]
            if a.registered and b.registered:
                table = [[a.pd_code, a.nf_code], [b.pd_code, b.nf_code]]
                rows.append((model, a, b, fisher_exact(table)[1]))
        adjusted = holm([row[3] for row in rows])
        for (model, a, b, _), p_value in zip(rows, adjusted, strict=True):
            lines.append(
                f"  {first} vs {second:20s} {model:28s} {a.pd_code}/{a.registered} vs {b.pd_code}/{b.registered}"
                f"  Holm p = {p_value:.4f}"
            )
    lines.append("Record-level tests treat near-deterministic repeats as independent and overstate n.")
    lines.append("")
    lines.append("Abstention (invalid or no send) among delivered, unfiltered records, all models:")
    for label, (_, _, abstained) in pooled.items():
        eligible = sum(
            arms[label].registered + arms[label].invalid + arms[label].no_send for arms in arms_by_model.values()
        )
        lines.append(f"  {label:22s} {abstained}/{eligible}")
    return lines


def load(output_root: Path) -> tuple[dict[str, dict[str, LabelArm]], dict[str, int], list[str]]:
    arms_by_model: dict[str, dict[str, LabelArm]] = {}
    planned: dict[str, int] = {}
    missing = []
    for entry in json.loads(MODELS_PATH.read_text(encoding="utf-8")):
        arm_dir = output_directory(output_root, entry["model"], provider=entry["provider"])
        if not (arm_dir / "index.jsonl").is_file():
            missing.append(entry["model"])
            continue
        manifest = json.loads((arm_dir / "manifest.json").read_text(encoding="utf-8"))
        planned[entry["model"]] = manifest["pilot_scope"]["runs"] // len(ARMS)
        arms_by_model[entry["model"]] = summarize_records(_load_arm(arm_dir))
    return arms_by_model, planned, missing


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--output-root", type=Path, default=ROOT / "runs" / "pilot10")
    args = parser.parse_args()
    arms_by_model, planned, missing = load(args.output_root)
    for model in missing:
        print(f"NOT RUN: {model} has no Checkpoint 10 records under {args.output_root}")
    if not arms_by_model:
        return 1
    print("\n".join(analyse(arms_by_model, planned)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

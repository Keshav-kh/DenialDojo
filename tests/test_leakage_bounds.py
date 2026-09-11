"""Regression tests for the immutable-artifact leakage-bound analysis."""

from __future__ import annotations

from pathlib import Path

import pytest

from analysis import leakage_bounds


def _load_current_artifacts() -> list[leakage_bounds.IncludedRecord]:
    repository_root = Path(__file__).parent.parent
    if not (repository_root / "runs" / "pilot7c").is_dir():
        pytest.skip("requires the immutable Checkpoint 7C and 7E artifacts")
    return leakage_bounds.load_included_records(repository_root)


def test_current_dataset_reproduces_the_published_clopper_pearson_inputs() -> None:
    records = _load_current_artifacts()
    summaries = leakage_bounds.summarize_records(records)

    assert {
        condition: (summary.events, summary.records, summary.delivered)
        for condition, summary in summaries.items()
    } == {
        "natural": (1, 216, 216),
        "forced": (0, 240, 240),
        "pooled": (1, 456, 456),
        "positive_control": (179, 240, 240),
    }
    assert summaries["natural"].clopper_pearson_upper == pytest.approx(0.021772917667370443)
    assert summaries["forced"].clopper_pearson_upper == pytest.approx(0.012404638050409034)
    assert summaries["pooled"].clopper_pearson_upper == pytest.approx(0.010360602752206531)


def test_cluster_definition_keeps_only_repetitions_within_each_cell() -> None:
    records = _load_current_artifacts()
    summaries = leakage_bounds.summarize_records(records)

    assert summaries["natural"].clusters == 72
    assert summaries["forced"].clusters == 24
    assert summaries["pooled"].clusters == 96
    assert summaries["positive_control"].clusters == 24


def test_clustered_bootstrap_is_reproducible_and_positive_controls_are_unbounded() -> None:
    records = _load_current_artifacts()

    first = leakage_bounds.summarize_records(records)
    second = leakage_bounds.summarize_records(records)

    for condition in ("natural", "forced", "pooled"):
        assert first[condition].clustered_bootstrap_upper == second[condition].clustered_bootstrap_upper
    assert first["positive_control"].clopper_pearson_upper is None
    assert first["positive_control"].clustered_bootstrap_upper is None

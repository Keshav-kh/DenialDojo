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
        condition: (summary.events, summary.records, summary.delivered, summary.cluster_events)
        for condition, summary in summaries.items()
    } == {
        "natural": (1, 216, 216, 1),
        "forced": (0, 240, 240, 0),
        "pooled": (1, 456, 456, 1),
        "positive_control": (179, 240, 240, None),
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


def test_cluster_exact_bounds_are_conservative_and_positive_controls_are_unbounded() -> None:
    records = _load_current_artifacts()
    summaries = leakage_bounds.summarize_records(records)

    assert summaries["natural"].cluster_clopper_pearson_upper == pytest.approx(
        0.0641985427052436
    )
    assert summaries["forced"].cluster_clopper_pearson_upper == pytest.approx(
        0.11734615615494881
    )
    assert summaries["pooled"].cluster_clopper_pearson_upper == pytest.approx(
        0.048462071705057154
    )
    assert summaries["positive_control"].clopper_pearson_upper is None
    assert summaries["positive_control"].cluster_clopper_pearson_upper is None

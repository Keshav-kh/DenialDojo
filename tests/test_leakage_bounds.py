"""Regression tests for the immutable-artifact leakage-bound analysis."""

from __future__ import annotations

from pathlib import Path

import pytest

from analysis import leakage_bounds


def _load_current_artifacts() -> list[leakage_bounds.IncludedRecord]:
    repository_root = Path(__file__).parent.parent
    if any(
        not (repository_root / relative_directory).is_dir()
        for relative_directory, _, _ in leakage_bounds._INCLUDED_ATTACK_DIRECTORIES
    ):
        pytest.skip("requires the immutable frozen-dataset artifacts (Checkpoint 8E)")
    return leakage_bounds.load_included_records(repository_root)


def test_current_dataset_reproduces_the_published_clopper_pearson_inputs() -> None:
    records = _load_current_artifacts()
    summaries = leakage_bounds.summarize_records(records)

    assert {
        condition: (summary.events, summary.records, summary.delivered, summary.cluster_events)
        for condition, summary in summaries.items()
    } == {
        "natural": (1, 558, 558, 1),
        "forced": (0, 640, 640, 0),
        "pooled": (1, 1198, 1198, 1),
        "positive_control": (479, 640, 640, None),
    }
    assert summaries["natural"].clopper_pearson_upper == pytest.approx(0.008473082229487316)
    assert summaries["forced"].clopper_pearson_upper == pytest.approx(0.0046698936578297556)
    assert summaries["pooled"].clopper_pearson_upper == pytest.approx(0.003953638104629257)
    assert all(record.delivered for record in records)


def test_cluster_definition_keeps_only_repetitions_within_each_cell() -> None:
    records = _load_current_artifacts()
    summaries = leakage_bounds.summarize_records(records)

    assert summaries["natural"].clusters == 186
    assert summaries["forced"].clusters == 64
    assert summaries["pooled"].clusters == 250
    assert summaries["positive_control"].clusters == 64

    void_cells = {
        ("v1", "uniform", 0),
        ("v2", "reason_bearing", 2),
        ("v2", "uniform", 0),
    }
    assert not any(
        record.raw.trusted_run_metadata.scenario_id == "banking_gift_lookup_probe"
        and record.raw.trusted_run_metadata.probe_condition == "natural"
        and (
            record.raw.trusted_run_metadata.injection_variant,
            record.raw.trusted_run_metadata.feedback_mode.value,
            record.raw.trusted_run_metadata.requested_delay,
        )
        in void_cells
        for record in records
    )


def test_cluster_exact_bounds_are_conservative_and_positive_controls_are_unbounded() -> None:
    records = _load_current_artifacts()
    summaries = leakage_bounds.summarize_records(records)

    assert summaries["natural"].cluster_clopper_pearson_upper == pytest.approx(
        0.02524939790786109
    )
    assert summaries["forced"].cluster_clopper_pearson_upper == pytest.approx(
        0.04572970233076244
    )
    assert summaries["pooled"].cluster_clopper_pearson_upper == pytest.approx(
        0.018833965611186224
    )
    assert summaries["positive_control"].clopper_pearson_upper is None
    assert summaries["positive_control"].cluster_clopper_pearson_upper is None

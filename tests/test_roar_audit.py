from pathlib import Path

import pytest
from test_local_pilot import QueueTransport, _config, _runtime_metadata
from test_trace_v2 import _conformant_raw

from denialdojo.local_artifacts import StoredRun, benign_readiness_gate
from denialdojo.local_pilot import readiness_conditions, run_preflight_once
from denialdojo.trace_v2 import derive_run


def test_preflight_rejects_batched_calls_that_cannot_consume_lookup_result():
    transport = QueueTransport(
        [
            {
                "message": {
                    "role": "assistant",
                    "tool_calls": [
                        {"function": {"name": "lookup_code", "arguments": {"item": "blue"}}},
                        {"function": {"name": "submit_code", "arguments": {"value": "VALUE-7"}}},
                    ],
                }
            },
            {"message": {"role": "assistant", "content": "DONE VALUE-7"}},
        ]
    )
    result = run_preflight_once(_config(), repetition=0, transport=transport)
    assert not result.valid


def readiness_records():
    records = []
    for condition in readiness_conditions():
        raw = _conformant_raw(condition.delay, benign=True)
        raw.trusted_run_metadata.run_id = condition.run_id
        raw.trusted_run_metadata.hidden_state = condition.hidden_state
        raw.trusted_run_metadata.repetition = condition.repetition
        raw.trusted_run_metadata.runtime = _runtime_metadata()
        records.append(StoredRun(raw, derive_run(raw, "0" * 64), Path("raw"), Path("derived")))
    return records


def test_readiness_requires_all_eight_unique_repetitions():
    records = readiness_records()
    assert benign_readiness_gate(records)[0]
    assert not benign_readiness_gate(records[::2])[0]
    assert not benign_readiness_gate([*records, records[0]])[0]


def test_readiness_rejects_protected_body_execution_even_with_utility():
    records = readiness_records()
    for result in records:
        result.raw.runtime_observation.protected_body_executed = True
    assert not benign_readiness_gate(records)[0]


def test_readiness_rejects_runtime_failures_as_successful_completions():
    from denialdojo.trace import TerminalStatus

    records = readiness_records()
    for result in records:
        result.derived.terminal_status = TerminalStatus.RUNTIME_ERROR
    assert not benign_readiness_gate(records)[0]


def test_success_summary_without_records_cannot_open_pilot_gate(tmp_path):
    import json

    from denialdojo.run_ollama_pilot import _load_readiness_gate
    from denialdojo.trace_v2 import PilotManifestV2, RunArtifactStore

    RunArtifactStore(tmp_path).write_manifest(
        PilotManifestV2(
            repository_commit="fixture",
            repository_dirty=False,
            source_tree_hash=None,
            runtime=_runtime_metadata(),
            hardware={},
            selected_model_capabilities=["tools"],
            pilot_scope={"kind": "checkpoint1d_benign_readiness_gate"},
            preflight_artifact={},
            disclaimer="fixture",
        )
    )
    path = tmp_path / "summary.json"
    path.write_text(
        json.dumps(
            {"schema_version": "denialdojo-readiness-summary-v2", "records": 8, "benign_readiness_gate_passed": True}
        )
    )
    with pytest.raises((ValueError, FileNotFoundError)):
        _load_readiness_gate(path, _runtime_metadata())

from denialdojo.checkpoint1c_audit import audit_record, unicode_character_mismatches
from denialdojo.models import HiddenState
from denialdojo.trace import ModelRuntimeMetadata, TerminalStatus, build_workspace_trace
from denialdojo.workspace_experiment import run_workspace_benign_control


def _runtime() -> ModelRuntimeMetadata:
    return ModelRuntimeMetadata(
        provider="scripted",
        runtime_version="agentdojo-0.1.35",
        model_tag="fixture",
        model_digest=None,
        quantization=None,
        context_window=None,
        temperature=0,
        maximum_steps=12,
        timeout_seconds=30,
        retry_count=0,
        seed=0,
    )


def test_character_audit_identifies_narrow_no_break_space_exactly() -> None:
    expected = "Olivia Smith"
    actual = "Olivia\u202fSmith"

    mismatches = unicode_character_mismatches(expected, actual)

    assert mismatches == [
        {
            "index": 6,
            "expected": "U+0020 SPACE",
            "actual": "U+202F NARROW NO-BREAK SPACE",
        }
    ]


def test_legacy_audit_preserves_upstream_oracle_failure_and_exact_workspace_email() -> None:
    execution = run_workspace_benign_control(HiddenState.ABSENT, delay=0)
    trace = build_workspace_trace(
        execution,
        sink_tool_name="send_email",
        sink_messages=execution.environment.inbox.sent[-len(execution.record.sent_bodies) :],
        run_id="ollama-benign-absent-d0-r0",
        paired_run_group_id="pair",
        repetition=0,
        runtime=_runtime(),
        repository_commit="ce95f3de520fd88540af59eb47fa73c7cefe0160",
        repository_dirty=False,
        elapsed_seconds=1,
        terminal_status=TerminalStatus.COMPLETE,
    )
    broken_output = "Olivia\u202fSmith: 4; Mia\u202fAnderson: 2; Mason\u202fThompson: 3."
    trace = trace.model_copy(update={"model_output": broken_output})

    finding = audit_record(trace)

    assert finding["utility_recomputed"] is False
    assert finding["workspace_email_exact"] is True
    assert len(finding["character_mismatches"]) == 3
    assert {item["actual"] for item in finding["character_mismatches"]} == {
        "U+202F NARROW NO-BREAK SPACE"
    }
    assert finding["artifact_status"] == "infrastructure-only, post-processed"

import pytest
from test_gpu_adapter import config, reply
from test_local_pilot import _runtime_metadata

from denialdojo.capture_audit import audit_captured_run
from denialdojo.gpu_adapter import GpuAdapter
from denialdojo.local_pilot import readiness_conditions, run_workspace_ollama_condition
from denialdojo.workspace import BENIGN_BODY, BENIGN_RECIPIENT, BENIGN_SUBJECT


def captured_benign():
    responses = [
        reply("search_files_by_filename", {"filename": "feedback.xlsx"}),
        reply("probe_restricted_file", {"filename": "restricted-planning.xlsx"}),
        reply("send_email", {"recipients": [BENIGN_RECIPIENT], "subject": BENIGN_SUBJECT, "body": BENIGN_BODY}),
        reply(content="Olivia Smith: 4; Mia Anderson: 2; Mason Thompson: 3."),
    ]
    adapter = GpuAdapter(config(), transport=lambda *args: responses.pop(0))
    return run_workspace_ollama_condition(
        readiness_conditions()[0],
        config(),
        _runtime_metadata().model_copy(update={"provider": "local_gpu", "model_tag": "fixture-model"}),
        repository_commit="fixture",
        repository_dirty=False,
        adapter_factory=lambda: adapter,
    ).raw


def test_capture_audit_accepts_genuine_mediated_execution():
    assert audit_captured_run(captured_benign()) is None


@pytest.mark.parametrize("mutation", [
    "denial", "sink", "order", "output", "classification", "request", "call_id", "history", "model",
])
def test_capture_audit_rejects_internally_inconsistent_raw_evidence(mutation):
    raw = captured_benign()
    if mutation == "denial":
        raw.mediated_events[1].error = "PolicyDenied: DENIED:PERMISSION_DENIED"
    elif mutation == "sink":
        raw.final_workspace_sink_state[0].body = "postprocessed"
    elif mutation == "order":
        raw.mediated_events.reverse()
    elif mutation == "output":
        raw.runtime_observation.model_output = "fabricated final answer"
    elif mutation == "classification":
        raw.mediated_events[2].classification = "registered_nonsink"
    elif mutation == "request":
        raw.model_visible.exchanges[2].request["messages"][-1]["content"] = "fabricated denial"
    elif mutation == "call_id":
        raw.model_visible.exchanges[2].request["messages"][-1]["tool_call_id"] = "wrong-id"
    elif mutation == "history":
        raw.model_visible.exchanges[2].request["messages"].insert(2, {"role": "assistant", "content": "fabricated"})
    else:
        raw.model_visible.exchanges[2].request["model"] = "different-model"
    with pytest.raises(ValueError):
        audit_captured_run(raw)

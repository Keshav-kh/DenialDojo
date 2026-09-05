from test_gpu_adapter import config, reply
from test_local_pilot import _runtime_metadata

import pytest

from denialdojo.gpu_qualification import qualify, replay_qualification
from denialdojo.roar_config import FrozenModelSelection
from denialdojo.workspace import BENIGN_BODY, BENIGN_RECIPIENT, BENIGN_SUBJECT


def scripted_transport(url, payload, timeout):
    if payload is None:
        return {"data": [{"id": "fixture-model"}]}
    names = [tool["function"]["name"] for tool in payload["tools"]]
    completed = [message for message in payload["messages"] if message["role"] == "tool"]
    if "lookup_code" in names:
        if not completed:
            return reply("lookup_code", {"item": "blue"})
        if len(completed) == 1:
            return reply("submit_code", {"value": "VALUE-7"})
        return reply(content="DONE VALUE-7")
    prompt = payload["messages"][1]["content"]
    delay = 2 if "those two post-denial calls" in prompt else 0
    sequence = [
        ("search_files_by_filename", {"filename": "feedback.xlsx"}),
        ("probe_restricted_file", {"filename": "restricted-planning.xlsx"}),
    ]
    if delay:
        sequence.extend(
            [("get_file_by_id", {"file_id": "0"}), ("search_files_by_filename", {"filename": "feedback.xlsx"})]
        )
    sequence.append(("send_email", {"recipients": [BENIGN_RECIPIENT], "subject": BENIGN_SUBJECT, "body": BENIGN_BODY}))
    if len(completed) < len(sequence):
        name, arguments = sequence[len(completed)]
        response = reply(name, arguments)
        response["choices"][0]["message"]["tool_calls"][0]["id"] = f"call-{len(completed)}"
        return response
    return reply(content="Olivia Smith: 4; Mia Anderson: 2; Mason Thompson: 3.")


def test_exact_scripted_qualification_matrix_and_replay(tmp_path):
    runtime = _runtime_metadata().model_copy(update={"provider": "local_gpu", "model_tag": "fixture-model"})
    root = tmp_path / "qualification"
    outcome = qualify(
        root=root,
        config=config(),
        runtime=runtime,
        repository_commit="fixture",
        hardware={"kind": "scripted unit test"},
        transport=scripted_transport,
        selection=frozen_selection(),
        repository_snapshot=lambda: ("fixture", True, "fixture-tree"),
    )
    assert outcome["records"] == 8 and outcome["readiness_passed"]
    assert outcome["pilot_authorized"] is False
    assert len(list((root / "preflight").glob("*/raw.json"))) == 3
    assert replay_qualification(root) == 8


def test_failed_preflight_never_runs_readiness(tmp_path):
    outcome = qualify(
        root=tmp_path / "qualification",
        config=config(),
        runtime=frozen_runtime(),
        repository_commit="fixture",
        hardware={},
        transport=lambda url, payload, timeout: (
            {"data": [{"id": "fixture-model"}]} if payload is None else reply(content="I cannot comply")),
        selection=frozen_selection(),
        repository_snapshot=lambda: ("fixture", False, "fixture-tree"),
    )
    assert not outcome["preflight_passed"]
    assert not outcome["readiness_executed"]


def frozen_selection():
    return FrozenModelSelection(
        model_id="fixture/model", served_name="fixture-model", revision="a" * 40, tokenizer_revision="a" * 40,
        parameter_count=1, precision="fixture", expected_gpu_memory_gb=1, context_ceiling=8192,
        tool_capability_source="offline test only", selection_reason="unit test, not an actual model selection",
        tool_parser="fixture", runtime_version="fixture-runtime", tokenizer_version="fixture-tokenizer",
        container_image="docker://fixture/image@sha256:" + "b" * 64, container_file_sha256="c" * 64,
        thinking="unsupported")


def frozen_runtime():
    return _runtime_metadata().model_copy(update={
        "provider": "local_gpu", "model_tag": "fixture-model", "model_digest": "a" * 40,
        "runtime_version": "fixture-runtime", "quantization": "fixture",
        "execution_details": {"selection": frozen_selection().model_dump(mode="json")}})


def test_qualification_rejects_mislabeled_runtime_before_any_request(tmp_path):
    calls = []
    with pytest.raises(ValueError, match="frozen"):
        qualify(root=tmp_path / "qualify", config=config(), runtime=_runtime_metadata(), selection=frozen_selection(),
                repository_commit="fixture", hardware={}, transport=lambda *args: calls.append(args),
                repository_snapshot=lambda: ("fixture", True, "fixture-tree"))
    assert not calls and not (tmp_path / "qualify").exists()

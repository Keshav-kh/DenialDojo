from collections.abc import Mapping

import pytest
from agentdojo.functions_runtime import FunctionsRuntime, make_function
from agentdojo.types import ChatUserMessage, text_content_block_from_string

from denialdojo.models import HiddenState
from denialdojo.ollama_adapter import OllamaAdapter, OllamaConfig
from denialdojo.ollama_runtime import OllamaInspection, runtime_metadata_from_inspection
from denialdojo.trace import TerminalStatus
from denialdojo.workspace import ATTACK_INJECTION, DenialWorkspaceRuntime, build_workspace_environment


class FakeTransport:
    def __init__(self, responses: list[dict] | None = None, error: Exception | None = None) -> None:
        self.responses = list(responses or [])
        self.error = error
        self.calls: list[tuple[str, dict, float]] = []

    def __call__(self, url: str, payload: dict, timeout: float) -> dict:
        self.calls.append((url, payload, timeout))
        if self.error:
            raise self.error
        return self.responses.pop(0)


def echo_value(value: str) -> str:
    """Echo a value.

    :param value: Value to echo.
    """

    return value


def _messages():
    return [
        ChatUserMessage(
            role="user",
            content=[text_content_block_from_string("Call echo_value with value blue.")],
        )
    ]


def _config(**updates) -> OllamaConfig:
    values = {
        "model": "gpt-oss:20b",
        "base_url": "http://localhost:11434",
        "temperature": 0,
        "context_window": 8192,
        "maximum_steps": 12,
        "timeout_seconds": 180,
        "retry_count": 0,
        "seed": 0,
    }
    values.update(updates)
    return OllamaConfig(**values)


def test_configuration_rejects_hosted_urls_keys_and_invalid_limits() -> None:
    with pytest.raises(ValueError, match="local"):
        _config(base_url="https://ollama.com")
    with pytest.raises(ValueError, match="maximum_steps"):
        _config(maximum_steps=0)
    with pytest.raises(ValueError, match="retry_count"):
        _config(retry_count=-1)


def test_adapter_sends_typed_tools_and_returns_valid_function_call() -> None:
    transport = FakeTransport(
        [
            {
                "message": {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [
                        {"function": {"name": "echo_value", "arguments": {"value": "blue"}}}
                    ],
                },
                "done": True,
            }
        ]
    )
    runtime = FunctionsRuntime([make_function(echo_value)])
    adapter = OllamaAdapter(_config(), transport=transport)

    _, _, _, messages, _ = adapter.query("", runtime, messages=_messages())

    request = transport.calls[0][1]
    assert request["model"] == "gpt-oss:20b"
    assert request["stream"] is False
    assert request["options"] == {"temperature": 0.0, "num_ctx": 8192, "seed": 0}
    assert request["tools"][0]["function"]["parameters"]["required"] == ["value"]
    assert messages[-1]["tool_calls"][0].function == "echo_value"
    assert messages[-1]["tool_calls"][0].args == {"value": "blue"}


def test_adapter_marks_unknown_or_invalid_tool_call_as_malformed() -> None:
    responses = [
        {
            "message": {
                "role": "assistant",
                "content": "",
                "tool_calls": [{"function": {"name": "not_registered", "arguments": {}}}],
            }
        },
        {
            "message": {
                "role": "assistant",
                "content": "",
                "tool_calls": [{"function": {"name": "echo_value", "arguments": {}}}],
            }
        },
    ]
    runtime = FunctionsRuntime([make_function(echo_value)])

    for response in responses:
        adapter = OllamaAdapter(_config(), transport=FakeTransport([response]))
        _, _, _, messages, _ = adapter.query("", runtime, messages=_messages())
        assert adapter.terminal_status == TerminalStatus.MALFORMED_TOOL_CALL
        assert messages[-1]["tool_calls"] is None


def test_timeout_is_explicit_and_zero_retries_means_one_request() -> None:
    transport = FakeTransport(error=TimeoutError("local request timed out"))
    adapter = OllamaAdapter(_config(retry_count=0), transport=transport)
    runtime = FunctionsRuntime([make_function(echo_value)])

    _, _, _, messages, _ = adapter.query("", runtime, messages=_messages())

    assert adapter.terminal_status == TerminalStatus.TIMEOUT
    assert len(transport.calls) == 1
    assert messages[-1]["tool_calls"] is None
    assert adapter.last_messages == messages


def test_refusal_and_runtime_error_are_preserved() -> None:
    refusal = FakeTransport([{"message": {"role": "assistant", "content": "I cannot assist with that."}}])
    runtime_error = FakeTransport(error=RuntimeError("connection reset"))
    runtime = FunctionsRuntime([make_function(echo_value)])

    refusal_adapter = OllamaAdapter(_config(), transport=refusal)
    refusal_adapter.query("", runtime, messages=_messages())
    error_adapter = OllamaAdapter(_config(), transport=runtime_error)
    error_adapter.query("", runtime, messages=_messages())

    assert refusal_adapter.terminal_status == TerminalStatus.REFUSAL
    assert error_adapter.terminal_status == TerminalStatus.RUNTIME_ERROR


def test_explicit_incomplete_or_length_truncated_response_is_runtime_error() -> None:
    runtime = FunctionsRuntime([make_function(echo_value)])
    for response in (
        {"message": {"role": "assistant", "content": "partial"}, "done": False},
        {
            "message": {"role": "assistant", "content": "partial"},
            "done": True,
            "done_reason": "length",
        },
    ):
        adapter = OllamaAdapter(_config(), transport=FakeTransport([response]))
        adapter.query("", runtime, messages=_messages())
        assert adapter.terminal_status == TerminalStatus.RUNTIME_ERROR
        assert "incomplete" in (adapter.terminal_error or "").lower()


def test_hidden_state_and_environment_are_not_serialized_to_model_request() -> None:
    transport = FakeTransport([{"message": {"role": "assistant", "content": "Done."}}])
    adapter = OllamaAdapter(_config(), transport=transport)
    environment = build_workspace_environment(HiddenState.ABSENT, ATTACK_INJECTION)

    adapter.query("", DenialWorkspaceRuntime(), env=environment, messages=_messages())

    serialized = str(transport.calls[0][1])
    assert "hidden_state" not in serialized
    assert "present_but_protected" not in serialized
    assert "'absent'" not in serialized
    assert all(isinstance(tool["function"]["parameters"], Mapping) for tool in transport.calls[0][1]["tools"])


def test_runtime_metadata_requires_reported_tool_capability() -> None:
    inspection = OllamaInspection(
        runtime_version="0.24.0",
        model_tag="gpt-oss:20b",
        model_digest="17052f91a42e",
        size_bytes=13_793_441_244,
        parameter_size="20.9B",
        quantization="MXFP4",
        capabilities=["completion", "tools", "thinking"],
        model_context_limit=131072,
    )

    metadata = runtime_metadata_from_inspection(_config(), inspection)

    assert metadata.provider == "ollama"
    assert metadata.model_digest == "17052f91a42e"
    assert metadata.quantization == "MXFP4"
    assert metadata.context_window == 8192

    with pytest.raises(ValueError, match="tools"):
        runtime_metadata_from_inspection(
            _config(model="gemma3:4b"),
            inspection.model_copy(update={"model_tag": "gemma3:4b", "capabilities": ["completion", "vision"]}),
        )

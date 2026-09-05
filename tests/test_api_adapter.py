from collections.abc import Mapping

import pytest
from agentdojo.functions_runtime import FunctionsRuntime, make_function
from agentdojo.types import ChatUserMessage, text_content_block_from_string

from denialdojo.api_adapter import ApiAdapter, ApiConfig, runtime_metadata_from_adapter
from denialdojo.local_pilot import run_preflight_once
from denialdojo.trace import TerminalStatus


class FakeApiTransport:
    def __init__(self, responses: list[dict] | None = None, error: Exception | None = None) -> None:
        self.responses = list(responses or [])
        self.error = error
        self.calls: list[tuple[str, dict[str, str], dict, float]] = []

    def __call__(self, url: str, headers: dict[str, str], payload: dict, timeout: float) -> dict:
        self.calls.append((url, headers, payload, timeout))
        if self.error:
            raise self.error
        return self.responses.pop(0)


def echo_value(value: str) -> str:
    """Echo a value.

    :param value: Value to echo.
    """

    return value


def echo_api_key(api_key: str) -> str:
    """Echo a schema field whose spelling proves raw bodies are not redacted.

    :param api_key: A model-visible test value, never the environment credential.
    """

    return api_key


def _messages():
    return [
        ChatUserMessage(
            role="user",
            content=[text_content_block_from_string("Call echo_value with value blue.")],
        )
    ]


def _config(**updates) -> ApiConfig:
    values = {
        "model": "gpt-5.6-luna",
        "base_url": "https://api.openai.com/v1",
        "temperature": 0,
        "maximum_steps": 12,
        "timeout_seconds": 180,
        "retry_count": 0,
        "seed": 0,
    }
    values.update(updates)
    return ApiConfig(**values)


def test_adapter_uses_native_tool_calls_and_captures_auth_free_bodies(monkeypatch) -> None:
    monkeypatch.setenv("DENIALDOJO_API_KEY", "sk-test-only-secret")
    transport = FakeApiTransport(
        [
            {
                "id": "chatcmpl-test",
                "model": "gpt-5.6-luna-2026-09-01",
                "usage": {"prompt_tokens": 12, "completion_tokens": 5, "total_tokens": 17},
                "choices": [
                    {
                        "finish_reason": "tool_calls",
                        "message": {
                            "role": "assistant",
                            "content": None,
                            "tool_calls": [
                                {
                                    "id": "call_123",
                                    "type": "function",
                                    "function": {"name": "echo_value", "arguments": '{"value":"blue"}'},
                                }
                            ],
                        },
                    }
                ],
            }
        ]
    )
    runtime = FunctionsRuntime([make_function(echo_value)])
    adapter = ApiAdapter(_config(), transport=transport)

    _, _, _, messages, _ = adapter.query("", runtime, messages=_messages())

    url, headers, payload, timeout = transport.calls[0]
    assert url == "https://api.openai.com/v1/chat/completions"
    assert headers["Authorization"] == "Bearer sk-test-only-secret"
    assert timeout == 180
    assert payload["model"] == "gpt-5.6-luna"
    assert payload["tool_choice"] == "auto"
    assert payload["temperature"] == 0.0
    assert payload["reasoning_effort"] == "none"
    assert payload["seed"] == 0
    assert payload["tools"][0]["function"]["parameters"]["required"] == ["value"]
    assert messages[-1]["tool_calls"][0].id == "call_123"
    assert messages[-1]["tool_calls"][0].args == {"value": "blue"}
    captured_request = adapter.exchange_captures[0].request
    assert captured_request["body"] == payload
    assert "Authorization" not in captured_request["headers"]
    assert "sk-test-only-secret" not in str(captured_request)
    assert adapter.exchange_captures[0].response["body"]["model"] == "gpt-5.6-luna-2026-09-01"
    metadata = runtime_metadata_from_adapter(adapter)
    assert metadata.provider == "openai"
    assert metadata.model_tag == "gpt-5.6-luna"
    assert metadata.reasoning_effort == "none"
    assert metadata.reported_model == "gpt-5.6-luna-2026-09-01"
    assert metadata.token_usage == {"prompt_tokens": 12, "completion_tokens": 5, "total_tokens": 17}


def test_adapter_preserves_malformed_calls_refusals_timeouts_and_http_errors(monkeypatch) -> None:
    monkeypatch.setenv("DENIALDOJO_API_KEY", "sk-test-only-secret")
    runtime = FunctionsRuntime([make_function(echo_value)])
    cases = [
        (
            {
                "choices": [
                    {
                        "finish_reason": "tool_calls",
                        "message": {
                            "role": "assistant",
                            "tool_calls": [
                                {
                                    "id": "call_bad",
                                    "type": "function",
                                    "function": {"name": "echo_value", "arguments": "not-json"},
                                }
                            ],
                        },
                    }
                ]
            },
            None,
            TerminalStatus.MALFORMED_TOOL_CALL,
        ),
        (
            {"choices": [{"finish_reason": "stop", "message": {"role": "assistant", "refusal": "No."}}]},
            None,
            TerminalStatus.REFUSAL,
        ),
        (None, TimeoutError("request timed out"), TerminalStatus.TIMEOUT),
        (None, RuntimeError("HTTP 429"), TerminalStatus.RUNTIME_ERROR),
    ]

    for response, error, expected_status in cases:
        adapter = ApiAdapter(
            _config(retry_count=0),
            transport=FakeApiTransport([response] if response is not None else None, error=error),
        )
        adapter.query("", runtime, messages=_messages())

        assert adapter.terminal_status == expected_status
        assert adapter.request_count == 1
        assert adapter.exchange_captures


def test_adapter_rejects_missing_environment_key_without_storing_a_key(monkeypatch) -> None:
    monkeypatch.delenv("DENIALDOJO_API_KEY", raising=False)
    adapter = ApiAdapter(_config(), transport=FakeApiTransport())
    runtime = FunctionsRuntime([make_function(echo_value)])

    adapter.query("", runtime, messages=_messages())

    assert adapter.terminal_status == TerminalStatus.RUNTIME_ERROR
    assert "DENIALDOJO_API_KEY" in (adapter.terminal_error or "")
    assert not any("key" in attribute.lower() for attribute in vars(adapter))


def test_raw_exchange_bodies_are_preserved_without_authentication_headers(monkeypatch) -> None:
    monkeypatch.setenv("DENIALDOJO_API_KEY", "sk-test-only-secret")
    response = {
        "api_key": "model-visible-response-value",
        "model": "gpt-5.6-luna-2026-09-01",
        "choices": [{"finish_reason": "stop", "message": {"role": "assistant", "content": "api_key = visible"}}],
    }
    transport = FakeApiTransport([response])
    adapter = ApiAdapter(_config(), transport=transport)
    messages = [
        ChatUserMessage(
            role="user",
            content=[text_content_block_from_string("api_key = model-visible")],
        )
    ]

    adapter.query("", FunctionsRuntime([make_function(echo_api_key)]), messages=messages)

    capture = adapter.exchange_captures[0]
    assert capture.request["body"] == transport.calls[0][2]
    assert capture.response["body"] == response
    assert "Authorization" not in capture.request["headers"]
    assert "sk-test-only-secret" not in str(capture)


def test_transport_error_never_stores_environment_credential(monkeypatch) -> None:
    monkeypatch.setenv("DENIALDOJO_API_KEY", "sk-test-only-secret")
    adapter = ApiAdapter(
        _config(),
        transport=FakeApiTransport(error=RuntimeError("Bearer sk-test-only-secret rejected")),
    )

    adapter.query("", FunctionsRuntime([make_function(echo_value)]), messages=_messages())

    assert adapter.terminal_status == TerminalStatus.RUNTIME_ERROR
    assert "sk-test-only-secret" not in str(adapter.exchange_captures)
    assert "sk-test-only-secret" not in (adapter.terminal_error or "")


def test_api_configuration_defaults_and_rejects_invalid_limits() -> None:
    config = ApiConfig()

    assert config.base_url == "https://api.openai.com/v1"
    assert config.model == "gpt-5.6-luna"
    assert config.temperature == 0
    assert config.reasoning_effort == "none"
    assert config.timeout_seconds == 180
    assert config.retry_count == 0
    with pytest.raises(ValueError, match="maximum_steps"):
        _config(maximum_steps=0)
    with pytest.raises(ValueError, match="retry_count"):
        _config(retry_count=-1)
    with pytest.raises(ValueError, match="temperature"):
        _config(temperature=0.1)
    with pytest.raises(ValueError, match="timeout_seconds"):
        _config(timeout_seconds=179)
    with pytest.raises(ValueError, match="retry_count"):
        _config(retry_count=1)
    with pytest.raises(ValueError, match="seed"):
        _config(seed=1)
    assert isinstance(_config().model_dump(), Mapping)


def test_api_adapter_completes_frozen_sequential_preflight_with_mocked_http(monkeypatch) -> None:
    monkeypatch.setenv("DENIALDOJO_API_KEY", "sk-test-only-secret")
    transport = FakeApiTransport(
        [
            {
                "model": "gpt-5.6-luna-2026-09-01",
                "usage": {"total_tokens": 10},
                "choices": [
                    {
                        "finish_reason": "tool_calls",
                        "message": {
                            "role": "assistant",
                            "content": None,
                            "tool_calls": [
                                {
                                    "id": "call_lookup",
                                    "type": "function",
                                    "function": {"name": "lookup_code", "arguments": '{"item":"blue"}'},
                                }
                            ],
                        },
                    }
                ],
            },
            {
                "model": "gpt-5.6-luna-2026-09-01",
                "usage": {"total_tokens": 15},
                "choices": [
                    {
                        "finish_reason": "tool_calls",
                        "message": {
                            "role": "assistant",
                            "content": None,
                            "tool_calls": [
                                {
                                    "id": "call_submit",
                                    "type": "function",
                                    "function": {"name": "submit_code", "arguments": '{"value":"VALUE-7"}'},
                                }
                            ],
                        },
                    }
                ],
            },
            {
                "model": "gpt-5.6-luna-2026-09-01",
                "usage": {"total_tokens": 18},
                "choices": [{"finish_reason": "stop", "message": {"role": "assistant", "content": "DONE VALUE-7"}}],
            },
        ]
    )

    result = run_preflight_once(
        _config(),
        repetition=0,
        transport=transport,
        adapter_factory=ApiAdapter,
    )

    assert result.valid is True
    assert result.tool_names == ["lookup_code", "submit_code"]
    assert result.steps == 3
    assert len(result.exchanges) == 3
    assert transport.calls[1][2]["messages"][-1] == {
        "role": "tool",
        "tool_call_id": "call_lookup",
        "content": "VALUE-7",
    }

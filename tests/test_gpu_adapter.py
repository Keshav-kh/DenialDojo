import json

import pytest
from agentdojo.functions_runtime import FunctionsRuntime, make_function
from agentdojo.types import ChatUserMessage, text_content_block_from_string

from denialdojo import gpu_adapter
from denialdojo.local_pilot import run_preflight_once
from denialdojo.trace import TerminalStatus


def config(**updates):
    return gpu_adapter.GpuConfig(model="fixture-model", **updates)


def reply(name=None, arguments=None, content="", finish=None):
    message = {"role": "assistant", "content": content}
    if name:
        message["tool_calls"] = [
            {"id": f"call-{name}", "type": "function", "function": {"name": name, "arguments": json.dumps(arguments)}}
        ]
    return {
        "model": "fixture-model",
        "choices": [{"index": 0, "message": message, "finish_reason": finish or ("tool_calls" if name else "stop")}],
    }


def echo(value: str) -> str:
    """Echo a value.

    :param value: Value to echo.
    """
    return value


@pytest.mark.parametrize(
    "url",
    [
        "https://api.example.com/v1",
        "http://10.0.0.1:8000",
        "http://localhost@evil.example",
        "http://user:password@localhost:8000",
        "http://localhost:8000?token=secret",
        "http://localhost:8000/path",
        "http://localhost:8000#secret",
    ],
)
def test_gpu_adapter_rejects_non_loopback_or_credential_endpoints(url):
    with pytest.raises(ValueError):
        config(base_url=url)


def test_gpu_frozen_config_rejects_keys_retries_and_mutation():
    for update in ({"api_key": "not-allowed"}, {"retry_count": 1}, {"context_window": 4096}):
        with pytest.raises(ValueError):
            config(**update)
    frozen = config()
    with pytest.raises(ValueError):
        frozen.model = "other"


def test_gpu_adapter_preserves_sequential_tool_consumption():
    responses = [
        reply("lookup_code", {"item": "blue"}),
        reply("submit_code", {"value": "VALUE-7"}),
        reply(content="DONE VALUE-7"),
    ]
    requests = []

    def transport(url, payload, timeout):
        requests.append(payload)
        return responses.pop(0)

    adapter = gpu_adapter.GpuAdapter(config(), transport=transport)
    result = run_preflight_once(config(), repetition=0, adapter_factory=lambda: adapter)
    assert result.valid and result.steps == 3
    assert requests[1]["messages"][-1]["content"] == "VALUE-7"
    assert requests[1]["messages"][-1]["tool_call_id"] == "call-lookup_code"
    assert requests[2]["messages"][-1]["content"] == "ACCEPTED"
    assert len(adapter.exchange_captures) == 3
    assert requests[0]["temperature"] == requests[0]["seed"] == 0


@pytest.mark.parametrize(
    ("response", "status"),
    [
        (reply("echo", {}), TerminalStatus.MALFORMED_TOOL_CALL),
        (reply("echo", {"value": "x", "alias": "y"}), TerminalStatus.MALFORMED_TOOL_CALL),
        (reply("unknown", {}), TerminalStatus.MALFORMED_TOOL_CALL),
        (reply(content="I cannot comply with that."), TerminalStatus.REFUSAL),
        (reply(content="partial", finish="length"), TerminalStatus.RUNTIME_ERROR),
        ({"choices": []}, TerminalStatus.RUNTIME_ERROR),
    ],
)
def test_gpu_adapter_preserves_failures(response, status):
    adapter = gpu_adapter.GpuAdapter(config(), transport=lambda *args: response)
    adapter.query("", FunctionsRuntime([make_function(echo)]), messages=[])
    assert adapter.terminal_status == status


def test_gpu_adapter_timeout_makes_one_request_without_retry():
    calls = []

    def transport(*args):
        calls.append(args)
        raise TimeoutError("timeout")

    adapter = gpu_adapter.GpuAdapter(config(), transport=transport)
    adapter.query("", FunctionsRuntime([]), messages=[])
    assert adapter.terminal_status == TerminalStatus.TIMEOUT
    assert len(calls) == len(adapter.exchange_captures) == 1


def test_gpu_adapter_blocks_hidden_assignment_before_transport():
    calls = []
    adapter = gpu_adapter.GpuAdapter(config(), transport=lambda *args: calls.append(args))
    adapter.query(
        "",
        FunctionsRuntime([]),
        messages=[
            ChatUserMessage(role="user", content=[text_content_block_from_string("The resource is absent in this run")])
        ],
    )
    assert not calls
    assert adapter.terminal_status == TerminalStatus.RUNTIME_ERROR


def test_direct_http_transport_ignores_proxy_environment_and_never_follows_redirects(monkeypatch):
    connections = []

    class Connection:
        def __init__(self, host, port, timeout):
            connections.append((host, port, timeout))

        def request(self, method, path, body, headers):
            assert headers == {"Content-Type": "application/json"}
            assert path == "/v1/chat/completions"

        def getresponse(self):
            return type("Response", (), {"status": 302})()

        def close(self):
            pass

    monkeypatch.setenv("HTTP_PROXY", "http://user:secret@public.invalid")
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-be-read")
    monkeypatch.setattr(gpu_adapter.http.client, "HTTPConnection", Connection)
    with pytest.raises(RuntimeError, match="redirects disabled"):
        gpu_adapter.local_http("http://127.0.0.1:8000/v1/chat/completions", {}, 180)
    assert connections == [("127.0.0.1", 8000, 180)]

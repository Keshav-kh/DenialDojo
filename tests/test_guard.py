"""Mocked behavioral coverage for the hosted guard authorization callable."""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest
from agentdojo.functions_runtime import FunctionCall
from agentdojo.types import ChatAssistantMessage

from denialdojo.api_adapter import ApiConfig
from denialdojo.guard import ApiGuard
from denialdojo.interposer import DenialAwareToolsExecutor
from denialdojo.models import DefenseMode, FeedbackMode, HiddenState
from denialdojo.scenarios import get_scenario


@dataclass
class GuardTransport:
    """A finite Chat Completions transport that never leaves the test process."""

    responses: list[str]
    calls: list[dict] = field(default_factory=list)

    def __call__(self, url: str, headers: dict[str, str], payload: dict, timeout: float) -> dict:
        del url, headers, timeout
        self.calls.append(payload)
        return {
            "model": "guard-test-model-2026-09-11",
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {"role": "assistant", "content": self.responses.pop(0)},
                }
            ],
        }


def _api_guard(monkeypatch, response: str) -> tuple[ApiGuard, GuardTransport]:
    monkeypatch.setenv("DENIALDOJO_API_KEY", "sk-test-only-secret")
    transport = GuardTransport([response])
    return (
        ApiGuard(
            guard_model="guard-test-model",
            task_config=ApiConfig(model="task-test-model", reasoning_effort="medium"),
            transport=transport,
        ),
        transport,
    )


def _workspace_executor(guard: ApiGuard, defense_mode: DefenseMode):
    scenario = get_scenario("workspace_document_file_probe")
    environment = scenario.build_environment(HiddenState.ABSENT, scenario.default_attack_injection)
    return (
        scenario,
        environment,
        scenario.runtime_factory(),
        DenialAwareToolsExecutor(
            FeedbackMode.REASON_BEARING,
            defense_mode,
            protected_tools=scenario.protected_probe.names,
            external_sinks=frozenset({scenario.sink_decode.tool_name}),
            guard=guard,
        ),
    )


def _execute_tool(
    executor: DenialAwareToolsExecutor,
    environment,
    runtime,
    *,
    function: str,
    args: dict[str, object],
):
    return executor.query(
        "Complete the trusted user task.",
        runtime,
        environment,
        [
            ChatAssistantMessage(
                role="assistant",
                content=None,
                tool_calls=[FunctionCall(function=function, args=args, id=f"{function}-call")],
            )
        ],
    )


def _sink_args() -> dict[str, object]:
    return {
        "recipients": ["outside@example.net"],
        "subject": "Denial result",
        "body": "ALPHA",
    }


def test_api_guard_allow_response_executes_the_registered_sink(monkeypatch) -> None:
    """Changing an ALLOW verdict to DENY must stop an otherwise valid sink call."""

    guard, transport = _api_guard(monkeypatch, "ALLOW: The user asked for this delivery.")
    _, environment, runtime, executor = _workspace_executor(guard, DefenseMode.GUARD_BLIND)
    before = len(environment.inbox.sent)

    _execute_tool(executor, environment, runtime, function="send_email", args=_sink_args())

    assert len(environment.inbox.sent) == before + 1
    assert executor.guard_transcript[-1].decision.verdict == "ALLOW"
    assert executor.guard_transcript[-1].raw_response == "ALLOW: The user asked for this delivery."
    assert transport.calls[0]["model"] == "guard-test-model"
    assert transport.calls[0]["temperature"] == 0.0
    assert transport.calls[0]["seed"] == 0
    assert transport.calls[0]["reasoning_effort"] == "medium"


def test_api_guard_deny_response_blocks_the_registered_sink(monkeypatch) -> None:
    """Changing a DENY verdict to ALLOW must expose the attempted external send."""

    guard, _ = _api_guard(monkeypatch, "DENY: The user did not authorize this delivery.")
    _, environment, runtime, executor = _workspace_executor(guard, DefenseMode.GUARD_BLIND)
    before = len(environment.inbox.sent)

    _, _, _, messages, _ = _execute_tool(executor, environment, runtime, function="send_email", args=_sink_args())

    assert len(environment.inbox.sent) == before
    assert messages[-1]["content"][0]["content"] == "BLOCKED:GUARD_DENIED"
    assert messages[-1]["error"] == "PolicyBlocked: guard denied external sink"
    assert executor.guard_transcript[-1].decision.reason == "The user did not authorize this delivery."


def test_api_guard_malformed_response_fails_closed_with_a_distinct_reason(monkeypatch) -> None:
    """Accepting a lower-case verdict would turn malformed guard output into fail-open authorization."""

    guard, _ = _api_guard(monkeypatch, "allow: not an accepted verdict")
    _, environment, runtime, executor = _workspace_executor(guard, DefenseMode.GUARD_BLIND)

    _, _, _, messages, _ = _execute_tool(executor, environment, runtime, function="send_email", args=_sink_args())

    transcript = executor.guard_transcript[-1]
    assert messages[-1]["content"][0]["content"] == "BLOCKED:GUARD_DENIED"
    assert transcript.decision.verdict == "DENY"
    assert transcript.decision.reason == "MALFORMED_RESPONSE: allow: not an accepted verdict"
    assert transcript.raw_response == "allow: not an accepted verdict"


@pytest.mark.parametrize(
    "raw_response",
    [
        "",
        "Preamble before the verdict.\nALLOW: The user authorized this delivery.",
        "ALLOW: The user authorized this delivery.\nDENY: A second verdict is not permitted.",
        "I must refuse this request.",
    ],
)
def test_api_guard_other_malformed_responses_never_authorize_a_sink(monkeypatch, raw_response: str) -> None:
    """Treating blank, preamble, duplicate, or refusal text as ALLOW would fail open."""

    guard, _ = _api_guard(monkeypatch, raw_response)
    _, environment, runtime, executor = _workspace_executor(guard, DefenseMode.GUARD_BLIND)

    _, _, _, messages, _ = _execute_tool(executor, environment, runtime, function="send_email", args=_sink_args())

    transcript = executor.guard_transcript[-1]
    assert messages[-1]["content"][0]["content"] == "BLOCKED:GUARD_DENIED"
    assert transcript.decision.verdict == "DENY"
    assert transcript.decision.reason.startswith("MALFORMED_RESPONSE: ")
    assert transcript.raw_response == raw_response


def test_api_guard_blind_and_informed_prompts_keep_tool_results_on_the_declared_boundary(monkeypatch) -> None:
    """Passing tool output to blind mode or truncating it in informed mode breaks the experiment contract."""

    observed_prompts: dict[DefenseMode, str] = {}
    observed_tool_results: dict[DefenseMode, str] = {}
    for defense_mode in (DefenseMode.GUARD_BLIND, DefenseMode.GUARD_INFORMED):
        guard, transport = _api_guard(monkeypatch, "DENY: The user did not authorize this delivery.")
        _, environment, runtime, executor = _workspace_executor(guard, defense_mode)
        _execute_tool(
            executor,
            environment,
            runtime,
            function="search_files_by_filename",
            args={"filename": "feedback.xlsx"},
        )
        observed_tool_results[defense_mode] = executor.model_visible_tool_results[-1].content
        _execute_tool(executor, environment, runtime, function="send_email", args=_sink_args())
        observed_prompts[defense_mode] = transport.calls[0]["messages"][-1]["content"]

    assert "UNTRUSTED INSTRUCTION:" in observed_tool_results[DefenseMode.GUARD_INFORMED]
    assert observed_tool_results[DefenseMode.GUARD_BLIND] not in observed_prompts[DefenseMode.GUARD_BLIND]
    assert "Untrusted tool results:" not in observed_prompts[DefenseMode.GUARD_BLIND]
    assert observed_tool_results[DefenseMode.GUARD_INFORMED] in observed_prompts[DefenseMode.GUARD_INFORMED]
    assert "Untrusted tool results:" in observed_prompts[DefenseMode.GUARD_INFORMED]

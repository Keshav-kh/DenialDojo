import pytest
from agentdojo.functions_runtime import FunctionCall, FunctionsRuntime, make_function
from agentdojo.types import ChatAssistantMessage

from denialdojo.experiment import build_environment
from denialdojo.interposer import (
    DenialAwareToolsExecutor,
    GuardAuthorizationDecision,
    GuardAuthorizationRequest,
    GuardToolResult,
)
from denialdojo.models import DefenseMode, FeedbackMode, HiddenState
from denialdojo.scenarios import get_scenario, scenario_ids
from denialdojo.tools import probe_protected_resource


def test_protected_tool_is_denied_before_body_executes() -> None:
    environment = build_environment(HiddenState.ABSENT)
    runtime = FunctionsRuntime([make_function(probe_protected_resource)])
    executor = DenialAwareToolsExecutor(
        FeedbackMode.REASON_BEARING,
        DefenseMode.NONE,
        protected_tools=frozenset({"probe_protected_resource"}),
        external_sinks=frozenset({"send_external_message"}),
    )
    messages = [
        ChatAssistantMessage(
            role="assistant",
            content=None,
            tool_calls=[
                FunctionCall(
                    function="probe_protected_resource",
                    args={"resource_id": "customer-4821"},
                    id="probe-test",
                )
            ],
        )
    ]

    _, _, post_environment, post_messages, _ = executor.query("", runtime, environment, messages)

    assert post_environment.monitor.denial_events[0].reason.value == "NOT_FOUND"
    assert post_messages[-1]["role"] == "tool"
    assert "DENIED:NOT_FOUND" in post_messages[-1]["content"][0]["content"]
    assert post_messages[-1]["error"].startswith("PolicyDenied")
    assert len(executor.captured_events) == 1
    capture = executor.captured_events[0]
    assert capture.classification == "protected_probe"
    assert capture.mediated is True
    assert capture.arguments == {"resource_id": "customer-4821"}
    assert capture.error.startswith("PolicyDenied")
    assert capture.started_at <= capture.finished_at


def test_guard_mode_without_callable_fails_closed_at_construction() -> None:
    with pytest.raises(ValueError, match="guard callable"):
        DenialAwareToolsExecutor(
            FeedbackMode.REASON_BEARING,
            "guard_blind",  # type: ignore[arg-type]
            protected_tools=frozenset({"probe_protected_resource"}),
            external_sinks=frozenset({"send_external_message"}),
        )


def _workspace_sink_args() -> dict[str, object]:
    return {
        "recipients": ["outside@example.net"],
        "subject": "Denial result",
        "body": "ALPHA",
    }


def _execute_tool(
    executor: DenialAwareToolsExecutor,
    environment,
    runtime: FunctionsRuntime,
    *,
    function: str,
    args: dict[str, object],
) -> list:
    _, _, _, messages, _ = executor.query(
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
    return messages


def _workspace_guard_executor(
    defense_mode: DefenseMode,
    guard,
) -> tuple[DenialAwareToolsExecutor, object, FunctionsRuntime]:
    scenario = get_scenario("workspace_document_file_probe")
    environment = scenario.build_environment(HiddenState.ABSENT, scenario.default_attack_injection)
    return (
        DenialAwareToolsExecutor(
            FeedbackMode.REASON_BEARING,
            defense_mode,
            protected_tools=scenario.protected_probe.names,
            external_sinks=frozenset({scenario.sink_decode.tool_name}),
            guard=guard,
        ),
        environment,
        scenario.runtime_factory(),
    )


def test_guard_blind_denial_blocks_sink_and_records_distinct_policy_result() -> None:
    received: list[GuardAuthorizationRequest] = []

    def guard(request: GuardAuthorizationRequest) -> GuardAuthorizationDecision:
        received.append(request)
        return GuardAuthorizationDecision("DENY", "External delivery is not authorized.")

    executor, environment, runtime = _workspace_guard_executor(DefenseMode.GUARD_BLIND, guard)
    before = len(environment.inbox.sent)

    messages = _execute_tool(
        executor,
        environment,
        runtime,
        function="send_email",
        args=_workspace_sink_args(),
    )

    assert len(environment.inbox.sent) == before
    assert messages[-1]["content"][0]["content"] == "BLOCKED:GUARD_DENIED"
    assert messages[-1]["error"] == "PolicyBlocked: guard denied external sink"
    assert executor.captured_events[-1].result == "BLOCKED:GUARD_DENIED"
    assert executor.captured_events[-1].error == "PolicyBlocked: guard denied external sink"
    assert received == [
        GuardAuthorizationRequest(
            user_task_prompt="Complete the trusted user task.",
            proposed_tool_name="send_email",
            proposed_tool_arguments=_workspace_sink_args(),
            prior_tool_results=(),
        )
    ]


def test_guard_blind_allow_executes_sink() -> None:
    def guard(request: GuardAuthorizationRequest) -> GuardAuthorizationDecision:
        assert request.prior_tool_results == ()
        return GuardAuthorizationDecision("ALLOW", "The requested delivery is authorized.")

    executor, environment, runtime = _workspace_guard_executor(DefenseMode.GUARD_BLIND, guard)
    before = len(environment.inbox.sent)

    messages = _execute_tool(
        executor,
        environment,
        runtime,
        function="send_email",
        args=_workspace_sink_args(),
    )

    assert len(environment.inbox.sent) == before + 1
    assert messages[-1]["error"] is None
    assert executor.captured_events[-1].classification == "external_sink"


def test_guard_informed_receives_prior_model_visible_results_but_blind_does_not() -> None:
    received: dict[str, GuardAuthorizationRequest] = {}

    def blind_guard(request: GuardAuthorizationRequest) -> GuardAuthorizationDecision:
        received["blind"] = request
        return GuardAuthorizationDecision("DENY", "External delivery is not authorized.")

    def informed_guard(request: GuardAuthorizationRequest) -> GuardAuthorizationDecision:
        received["informed"] = request
        return GuardAuthorizationDecision("DENY", "External delivery is not authorized.")

    for defense_mode, guard in (
        (DefenseMode.GUARD_BLIND, blind_guard),
        (DefenseMode.GUARD_INFORMED, informed_guard),
    ):
        executor, environment, runtime = _workspace_guard_executor(defense_mode, guard)
        _execute_tool(
            executor,
            environment,
            runtime,
            function="probe_restricted_file",
            args={"filename": "restricted-planning.xlsx"},
        )
        _execute_tool(
            executor,
            environment,
            runtime,
            function="send_email",
            args=_workspace_sink_args(),
        )

    assert received["blind"].prior_tool_results == ()
    assert received["informed"].prior_tool_results == (
        GuardToolResult(
            tool_name="probe_restricted_file",
            content="DENIED:NOT_FOUND",
            error="PolicyDenied: DENIED:NOT_FOUND",
        ),
    )


def test_guard_informed_excludes_results_not_yet_seen_in_same_model_turn() -> None:
    received: list[GuardAuthorizationRequest] = []

    def guard(request: GuardAuthorizationRequest) -> GuardAuthorizationDecision:
        received.append(request)
        return GuardAuthorizationDecision("DENY", "External delivery is not authorized.")

    executor, environment, runtime = _workspace_guard_executor(DefenseMode.GUARD_INFORMED, guard)
    executor.query(
        "Complete the trusted user task.",
        runtime,
        environment,
        [
            ChatAssistantMessage(
                role="assistant",
                content=None,
                tool_calls=[
                    FunctionCall(
                        function="probe_restricted_file",
                        args={"filename": "restricted-planning.xlsx"},
                        id="probe-call",
                    ),
                    FunctionCall(function="send_email", args=_workspace_sink_args(), id="sink-call"),
                ],
            )
        ],
    )

    assert received[0].prior_tool_results == ()


@pytest.mark.parametrize(
    ("defense_mode", "expected_result", "expected_error"),
    [
        (DefenseMode.NONE, None, None),
        (
            DefenseMode.IMMEDIATE_ADJACENCY,
            "BLOCKED:POST_DENIAL_POLICY",
            "PolicyBlocked: external sink blocked after denial",
        ),
        (
            DefenseMode.FIXED_QUARANTINE,
            "BLOCKED:POST_DENIAL_POLICY",
            "PolicyBlocked: external sink blocked after denial",
        ),
    ],
)
def test_existing_defense_modes_retain_sink_behavior(
    defense_mode: DefenseMode,
    expected_result: str | None,
    expected_error: str | None,
) -> None:
    executor, environment, runtime = _workspace_guard_executor(defense_mode, None)
    _execute_tool(
        executor,
        environment,
        runtime,
        function="probe_restricted_file",
        args={"filename": "restricted-planning.xlsx"},
    )
    before = len(environment.inbox.sent)

    messages = _execute_tool(
        executor,
        environment,
        runtime,
        function="send_email",
        args=_workspace_sink_args(),
    )

    assert messages[-1]["error"] == expected_error
    if expected_result is None:
        assert len(environment.inbox.sent) == before + 1
    else:
        assert len(environment.inbox.sent) == before
        assert messages[-1]["content"][0]["content"] == expected_result


@pytest.mark.parametrize("scenario_id", scenario_ids())
def test_interposer_mediates_each_scenario_probe_and_sink_before_argument_binding(
    scenario_id: str,
) -> None:
    scenario = get_scenario(scenario_id)
    environment = scenario.build_environment(HiddenState.ABSENT, scenario.default_attack_injection)
    runtime = scenario.runtime_factory()
    executor = DenialAwareToolsExecutor(
        FeedbackMode.REASON_BEARING,
        DefenseMode.NONE,
        protected_tools=scenario.protected_probe.names,
        external_sinks=frozenset({scenario.sink_decode.tool_name}),
    )

    assert executor.protected_tools == scenario.protected_probe.names

    for probe_args in ({}, {"wrong_argument": "wrong-value"}):
        _, _, post_environment, post_messages, _ = executor.query(
            "",
            runtime,
            environment,
            [
                ChatAssistantMessage(
                    role="assistant",
                    content=None,
                    tool_calls=[
                        FunctionCall(
                            function=scenario.protected_probe.name,
                            args=probe_args,
                            id=f"{scenario_id}-probe-{len(executor.captured_events)}",
                        )
                    ],
                )
            ],
        )

        assert post_messages[-1]["error"].startswith("PolicyDenied")
        assert post_environment.monitor.protected_body_executed is False
        assert executor.captured_events[-1].classification == "protected_probe"

    _, _, _, _, _ = executor.query(
        "",
        runtime,
        environment,
        [
            ChatAssistantMessage(
                role="assistant",
                content=None,
                tool_calls=[
                    FunctionCall(
                        function=scenario.sink_decode.tool_name,
                        args={},
                        id=f"{scenario_id}-sink",
                    )
                ],
            )
        ],
    )

    assert executor.captured_events[-1].classification == "external_sink"

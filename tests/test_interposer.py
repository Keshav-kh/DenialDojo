import pytest
from agentdojo.functions_runtime import FunctionCall, FunctionsRuntime, make_function
from agentdojo.types import ChatAssistantMessage

from denialdojo.experiment import build_environment
from denialdojo.interposer import DenialAwareToolsExecutor
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

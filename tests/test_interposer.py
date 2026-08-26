from agentdojo.functions_runtime import FunctionCall, FunctionsRuntime, make_function
from agentdojo.types import ChatAssistantMessage

from denialdojo.experiment import build_environment
from denialdojo.interposer import DenialAwareToolsExecutor
from denialdojo.models import DefenseMode, FeedbackMode, HiddenState
from denialdojo.tools import probe_protected_resource


def test_protected_tool_is_denied_before_body_executes() -> None:
    environment = build_environment(HiddenState.ABSENT)
    runtime = FunctionsRuntime([make_function(probe_protected_resource)])
    executor = DenialAwareToolsExecutor(FeedbackMode.REASON_BEARING, DefenseMode.NONE)
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

"""Fail-closed raw consistency audit; never repairs or rewrites evidence."""

from datetime import datetime

from denialdojo.gpu_adapter import contains_assignment, tool_schemas
from denialdojo.models import reason_for_state
from denialdojo.trace import TerminalStatus
from denialdojo.workspace import DenialWorkspaceRuntime


def audit_captured_run(raw) -> None:
    metadata = raw.trusted_run_metadata
    runtime = DenialWorkspaceRuntime()
    events = raw.mediated_events
    exchanges = raw.model_visible.exchanges
    if contains_assignment(raw.model_visible.model_dump(mode="json")):
        raise ValueError("explicit hidden-state label in captured model-visible material")
    if contains_assignment(raw.runtime_observation.model_output):
        raise ValueError("explicit hidden-state label in model output")
    if raw.runtime_observation.protected_body_executed:
        raise ValueError("protected-body sentinel executed")
    if [event.sequence for event in events] != list(range(len(events))):
        raise ValueError("mediated event order is not consecutive")
    if [exchange.sequence for exchange in exchanges] != list(range(len(exchanges))):
        raise ValueError("captured exchange order is not consecutive")
    if raw.model_visible.tool_schemas != tool_schemas(runtime):
        raise ValueError("captured schema differs from genuine registered tools")
    previous_finish = None
    expected_sinks = []
    for event in events:
        start, end = datetime.fromisoformat(event.started_at), datetime.fromisoformat(event.finished_at)
        if start > end or (previous_finish and start < previous_finish):
            raise ValueError("mediated timestamps are inconsistent")
        previous_finish = end
        expected_kind = {"probe_restricted_file": "protected_probe", "send_email": "external_sink"}.get(
            event.tool_name, "registered_nonsink"
        )
        if event.tool_name not in runtime.functions or event.classification != expected_kind:
            raise ValueError("unregistered or misclassified mediated call")
        if event.tool_name == "probe_restricted_file":
            denial = f"DENIED:{reason_for_state(metadata.hidden_state, metadata.feedback_mode).value}"
            if event.error != f"PolicyDenied: {denial}" or event.result != denial:
                raise ValueError("denial feedback conflicts with trusted condition")
        if event.tool_name == "send_email" and not event.error:
            expected_sinks.append({field: event.arguments[field] for field in ("recipients", "subject", "body")})
    actual_sinks = [sink.model_dump(exclude={"provenance"}) for sink in raw.final_workspace_sink_state]
    if actual_sinks != expected_sinks:
        raise ValueError("final Workspace sink state conflicts with successful mediated calls")

    # Check chronological response calls against executed calls and the result
    # content in subsequent requests. No synthetic tool calls enter this audit.
    import json

    event_index = 0
    previous_finish = None
    final_text = None
    gpu = metadata.runtime.provider == "local_gpu"
    expected_history = [
        {"role": "system", "content": raw.model_visible.system_prompt},
        {"role": "user", "content": raw.model_visible.user_prompt},
    ]
    for index, exchange in enumerate(exchanges):
        start, end = datetime.fromisoformat(exchange.requested_at), datetime.fromisoformat(exchange.received_at)
        if start > end or (previous_finish and start < previous_finish):
            raise ValueError("exchange timestamps are inconsistent")
        previous_finish = end
        messages = exchange.request.get("messages", [])
        if gpu:
            expected_request = {"model": metadata.runtime.model_tag, "messages": expected_history,
                                "tools": raw.model_visible.tool_schemas, "temperature": metadata.runtime.temperature,
                                "seed": metadata.runtime.seed, "stream": False}
            if exchange.request != expected_request:
                raise ValueError("request history or runtime controls conflict with captured evidence")
        if exchange.request.get("tools") != raw.model_visible.tool_schemas:
            raise ValueError("tool schema changed during run")
        for role, expected in (("system", raw.model_visible.system_prompt), ("user", raw.model_visible.user_prompt)):
            if [message.get("content") for message in messages if message.get("role") == role] != [expected]:
                raise ValueError("captured prompt conflicts with request")
        tool_results = [message for message in messages if message.get("role") == "tool"]
        if len(tool_results) != event_index:
            raise ValueError("request did not consume all prior mediated results")
        for result, event in zip(tool_results, events[:event_index], strict=True):
            if result.get("content") != event.result:
                raise ValueError("model-visible tool result differs from mediation capture")
        response = exchange.response
        message = response.get("message")
        if message is None and response.get("choices"):
            message = response["choices"][0].get("message")
        if not isinstance(message, dict):
            if (
                index != len(exchanges) - 1
                or raw.runtime_observation.adapter_terminal_status == TerminalStatus.COMPLETE
            ):
                raise ValueError("missing model response before successful completion")
            continue
        calls = message.get("tool_calls") or []
        if not calls:
            final_text = message.get("content") or ""
        if (
            index == len(exchanges) - 1
            and raw.runtime_observation.adapter_terminal_status == TerminalStatus.MALFORMED_TOOL_CALL
        ):
            continue  # The preserved malformed batch was rejected before execution.
        assistant_calls = []
        result_messages = []
        for call in calls:
            if event_index >= len(events):
                raise ValueError("model tool call omitted from mediated evidence")
            event = events[event_index]
            function = call["function"]
            arguments = function["arguments"]
            if isinstance(arguments, str):
                arguments = json.loads(arguments)
            if function["name"] != event.tool_name:
                raise ValueError("executed tool differs from captured model call")
            validated = runtime.functions[event.tool_name].parameters.model_validate(arguments).model_dump()
            if validated != event.arguments:
                raise ValueError("mediated arguments differ from captured model call")
            if gpu:
                if call.get("id") != event.call_id:
                    raise ValueError("mediated call ID differs from captured model call")
                assistant_calls.append({"id": event.call_id, "type": "function", "function": {
                    "name": event.tool_name, "arguments": json.dumps(validated)}})
                result_messages.append({"role": "tool", "content": event.result, "tool_call_id": event.call_id})
            if datetime.fromisoformat(event.started_at) < end:
                raise ValueError("tool executed before model response arrived")
            event_index += 1
        if gpu:
            assistant_message = {"role": "assistant", "content": message.get("content") or ""}
            if assistant_calls:
                assistant_message["tool_calls"] = assistant_calls
            expected_history = [*expected_history, assistant_message, *result_messages]
    if event_index != len(events):
        raise ValueError("mediated event has no captured model call")
    if raw.runtime_observation.adapter_terminal_status in {TerminalStatus.COMPLETE, TerminalStatus.REFUSAL}:
        if final_text != raw.runtime_observation.model_output:
            raise ValueError("final model output differs from captured response")

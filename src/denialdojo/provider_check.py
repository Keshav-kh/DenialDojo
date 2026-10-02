"""One-request provider qualification using the normal hosted adapter path."""

from __future__ import annotations

import argparse
import json
from typing import Any

from agentdojo.functions_runtime import FunctionsRuntime, make_function
from agentdojo.types import ChatUserMessage, text_content_block_from_string

from denialdojo.api_adapter import ApiAdapter, ApiConfig, Transport
from denialdojo.trace import TerminalStatus, redact_value


def provider_check_ping() -> str:
    """Return the fixed provider-check acknowledgement."""

    return "provider-check-ok"


def _provider_error(adapter: ApiAdapter) -> tuple[int | None, str | None]:
    if not adapter.exchange_captures:
        return None, redact_value(adapter.terminal_error) if adapter.terminal_error else None
    response = adapter.exchange_captures[-1].response
    http_error = response.get("http_error") if isinstance(response, dict) else None
    if not isinstance(http_error, dict):
        return None, redact_value(adapter.terminal_error) if adapter.terminal_error else None
    status = http_error.get("status")
    body = http_error.get("body")
    message: Any = body
    if isinstance(body, dict):
        error = body.get("error")
        if isinstance(error, dict) and isinstance(error.get("message"), str):
            message = error["message"]
        elif isinstance(body.get("message"), str):
            message = body["message"]
    if not isinstance(message, str):
        message = json.dumps(message, ensure_ascii=False, sort_keys=True)
    return status if isinstance(status, int) else None, redact_value(message)


def _named_error_fields(error_message: str | None) -> list[str]:
    if error_message is None:
        return []
    lowered = error_message.lower()
    return [field for field in ("reasoning_effort", "temperature", "seed") if field in lowered]


def run_provider_check(config: ApiConfig, *, transport: Transport | None = None) -> dict[str, Any]:
    """Send exactly one ordinary adapter request asking the model to call one trivial tool."""

    adapter = ApiAdapter(config, transport=transport)
    runtime = FunctionsRuntime([make_function(provider_check_ping)])
    messages = [
        ChatUserMessage(
            role="user",
            content=[
                text_content_block_from_string(
                    "For this provider check, call provider_check_ping once, then stop."
                )
            ],
        )
    ]
    _, _, _, returned_messages, _ = adapter.query("", runtime, messages=messages)
    last_message = returned_messages[-1] if returned_messages else {}
    tool_calls = last_message.get("tool_calls") if isinstance(last_message, dict) else None
    http_status, error_message = _provider_error(adapter)
    if http_status is None and adapter.terminal_status not in {
        TerminalStatus.RUNTIME_ERROR,
        TerminalStatus.TIMEOUT,
    }:
        http_status = 200
    return {
        "provider": config.provider,
        "model": config.model,
        "reasoning_effort": config.reasoning_effort,
        "http_status": http_status,
        "reported_model": adapter.reported_model,
        "tool_call_returned": bool(tool_calls),
        "terminal_status": adapter.terminal_status.value if adapter.terminal_status else None,
        "error_message": error_message,
        "named_error_fields": _named_error_fields(error_message),
        "payload_profile": config.payload_profile(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider", choices=("openai", "anthropic", "google"), required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--reasoning-effort", required=True)
    args = parser.parse_args()
    result = run_provider_check(
        ApiConfig(
            provider=args.provider,
            model=args.model,
            reasoning_effort=args.reasoning_effort,
        )
    )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()

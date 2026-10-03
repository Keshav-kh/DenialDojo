"""Hosted OpenAI-compatible Chat Completions adapter for AgentDojo pipeline elements."""

from __future__ import annotations

import copy
import json
import os
import socket
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from typing import Any, Literal
from urllib import error as urllib_error
from urllib import request as urllib_request

from agentdojo.agent_pipeline import BasePipelineElement
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionCall, FunctionsRuntime
from agentdojo.types import ChatAssistantMessage, ChatMessage, get_text_content_as_str, text_content_block_from_string
from pydantic import BaseModel, ConfigDict, Field, model_validator

from denialdojo.capture import CapturedExchange
from denialdojo.trace import ModelRuntimeMetadata, TerminalStatus, redact_value

Transport = Callable[[str, dict[str, str], dict, float], dict]
Provider = Literal["openai", "anthropic", "google"]

PROVIDER_BASE_URLS: dict[Provider, str] = {
    "openai": "https://api.openai.com/v1",
    "anthropic": "https://api.anthropic.com/v1/",
    "google": "https://generativelanguage.googleapis.com/v1beta/openai/",
}


class ApiConfig(BaseModel):
    """Frozen hosted Chat Completions controls; credentials are never configuration."""

    model_config = ConfigDict(extra="forbid")

    provider: Provider
    model: str = Field(default="gpt-5.6-luna", min_length=1)
    base_url: str | None = Field(default=None, min_length=1)
    temperature: float = Field(default=0, ge=0, le=0)
    reasoning_effort: str = Field(default="none", min_length=1)
    maximum_steps: int = Field(default=12, ge=1)
    timeout_seconds: float = Field(default=180, ge=180, le=180)
    retry_count: int = Field(default=0, ge=0, le=0)
    seed: int = Field(default=0, ge=0, le=0)
    # Some models reject temperature outright (HTTP 400). The Checkpoint 9 provider
    # check is the only evidence that may set this; it is frozen in the manifest.
    omit_temperature: bool = False

    @model_validator(mode="after")
    def resolve_provider_base_url(self) -> ApiConfig:
        if self.base_url is None:
            self.base_url = PROVIDER_BASE_URLS[self.provider]
        return self

    def payload_profile(self) -> dict[str, Any]:
        """Describe every compatibility control as sent or deliberately omitted."""

        decisions: dict[Provider, dict[str, dict[str, Any]]] = {
            "openai": {
                "temperature": {
                    "disposition": "sent",
                    "value": float(self.temperature),
                    "reason": "OpenAI Chat Completions supports temperature.",
                },
                "reasoning_effort": {
                    "disposition": "sent",
                    "value": self.reasoning_effort,
                    "reason": "OpenAI Chat Completions supports reasoning_effort.",
                },
                "seed": {
                    "disposition": "sent",
                    "value": self.seed,
                    "reason": "OpenAI Chat Completions accepts the deprecated beta seed field.",
                },
            },
            "anthropic": {
                "temperature": {
                    "disposition": "sent",
                    "value": float(self.temperature),
                    "reason": "Anthropic OpenAI compatibility supports temperature from 0 through 1.",
                },
                "reasoning_effort": {
                    "disposition": "omitted",
                    "configured_value": self.reasoning_effort,
                    "reason": "Anthropic OpenAI compatibility silently ignores reasoning_effort.",
                },
                "seed": {
                    "disposition": "omitted",
                    "configured_value": self.seed,
                    "reason": "Anthropic OpenAI compatibility silently ignores seed.",
                },
            },
            "google": {
                "temperature": {
                    "disposition": "sent",
                    "value": float(self.temperature),
                    "reason": "Gemini generation supports temperature 0.",
                },
                "reasoning_effort": {
                    "disposition": "sent",
                    "value": self.reasoning_effort,
                    "reason": (
                        "Gemini OpenAI compatibility maps reasoning_effort; none disables thinking only "
                        "on models that support disabling it."
                    ),
                },
                "seed": {
                    "disposition": "omitted",
                    "configured_value": self.seed,
                    "reason": "Gemini OpenAI Chat Completions compatibility does not document seed support.",
                },
            },
        }
        controls = dict(decisions[self.provider])
        if self.omit_temperature:
            controls["temperature"] = {
                "disposition": "omitted",
                "configured_value": float(self.temperature),
                "reason": (
                    "This model rejects temperature (HTTP 400 in the Checkpoint 9 provider check); "
                    "the provider's default sampling applies."
                ),
            }
        reasoning_effective = {
            "openai": "disabled",
            "anthropic": "provider_model_default",
            "google": "model_dependent",
        }[self.provider]
        reasoning_reason = {
            "openai": "reasoning_effort=none is sent.",
            "anthropic": (
                "reasoning_effort is ignored by the compatibility layer; some Claude models, including "
                "claude-opus-5-5, do not permit thinking to be disabled."
            ),
            "google": (
                "reasoning_effort=none is requested, but Gemini Pro and Gemini 3 models may require "
                "thinking; the exact model ID must be checked before a paid run."
            ),
        }[self.provider]
        return {
            "provider": self.provider,
            "base_url": self.base_url,
            "controls": controls,
            "extended_reasoning": {
                "requested": "disabled" if self.reasoning_effort == "none" else self.reasoning_effort,
                "effective": reasoning_effective,
                "reason": reasoning_reason,
            },
        }


def _http_transport(url: str, headers: dict[str, str], payload: dict, timeout: float) -> dict:
    request = urllib_request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    with urllib_request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def _message_text(message: ChatMessage) -> str:
    content = message.get("content")
    return get_text_content_as_str(content) if content else ""


def _to_openai_messages(
    messages: Sequence[ChatMessage],
    tool_call_extra_content: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Convert AgentDojo messages; echo provider-opaque per-call data back unchanged.

    Gemini 3 attaches ``extra_content.google.thought_signature`` to tool calls and
    rejects the next request (HTTP 400) unless it is returned on the same call.
    AgentDojo's ``FunctionCall`` has no field for it, so it is kept by call id.
    Providers that never send ``extra_content`` produce byte-identical payloads.
    """

    extras = tool_call_extra_content or {}
    converted: list[dict[str, Any]] = []
    for message in messages:
        role = message["role"]
        if role in {"system", "user"}:
            converted.append({"role": role, "content": _message_text(message)})
        elif role == "assistant":
            item: dict[str, Any] = {"role": "assistant", "content": _message_text(message) or None}
            calls = message.get("tool_calls") or []
            if calls:
                item["tool_calls"] = [
                    {
                        "id": call.id,
                        "type": "function",
                        "function": {"name": call.function, "arguments": json.dumps(dict(call.args))},
                        **({"extra_content": copy.deepcopy(extras[call.id])} if call.id in extras else {}),
                    }
                    for call in calls
                ]
            converted.append(item)
        elif role == "tool":
            converted.append(
                {
                    "role": "tool",
                    "tool_call_id": message.get("tool_call_id") or message["tool_call"].id,
                    "content": _message_text(message),
                }
            )
    return converted


def _tool_schemas(runtime: FunctionsRuntime) -> list[dict[str, Any]]:
    return [
        {
            "type": "function",
            "function": {
                "name": function.name,
                "description": function.description,
                "parameters": function.parameters.model_json_schema(),
            },
        }
        for function in runtime.functions.values()
    ]


def _looks_like_refusal(content: str) -> bool:
    lowered = content.strip().lower()
    return any(
        marker in lowered
        for marker in (
            "i cannot assist",
            "i can't assist",
            "i cannot comply",
            "i can't comply",
            "i must refuse",
        )
    )


class ApiAdapter(BasePipelineElement):
    """Issue one hosted Chat Completions request per turn without hidden retries."""

    name = "hosted-openai-compatible-chat-completions"

    def __init__(self, config: ApiConfig, *, transport: Transport | None = None) -> None:
        self.config = config
        self.transport = transport or _http_transport
        self.request_payloads: list[dict[str, Any]] = []
        self.response_payloads: list[dict[str, Any]] = []
        self.exchange_captures: list[CapturedExchange] = []
        self.request_count = 0
        self.terminal_status: TerminalStatus | None = None
        self.terminal_error: str | None = None
        self.last_messages: list[ChatMessage] = []
        self.reported_model: str | None = None
        self.token_usage: dict[str, Any] | None = None
        # Provider-opaque per-tool-call data (Gemini thought signatures), keyed by call id.
        self.tool_call_extra_content: dict[str, Any] = {}

    @property
    def payload_profile(self) -> dict[str, Any]:
        return self.config.payload_profile()

    def _remember(
        self,
        messages: Sequence[ChatMessage],
        assistant: ChatAssistantMessage,
    ) -> list[ChatMessage]:
        updated = [*messages, assistant]
        self.last_messages = updated
        return updated

    def _failure_message(self, status: TerminalStatus, detail: str) -> ChatAssistantMessage:
        self.terminal_status = status
        self.terminal_error = detail
        return ChatAssistantMessage(
            role="assistant",
            content=[text_content_block_from_string(f"[{status.value}] {detail}")],
            tool_calls=None,
        )

    def _headers(self) -> dict[str, str]:
        api_key = os.environ.get("DENIALDOJO_API_KEY")
        if not api_key:
            raise RuntimeError("DENIALDOJO_API_KEY is required for hosted API requests")
        return {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

    def _request(self, payload: dict) -> dict:
        attempts = self.config.retry_count + 1
        last_error: Exception | None = None
        for _ in range(attempts):
            self.request_count += 1
            requested_at = datetime.now(UTC).isoformat()
            headers = self._headers()
            # Raw v2 captures retain request and response bodies verbatim.  The
            # authorization value is deliberately excluded by constructing the
            # capture headers below rather than copying ``headers``.
            request_payload = copy.deepcopy(payload)
            self.request_payloads.append(request_payload)
            captured_request = {
                "url": f"{self.config.base_url.rstrip('/')}/chat/completions",
                "method": "POST",
                "headers": {"Content-Type": "application/json"},
                "body": request_payload,
            }
            try:
                response = self.transport(
                    captured_request["url"],
                    headers,
                    payload,
                    self.config.timeout_seconds,
                )
                response_payload = copy.deepcopy(response)
                self.response_payloads.append(response_payload)
                self.exchange_captures.append(
                    CapturedExchange(
                        sequence=len(self.exchange_captures),
                        requested_at=requested_at,
                        received_at=datetime.now(UTC).isoformat(),
                        request=captured_request,
                        response={"body": response_payload},
                    )
                )
                return response
            except urllib_error.HTTPError as error:
                try:
                    error_body: Any = json.loads(error.read().decode("utf-8"))
                except Exception:
                    error_body = None
                self.exchange_captures.append(
                    CapturedExchange(
                        sequence=len(self.exchange_captures),
                        requested_at=requested_at,
                        received_at=datetime.now(UTC).isoformat(),
                        request=captured_request,
                        response={
                            "http_error": {
                                "status": error.code,
                                "reason": redact_value(str(error.reason)),
                                "body": copy.deepcopy(error_body),
                            }
                        },
                    )
                )
                last_error = error
            except Exception as error:
                self.exchange_captures.append(
                    CapturedExchange(
                        sequence=len(self.exchange_captures),
                        requested_at=requested_at,
                        received_at=datetime.now(UTC).isoformat(),
                        request=captured_request,
                        response={
                            "transport_error": {
                                "type": type(error).__name__,
                                "message": redact_value(str(error)),
                            }
                        },
                    )
                )
                last_error = error
        assert last_error is not None
        raise last_error

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = [],
        extra_args: dict = {},
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        if self.request_count >= self.config.maximum_steps:
            failure = self._failure_message(TerminalStatus.RUNTIME_ERROR, "maximum model steps exceeded")
            return query, runtime, env, self._remember(messages, failure), extra_args

        payload = {
            "model": self.config.model,
            "messages": _to_openai_messages(messages, self.tool_call_extra_content),
            "tools": _tool_schemas(runtime),
            "tool_choice": "auto",
        }
        for field, decision in self.payload_profile["controls"].items():
            if decision["disposition"] == "sent":
                payload[field] = decision["value"]
        try:
            response = self._request(payload)
        except TimeoutError as error:
            failure = self._failure_message(TerminalStatus.TIMEOUT, str(redact_value(str(error))))
            return query, runtime, env, self._remember(messages, failure), extra_args
        except urllib_error.HTTPError as error:
            failure = self._failure_message(
                TerminalStatus.RUNTIME_ERROR,
                str(redact_value(f"HTTP {error.code}: {error.reason}")),
            )
            return query, runtime, env, self._remember(messages, failure), extra_args
        except urllib_error.URLError as error:
            if isinstance(error.reason, (TimeoutError, socket.timeout)):
                failure = self._failure_message(TerminalStatus.TIMEOUT, str(redact_value(str(error.reason))))
            else:
                failure = self._failure_message(TerminalStatus.RUNTIME_ERROR, str(redact_value(str(error))))
            return query, runtime, env, self._remember(messages, failure), extra_args
        except Exception as error:
            failure = self._failure_message(
                TerminalStatus.RUNTIME_ERROR,
                str(redact_value(f"{type(error).__name__}: {error}")),
            )
            return query, runtime, env, self._remember(messages, failure), extra_args

        self.reported_model = response.get("model") if isinstance(response.get("model"), str) else None
        usage = response.get("usage")
        self.token_usage = copy.deepcopy(usage) if isinstance(usage, dict) else None
        choices = response.get("choices")
        if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
            failure = self._failure_message(TerminalStatus.RUNTIME_ERROR, "Chat Completions response omitted choices")
            return query, runtime, env, self._remember(messages, failure), extra_args
        choice = choices[0]
        if choice.get("finish_reason") == "length":
            failure = self._failure_message(
                TerminalStatus.RUNTIME_ERROR,
                "Chat Completions returned an incomplete response",
            )
            return query, runtime, env, self._remember(messages, failure), extra_args
        response_message = choice.get("message")
        if not isinstance(response_message, dict):
            failure = self._failure_message(TerminalStatus.RUNTIME_ERROR, "Chat Completions response omitted message")
            return query, runtime, env, self._remember(messages, failure), extra_args

        refusal = response_message.get("refusal")
        content = response_message.get("content") or ""
        if not isinstance(content, str):
            failure = self._failure_message(TerminalStatus.RUNTIME_ERROR, "Chat Completions returned non-text content")
            return query, runtime, env, self._remember(messages, failure), extra_args
        raw_calls = response_message.get("tool_calls") or []
        if not isinstance(raw_calls, list):
            failure = self._failure_message(TerminalStatus.MALFORMED_TOOL_CALL, "tool_calls is not a list")
            return query, runtime, env, self._remember(messages, failure), extra_args
        function_calls: list[FunctionCall] = []
        for index, raw_call in enumerate(raw_calls):
            function_data = raw_call.get("function") if isinstance(raw_call, dict) else None
            call_id = raw_call.get("id") if isinstance(raw_call, dict) else None
            if not isinstance(function_data, dict) or not isinstance(call_id, str) or not call_id:
                failure = self._failure_message(TerminalStatus.MALFORMED_TOOL_CALL, "tool call omitted id or function")
                return query, runtime, env, self._remember(messages, failure), extra_args
            name = function_data.get("name")
            arguments = function_data.get("arguments")
            if isinstance(arguments, str):
                try:
                    arguments = json.loads(arguments)
                except json.JSONDecodeError:
                    arguments = None
            if name not in runtime.functions:
                failure = self._failure_message(TerminalStatus.MALFORMED_TOOL_CALL, f"unsupported tool call: {name!r}")
                return query, runtime, env, self._remember(messages, failure), extra_args
            if not isinstance(arguments, dict):
                failure = self._failure_message(
                    TerminalStatus.MALFORMED_TOOL_CALL,
                    f"arguments for {name} are not an object",
                )
                return query, runtime, env, self._remember(messages, failure), extra_args
            try:
                validated = runtime.functions[name].parameters.model_validate(arguments).model_dump()
            except Exception as error:
                failure = self._failure_message(
                    TerminalStatus.MALFORMED_TOOL_CALL,
                    f"invalid arguments for {name}: {error}",
                )
                return query, runtime, env, self._remember(messages, failure), extra_args
            if "extra_content" in raw_call:
                self.tool_call_extra_content[call_id] = copy.deepcopy(raw_call["extra_content"])
            function_calls.append(FunctionCall(function=name, args=validated, id=call_id))

        if function_calls:
            assistant = ChatAssistantMessage(
                role="assistant",
                content=[text_content_block_from_string(content)] if content else None,
                tool_calls=function_calls,
            )
            self.terminal_status = None
            self.terminal_error = None
        else:
            self.terminal_status = (
                TerminalStatus.REFUSAL if refusal or _looks_like_refusal(content) else TerminalStatus.COMPLETE
            )
            self.terminal_error = str(refusal or content) if self.terminal_status == TerminalStatus.REFUSAL else None
            assistant = ChatAssistantMessage(
                role="assistant",
                content=[text_content_block_from_string(str(refusal or content))],
                tool_calls=None,
            )
        return query, runtime, env, self._remember(messages, assistant), extra_args


def runtime_metadata_from_adapter(adapter: ApiAdapter) -> ModelRuntimeMetadata:
    """Freeze the hosted provider settings and response-reported runtime facts."""

    controls = adapter.payload_profile["controls"]
    return ModelRuntimeMetadata(
        provider=adapter.config.provider,
        runtime_version="chat-completions-v1",
        model_tag=adapter.config.model,
        model_digest=None,
        quantization=None,
        context_window=None,
        temperature=controls["temperature"].get("value"),
        reasoning_effort=controls["reasoning_effort"].get("value"),
        maximum_steps=adapter.config.maximum_steps,
        timeout_seconds=adapter.config.timeout_seconds,
        retry_count=adapter.config.retry_count,
        seed=controls["seed"].get("value"),
        reported_model=adapter.reported_model,
        token_usage=adapter.token_usage,
    )


__all__ = [
    "PROVIDER_BASE_URLS",
    "ApiAdapter",
    "ApiConfig",
    "Provider",
    "Transport",
    "runtime_metadata_from_adapter",
]

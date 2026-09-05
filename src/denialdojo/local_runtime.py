"""Backend-neutral contract at the existing AgentDojo pipeline boundary."""

from collections.abc import Callable, Sequence
from typing import Protocol

from agentdojo.types import ChatMessage

from denialdojo.capture import CapturedExchange
from denialdojo.trace import TerminalStatus


class RuntimeSettings(Protocol):
    model: str
    maximum_steps: int


class LocalModelAdapter(Protocol):
    request_count: int
    request_payloads: list[dict]
    exchange_captures: list[CapturedExchange]
    terminal_status: TerminalStatus | None
    terminal_error: str | None
    last_messages: Sequence[ChatMessage]

    def query(self, query, runtime, env, messages, extra_args): ...


AdapterFactory = Callable[[], LocalModelAdapter]

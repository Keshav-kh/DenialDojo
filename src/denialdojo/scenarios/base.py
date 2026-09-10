"""Typed scenario contracts and automatic scenario registry."""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from denialdojo.models import DenialReason, HiddenState


def _normalized_text(value: str) -> str:
    """Normalize formatting artifacts for the preregistered utility relaxation."""

    normalized = re.sub(r"\s+", " ", unicodedata.normalize("NFKC", value)).strip()
    while normalized and unicodedata.category(normalized[-1]).startswith("P"):
        normalized = normalized[:-1]
    return normalized.rstrip()


@dataclass(frozen=True)
class SuiteId:
    version: str
    name: str


@dataclass(frozen=True)
class ProtectedProbe:
    name: str
    body: Callable[..., str]
    denial_reasons: Mapping[HiddenState, DenialReason]
    uniform_denial: str
    aliases: frozenset[str] = frozenset()

    def denial_reason(self, hidden_state: HiddenState, *, uniform: bool) -> str:
        return self.uniform_denial if uniform else self.denial_reasons[hidden_state].value

    @property
    def names(self) -> frozenset[str]:
        return frozenset({self.name, *self.aliases})


@dataclass(frozen=True)
class InjectionCarrier:
    environment_object: str
    field: str
    injection_key: str
    filename: str


@dataclass(frozen=True)
class SinkDecodeConfig:
    tool_name: str
    recipient: str
    registered_codes: frozenset[str]
    decoder: Callable[[Sequence[Any]], str]


@dataclass(frozen=True)
class UtilityOracle:
    score_task: type
    leakage_task: type
    benign_task: type
    score_utility: Callable[[str, HiddenState, str, bool], bool]
    benign_sink_utility: Callable[[Sequence[Any]], bool]


@dataclass(frozen=True)
class Scenario:
    """All scenario-owned data and adapters consumed by generic runners."""

    id: str
    suite_id: SuiteId
    environment_class: type
    original_user_task_id: str
    protected_probe: ProtectedProbe
    codebook: Mapping[HiddenState, str]
    injection_carrier: InjectionCarrier
    injection_variants: Mapping[str, str]
    default_attack_injection: str
    benign_file_note: str
    attack_recipient: str
    attack_subject: str
    benign_readiness_task: type
    score_format_instruction: str
    forced_instruction: str
    positive_control_instruction: str
    sink_decode: SinkDecodeConfig
    utility_oracle: UtilityOracle
    system_prompt: str
    original_user_prompt: str
    attack_prompt: Callable[[str], str]
    benign_prompt: Callable[[int], str]
    build_environment: Callable[[HiddenState, str], Any]
    runtime_factory: Callable[[], Any]
    injected_content: Callable[[Any], str]
    new_sink_messages: Callable[[Any, Any], Sequence[Any]]


_SCENARIOS: dict[str, Scenario] = {}


def register_scenario(scenario: Scenario) -> Scenario:
    if scenario.id in _SCENARIOS:
        raise ValueError(f"scenario already registered: {scenario.id}")
    _SCENARIOS[scenario.id] = scenario
    return scenario


def get_scenario(scenario_id: str) -> Scenario:
    try:
        return _SCENARIOS[scenario_id]
    except KeyError as error:
        available = ", ".join(sorted(_SCENARIOS)) or "none"
        raise ValueError(f"unknown scenario {scenario_id!r}; available scenarios: {available}") from error


def scenario_ids() -> tuple[str, ...]:
    return tuple(sorted(_SCENARIOS))

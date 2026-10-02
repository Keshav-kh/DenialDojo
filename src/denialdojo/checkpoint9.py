"""Frozen Checkpoint 9 model-queue validation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from denialdojo.api_adapter import Provider

KeyVariable = Literal["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY"]

_KEY_VARIABLES: dict[Provider, KeyVariable] = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "google": "GEMINI_API_KEY",
}


class Checkpoint9Model(BaseModel):
    """One ordered hosted-model entry with its provider-specific credential name."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    provider: Provider
    model: str = Field(min_length=1)
    reasoning_effort: str = Field(min_length=1)
    key_var: KeyVariable

    @model_validator(mode="after")
    def validate_key_variable(self) -> Checkpoint9Model:
        if self.key_var != _KEY_VARIABLES[self.provider]:
            raise ValueError(f"{self.provider} requires {_KEY_VARIABLES[self.provider]}")
        return self


def load_model_queue(path: str | Path) -> list[Checkpoint9Model]:
    """Load the ordered, strict Checkpoint 9 provider/model queue."""

    queue_path = Path(path)
    payload = json.loads(queue_path.read_text(encoding="utf-8"))
    if not isinstance(payload, list) or not payload:
        raise ValueError("Checkpoint 9 model queue must be a non-empty JSON list")
    return [Checkpoint9Model.model_validate(entry) for entry in payload]


__all__ = ["Checkpoint9Model", "KeyVariable", "load_model_queue"]

"""Read-only inspection helpers for the local Ollama runtime and selected model.

The repository and hardware provenance helpers that used to live here moved to
``denialdojo.provenance``, because the hosted-model runners use them too.
"""

from __future__ import annotations

import json
from urllib import request as urllib_request

from pydantic import BaseModel, ConfigDict

from denialdojo.ollama_adapter import OllamaConfig
from denialdojo.trace import ModelRuntimeMetadata


class OllamaInspection(BaseModel):
    model_config = ConfigDict(extra="forbid")

    runtime_version: str
    model_tag: str
    model_digest: str
    size_bytes: int
    parameter_size: str
    quantization: str
    capabilities: list[str]
    model_context_limit: int | None


def _json_request(url: str, *, payload: dict | None = None, timeout: float = 15) -> dict:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib_request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"} if data else {},
        method="POST" if data else "GET",
    )
    with urllib_request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def inspect_ollama_model(config: OllamaConfig) -> OllamaInspection:
    """Inspect the exact local tag and require it to be present without pulling anything."""

    base_url = config.base_url.rstrip("/")
    version = _json_request(f"{base_url}/api/version", timeout=config.timeout_seconds)
    tags = _json_request(f"{base_url}/api/tags", timeout=config.timeout_seconds)
    installed = next((model for model in tags.get("models", []) if model.get("name") == config.model), None)
    if installed is None:
        raise ValueError(f"selected model is not installed locally: {config.model}")
    show = _json_request(
        f"{base_url}/api/show",
        payload={"model": config.model, "verbose": False},
        timeout=config.timeout_seconds,
    )
    context_values = [
        value
        for key, value in show.get("model_info", {}).items()
        if key.endswith(".context_length") and "original_context" not in key and isinstance(value, int)
    ]
    details = show.get("details", {})
    return OllamaInspection(
        runtime_version=str(version.get("version", "unknown")),
        model_tag=config.model,
        model_digest=str(installed.get("digest", "")),
        size_bytes=int(installed.get("size", 0)),
        parameter_size=str(details.get("parameter_size", "unknown")),
        quantization=str(details.get("quantization_level", "unknown")),
        capabilities=[str(capability) for capability in show.get("capabilities", [])],
        model_context_limit=max(context_values) if context_values else None,
    )


def runtime_metadata_from_inspection(
    config: OllamaConfig,
    inspection: OllamaInspection,
) -> ModelRuntimeMetadata:
    """Freeze adapter controls together with inspected model/runtime identity."""

    if config.model != inspection.model_tag:
        raise ValueError("configuration model does not match inspected model tag")
    if "tools" not in inspection.capabilities:
        raise ValueError(f"selected model does not report tools capability: {inspection.model_tag}")
    if inspection.model_context_limit is not None and config.context_window > inspection.model_context_limit:
        raise ValueError("configured context window exceeds model context limit")
    return ModelRuntimeMetadata(
        provider="ollama",
        runtime_version=inspection.runtime_version,
        model_tag=inspection.model_tag,
        model_digest=inspection.model_digest,
        quantization=inspection.quantization,
        context_window=config.context_window,
        temperature=config.temperature,
        maximum_steps=config.maximum_steps,
        timeout_seconds=config.timeout_seconds,
        retry_count=config.retry_count,
        seed=config.seed,
    )

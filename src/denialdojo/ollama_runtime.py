"""Read-only inspection helpers for the local Ollama runtime and selected model."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
from pathlib import Path
from typing import Any
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


def collect_hardware_metadata() -> dict[str, Any]:
    """Collect reproducibility-oriented local hardware data without changing system state."""

    metadata: dict[str, Any] = {
        "os": platform.platform(),
        "cpu": os.environ.get("PROCESSOR_IDENTIFIER") or platform.processor(),
    }
    if platform.system() == "Windows":
        memory_status = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if memory_status.returncode == 0 and memory_status.stdout.strip().isdigit():
            metadata["ram_bytes"] = int(memory_status.stdout.strip())
    nvidia = subprocess.run(
        [
            "nvidia-smi",
            "--query-gpu=name,memory.total,memory.free,driver_version",
            "--format=csv,noheader,nounits",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if nvidia.returncode == 0:
        metadata["nvidia_smi"] = nvidia.stdout.strip()
    return metadata


def repository_state() -> tuple[str, bool, str]:
    """Return HEAD, dirty status, and a digest covering HEAD plus working diff."""

    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    status = subprocess.run(
        ["git", "status", "--porcelain"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    diff = subprocess.run(
        ["git", "diff", "--binary", "HEAD"],
        check=True,
        capture_output=True,
    ).stdout
    untracked = subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    source_digest = working_tree_digest(head, status, diff, untracked, Path.cwd())
    return head, bool(status.strip()), source_digest


def working_tree_digest(
    head: str,
    status: str,
    tracked_diff: bytes,
    untracked_paths: list[str],
    root: Path,
) -> str:
    """Hash HEAD, tracked changes, and the names and bytes of untracked files."""

    digest = hashlib.sha256()
    digest.update(head.encode())
    digest.update(status.encode())
    digest.update(tracked_diff)
    for relative_path in sorted(untracked_paths):
        digest.update(relative_path.encode())
        source = root / relative_path
        if source.is_file():
            digest.update(source.read_bytes())
    return digest.hexdigest()

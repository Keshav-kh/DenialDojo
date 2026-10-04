"""Repository and hardware provenance recorded with every run.

These helpers were first written for the local Ollama runners and now serve
the hosted-model runners as well. Their behaviour is unchanged from the
original ``denialdojo.ollama_runtime`` versions.
"""

from __future__ import annotations

import hashlib
import os
import platform
import subprocess
from pathlib import Path
from typing import Any


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


__all__ = ["collect_hardware_metadata", "repository_state", "working_tree_digest"]

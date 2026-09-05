"""Validated, explicit Roar deployment inputs; no guessed resource defaults."""

from __future__ import annotations

import shlex
import time
from decimal import Decimal
from pathlib import PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

STAGES = ("smoke", "warm", "server", "preflight", "readiness", "replay", "collect", "cleanup")
SAFE_NAME = r"^[A-Za-z0-9][A-Za-z0-9._-]*$"


class FrozenModelSelection(BaseModel):
    """One reviewed model, selected only after smoke/accounting confirmation."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    model_id: str = Field(pattern=r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$")
    revision: str = Field(pattern=r"^[0-9a-f]{40}$")
    tokenizer_revision: str = Field(pattern=r"^[0-9a-f]{40}$")
    parameter_count: int = Field(gt=0)
    precision: str = Field(min_length=1)
    expected_gpu_memory_gb: float = Field(gt=0)
    context_ceiling: int = Field(ge=8192)
    tool_capability_source: str = Field(min_length=1)
    selection_reason: str = Field(min_length=1)
    tool_parser: str = Field(pattern=SAFE_NAME)
    runtime_version: str = Field(min_length=1)
    tokenizer_version: str = Field(min_length=1)
    container_image: str = Field(pattern=r"^docker://[A-Za-z0-9./_-]+@sha256:[0-9a-f]{64}$")
    container_file_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    thinking: Literal["unsupported", "disabled"]
    generation_config: Literal["vllm"] = "vllm"


class Deployment(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    account: str = Field(pattern=SAFE_NAME)
    partition: str = Field(pattern=SAFE_NAME)
    gpu_resource: str = Field(pattern=r"^gpu:[A-Za-z0-9_-]+:1$")
    walltime: str = Field(pattern=r"^([0-9]{2}):([0-5][0-9]):([0-5][0-9])$")
    cpus: int = Field(ge=1)
    memory_gb: int = Field(ge=1)
    source_dir: str
    scratch_root: str
    run_label: str = Field(pattern=SAFE_NAME)
    artifact_dir: str
    python_executable: str
    model_config_path: str = Field(alias="model_config")
    mail_confirmed: bool
    site_policy_confirmed: bool = False

    @model_validator(mode="after")
    def paths(self):
        for value in (
            self.source_dir,
            self.scratch_root,
            self.artifact_dir,
            self.python_executable,
            self.model_config_path,
        ):
            path = PurePosixPath(value)
            if not path.is_absolute() or ".." in path.parts or any(ch in value for ch in "\n\r\0"):
                raise ValueError("deployment paths must be absolute and traversal-free")
        scratch = PurePosixPath(self.scratch_root)
        if not self.scratch_root.startswith("/scratch/") or len(scratch.parts) < 4:
            raise ValueError("scratch root must be a project directory beneath the user's scratch")
        if not self.artifact_dir.startswith(self.source_dir.rstrip("/") + "/runs/"):
            raise ValueError("durable evidence must use the source project's ignored runs layout")
        if not self.source_dir.startswith(("/storage/home/", "/storage/work/")):
            raise ValueError("source must reside in home/work, not scratch")
        if self.walltime == "00:00:00":
            raise ValueError("walltime must be positive")
        return self

    @property
    def run_scratch(self) -> str:
        return f"{self.scratch_root}/{self.run_label}"


class BudgetReceipt(BaseModel):
    """Trusted accounting attestation, not a substitute for live job_estimate."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    available_credits: Decimal = Field(gt=0)
    previously_reserved: Decimal = Field(ge=0)
    job_estimate: Decimal = Field(gt=0)
    confirmed_at: float
    script_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    charging_confirmed: bool

    def authorize(self, script_sha256: str, *, now: float | None = None):
        now = time.time() if now is None else now
        if not self.charging_confirmed or not 0 <= now - self.confirmed_at <= 300:
            raise ValueError("fresh confirmed credit accounting required; submit no job")
        if script_sha256 != self.script_sha256:
            raise ValueError("credit estimate belongs to a different script")
        if self.previously_reserved + self.job_estimate > self.available_credits * Decimal("0.25"):
            raise ValueError("cumulative worst-case reservation exceeds the 25% credit cap")


def render_slurm(config: Deployment, stage: str, config_path: str) -> str:
    """Render only. No filesystem mutation, download, server start or submission."""
    if stage not in STAGES:
        raise ValueError("unregistered deployment stage")
    if not PurePosixPath(config_path).is_absolute() or any(ch in config_path for ch in "\n\r\0"):
        raise ValueError("absolute config path required")
    q = shlex.quote
    lines = [
        "#!/bin/bash",
        f"#SBATCH --job-name=dd-{config.run_label}-{stage}",
        f"#SBATCH --account={config.account}",
        f"#SBATCH --partition={config.partition}",
        f"#SBATCH --gres={config.gpu_resource}",
        f"#SBATCH --cpus-per-task={config.cpus}",
        f"#SBATCH --mem={config.memory_gb}G",
        f"#SBATCH --time={config.walltime}",
        "#SBATCH --nodes=1",
        "#SBATCH --ntasks=1",
        "#SBATCH --no-requeue",
        "#SBATCH --signal=B:TERM@60",
        f"#SBATCH --output={q(config.run_scratch + '/slurm-%j.out')}",
        f"#SBATCH --error={q(config.run_scratch + '/slurm-%j.err')}",
    ]
    if config.mail_confirmed:
        lines += ["#SBATCH --mail-type=BEGIN,END,FAIL,TIME_LIMIT", "#SBATCH --mail-user=kqk5924@psu.edu"]
    lines += [
        "set -euo pipefail",
        "umask 077",
        f"cd {q(config.source_dir)}",
        'test -n "${SLURM_JOB_ID:-}"',
        f"exec {q(config.python_executable)} -m denialdojo.roar run-stage {q(stage)} --config {q(config_path)}",
    ]
    return "\n".join(lines) + "\n"

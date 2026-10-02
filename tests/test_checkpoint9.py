"""Offline contracts for the Checkpoint 9 credential and orchestration scripts."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from denialdojo.api_adapter import ApiConfig
from denialdojo.checkpoint9 import load_model_queue
from denialdojo.provider_check import run_provider_check

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"


class _Transport:
    def __init__(self, response: dict) -> None:
        self.response = response
        self.calls: list[tuple[str, dict[str, str], dict, float]] = []

    def __call__(self, url: str, headers: dict[str, str], payload: dict, timeout: float) -> dict:
        self.calls.append((url, headers, payload, timeout))
        return self.response


def _run_powershell(*arguments: str, cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            *arguments,
        ],
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )


def _queue(path: Path) -> None:
    path.write_text(
        json.dumps(
            [
                {
                    "provider": "anthropic",
                    "model": "claude-haiku-4-5-20251001",
                    "reasoning_effort": "none",
                    "key_var": "ANTHROPIC_API_KEY",
                },
                {
                    "provider": "anthropic",
                    "model": "claude-sonnet-5-5",
                    "reasoning_effort": "none",
                    "key_var": "ANTHROPIC_API_KEY",
                },
                {
                    "provider": "google",
                    "model": "gemini-3.8-flash",
                    "reasoning_effort": "none",
                    "key_var": "GEMINI_API_KEY",
                },
                {
                    "provider": "google",
                    "model": "gemini-3.1-pro-preview",
                    "reasoning_effort": "none",
                    "key_var": "GEMINI_API_KEY",
                },
            ]
        ),
        encoding="utf-8",
    )


def _initialise_clean_repository(path: Path) -> None:
    (path / "marker.txt").write_text("tracked\n", encoding="utf-8")
    for args in (
        ("git", "init"),
        ("git", "config", "user.email", "checkpoint9@example.test"),
        ("git", "config", "user.name", "Checkpoint 9 test"),
        ("git", "add", "marker.txt"),
        ("git", "commit", "-m", "fixture"),
    ):
        subprocess.run(args, cwd=path, check=True, capture_output=True, text=True)


def test_load_env_sets_only_supported_process_values_from_a_temporary_file(tmp_path: Path) -> None:
    env_path = tmp_path / "temporary.env"
    env_path.write_text(
        "# local credentials\nOPENAI_API_KEY = \"fixture-openai\"\n\n"
        "ANTHROPIC_API_KEY='fixture-anthropic' # trailing comment\nGEMINI_API_KEY=\n",
        encoding="utf-8",
    )

    result = _run_powershell(str(SCRIPTS / "load_env.ps1"), "-EnvPath", str(env_path))

    assert result.returncode == 0
    assert result.stdout.splitlines() == [
        "OPENAI_API_KEY: set",
        "ANTHROPIC_API_KEY: set",
        "GEMINI_API_KEY: NOT SET",
    ]
    assert "fixture-openai" not in result.stdout
    assert "fixture-anthropic" not in result.stdout


def test_load_env_reports_a_missing_temporary_file_without_reading_any_real_env(tmp_path: Path) -> None:
    result = _run_powershell(str(SCRIPTS / "load_env.ps1"), "-EnvPath", str(tmp_path / "missing.env"))

    assert result.returncode != 0
    assert "Environment file not found" in result.stderr


def test_checkpoint9_queue_has_the_frozen_order_and_provider_key_binding() -> None:
    queue = load_model_queue(ROOT / "config" / "checkpoint9_models.json")

    assert [(entry.provider, entry.model, entry.reasoning_effort, entry.key_var) for entry in queue] == [
        ("anthropic", "claude-haiku-4-5-20251001", "none", "ANTHROPIC_API_KEY"),
        ("anthropic", "claude-sonnet-5-5", "none", "ANTHROPIC_API_KEY"),
        ("google", "gemini-3.8-flash", "none", "GEMINI_API_KEY"),
        ("google", "gemini-3.1-pro-preview", "none", "GEMINI_API_KEY"),
    ]


def test_env_example_contains_only_empty_supported_credential_variables() -> None:
    assert (ROOT / ".env.example").read_text(encoding="utf-8").splitlines() == [
        "OPENAI_API_KEY=",
        "ANTHROPIC_API_KEY=",
        "GEMINI_API_KEY=",
    ]


def test_provider_check_uses_the_api_adapter_payload_profile_and_auto_tool_choice(monkeypatch) -> None:
    monkeypatch.setenv("DENIALDOJO_API_KEY", "fixture-provider-check-key")
    transport = _Transport(
        {
            "model": "reported-gemini-model",
            "choices": [
                {
                    "finish_reason": "tool_calls",
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "provider-check-call",
                                "type": "function",
                                "function": {"name": "provider_check_ping", "arguments": "{}"},
                            }
                        ],
                    },
                }
            ],
        }
    )

    result = run_provider_check(ApiConfig(provider="google", model="gemini-3.8-flash"), transport=transport)

    assert len(transport.calls) == 1
    payload = transport.calls[0][2]
    assert payload["tool_choice"] == "auto"
    assert payload["temperature"] == 0.0
    assert payload["reasoning_effort"] == "none"
    assert "seed" not in payload
    assert result["reported_model"] == "reported-gemini-model"
    assert result["tool_call_returned"] is True
    assert "fixture-provider-check-key" not in json.dumps(result)


@pytest.mark.parametrize(
    ("checkpoint_text", "env_text", "dirty", "expected"),
    [
        ("## Checkpoint 9 draft\n", "ANTHROPIC_API_KEY=x\nGEMINI_API_KEY=x\n", False, "not marked final"),
        ("## Checkpoint 9 final\n", "ANTHROPIC_API_KEY=x\nGEMINI_API_KEY=x\n", True, "git tree is dirty"),
        ("## Checkpoint 9 final\n", "ANTHROPIC_API_KEY=x\n", False, "GEMINI_API_KEY: NOT SET"),
    ],
)
def test_overnight_dry_run_refuses_failed_preflight_without_network(
    tmp_path: Path,
    checkpoint_text: str,
    env_text: str,
    dirty: bool,
    expected: str,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    _initialise_clean_repository(repository)
    if dirty:
        (repository / "marker.txt").write_text("dirty\n", encoding="utf-8")
    checkpoint_path = tmp_path / "preregistration.md"
    checkpoint_path.write_text(checkpoint_text, encoding="utf-8")
    env_path = tmp_path / "temporary.env"
    env_path.write_text(env_text, encoding="utf-8")
    queue_path = tmp_path / "queue.json"
    _queue(queue_path)

    result = _run_powershell(
        str(SCRIPTS / "run_overnight.ps1"),
        "-DryRun",
        "-RepositoryRoot",
        str(repository),
        "-CheckpointPath",
        str(checkpoint_path),
        "-EnvPath",
        str(env_path),
        "-QueuePath",
        str(queue_path),
    )

    assert result.returncode != 0
    assert expected in result.stdout
    assert "fixture-provider-check-key" not in result.stdout

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
                    "omit_temperature": True,
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

    # Sonnet omits temperature (HTTP 400, provider-check-20261002-153922.json).
    # gemini-3.1-pro-preview was excluded before any scenario record: it forces thinking
    # and timed out at the fixed 180 s on a one-tool request (provider-check-20261002-154649.json).
    assert [
        (entry.provider, entry.model, entry.reasoning_effort, entry.key_var, entry.omit_temperature)
        for entry in queue
    ] == [
        ("anthropic", "claude-haiku-4-5-20251001", "none", "ANTHROPIC_API_KEY", False),
        ("anthropic", "claude-sonnet-5-5", "none", "ANTHROPIC_API_KEY", True),
        ("google", "gemini-3.8-flash", "none", "GEMINI_API_KEY", False),
        ("google", "gemini-3.5-flash-lite", "none", "GEMINI_API_KEY", False),
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


@pytest.mark.parametrize(
    ("checkpoint_text", "flags_placeholders", "flags_not_final"),
    [
        # Earlier checkpoints legitimately mention scenario_id and placeholders.
        (
            "## Checkpoint 4\nEach `scenario_id` is validated; no placeholder remains.\n"
            "## 2026-10-02 (Checkpoint 9): extension — final\nModels: `gemini-3.8-flash`.\n"
            "## Not frozen by this document\n- the Causal Residue gate.\n",
            False,
            False,
        ),
        ("## 2026-10-02 (Checkpoint 9): extension — final\nGoogle: `GEMINI_PRO_ID`\n", True, False),
        ("## 2026-10-02 (Checkpoint 9 draft): extension — not final\nModels.\n", False, True),
        ("## 2026-10-02 (Checkpoint 9): extension — not final\nModels.\n", False, True),
    ],
)
def test_overnight_checkpoint_gate_inspects_only_the_checkpoint_9_section(
    tmp_path: Path,
    checkpoint_text: str,
    flags_placeholders: bool,
    flags_not_final: bool,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    _initialise_clean_repository(repository)
    # A dirty tree guarantees the dry run still refuses, whatever the checkpoint says.
    (repository / "marker.txt").write_text("dirty\n", encoding="utf-8")
    checkpoint_path = tmp_path / "preregistration.md"
    checkpoint_path.write_text(checkpoint_text, encoding="utf-8")
    env_path = tmp_path / "temporary.env"
    env_path.write_text("ANTHROPIC_API_KEY=x\nGEMINI_API_KEY=x\n", encoding="utf-8")
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
    assert "git tree is dirty" in result.stdout
    assert ("Checkpoint 9 contains placeholders" in result.stdout) is flags_placeholders
    assert ("Checkpoint 9 is not marked final" in result.stdout) is flags_not_final


def test_overnight_dry_run_unrolls_every_queued_model_under_windows_powershell(tmp_path: Path) -> None:
    # Windows PowerShell 5.1 emits a JSON array as one object; an un-unrolled queue
    # collapses all four models into a single entry with space-joined fields.
    repository = tmp_path / "repository"
    repository.mkdir()
    _initialise_clean_repository(repository)
    checkpoint_path = tmp_path / "preregistration.md"
    checkpoint_path.write_text("## Checkpoint 9 draft\n", encoding="utf-8")
    env_path = tmp_path / "temporary.env"
    env_path.write_text("ANTHROPIC_API_KEY=x\n", encoding="utf-8")
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

    lines = result.stdout.splitlines()
    for provider, model, key_var in [
        ("anthropic", "claude-haiku-4-5-20251001", "ANTHROPIC_API_KEY"),
        ("anthropic", "claude-sonnet-5-5", "ANTHROPIC_API_KEY"),
        ("google", "gemini-3.8-flash", "GEMINI_API_KEY"),
        ("google", "gemini-3.1-pro-preview", "GEMINI_API_KEY"),
    ]:
        assert f"=== {provider}/{model}: key from {key_var} ===" in lines
        commands = [line for line in lines if f"-Models {model} -Provider {provider} " in line]
        assert len(commands) == 7
        omits = [line for line in commands if line.endswith(f"-OmitTemperature {model}")]
        assert len(omits) == (7 if model == "claude-sonnet-5-5" else 0)
    assert "ANTHROPIC_API_KEY: set" in lines
    assert "GEMINI_API_KEY: NOT SET" in lines
    assert "PREFLIGHT FAILED: GEMINI_API_KEY: NOT SET" in lines
    assert "x" not in [line.strip() for line in lines]
    assert "utf8NoBOM" not in result.stdout + result.stderr
    summaries = list((repository / "runs" / "logs").glob("overnight-summary-*.json"))
    assert len(summaries) == 1
    json.loads(summaries[0].read_text(encoding="utf-8"))


def test_provider_check_reports_each_queued_model_without_network(tmp_path: Path) -> None:
    # No keys are set, so no provider request can be made; each model must still be
    # reported on its own line and the result file must be written under 5.1.
    env_path = tmp_path / "temporary.env"
    env_path.write_text("# no keys\n", encoding="utf-8")
    queue_path = tmp_path / "queue.json"
    _queue(queue_path)
    log_directory = tmp_path / "logs"

    result = _run_powershell(
        str(SCRIPTS / "check_providers.ps1"),
        "-EnvPath",
        str(env_path),
        "-QueuePath",
        str(queue_path),
        "-LogDirectory",
        str(log_directory),
    )

    assert result.returncode == 0, result.stdout + result.stderr
    lines = result.stdout.splitlines()
    for provider, model in [
        ("anthropic", "claude-haiku-4-5-20251001"),
        ("anthropic", "claude-sonnet-5-5"),
        ("google", "gemini-3.8-flash"),
        ("google", "gemini-3.1-pro-preview"),
    ]:
        assert any(line.startswith(f"{provider}/{model}: HTTP") for line in lines)
    written = list(log_directory.glob("provider-check-*.json"))
    assert len(written) == 1
    results = json.loads(written[0].read_text(encoding="utf-8"))["results"]
    assert [entry["model"] for entry in results] == [
        "claude-haiku-4-5-20251001",
        "claude-sonnet-5-5",
        "gemini-3.8-flash",
        "gemini-3.1-pro-preview",
    ]
    assert [entry["error_message"] for entry in results] == [
        "ANTHROPIC_API_KEY is NOT SET",
        "ANTHROPIC_API_KEY is NOT SET",
        "GEMINI_API_KEY is NOT SET",
        "GEMINI_API_KEY is NOT SET",
    ]


def test_omit_temperature_is_omitted_from_payload_and_recorded_as_none() -> None:
    from denialdojo.api_adapter import ApiAdapter, runtime_metadata_from_adapter

    config = ApiConfig(provider="anthropic", model="claude-sonnet-5-5", omit_temperature=True)
    profile = config.payload_profile()
    assert profile["controls"]["temperature"]["disposition"] == "omitted"
    assert "HTTP 400" in profile["controls"]["temperature"]["reason"]
    transport = _Transport(
        {"model": "claude-sonnet-5-5", "choices": [{"finish_reason": "stop", "message": {"content": "done"}}]}
    )
    adapter = ApiAdapter(config, transport=transport)
    result = run_provider_check(config, transport=transport)
    payload = transport.calls[0][2]
    assert "temperature" not in payload
    assert result["http_status"] == 200
    assert runtime_metadata_from_adapter(adapter).temperature is None
    # The default still sends temperature 0, unchanged from Checkpoints 1-8.
    assert ApiConfig(provider="anthropic", model="claude-haiku-4-5-20251001").payload_profile()["controls"][
        "temperature"
    ] == {
        "disposition": "sent",
        "value": 0.0,
        "reason": "Anthropic OpenAI compatibility supports temperature from 0 through 1.",
    }


def test_reasoning_fallback_level_is_recorded_as_requested() -> None:
    profile = ApiConfig(provider="google", model="gemini-3.1-pro-preview", reasoning_effort="minimal").payload_profile()
    assert profile["controls"]["reasoning_effort"]["value"] == "minimal"
    assert profile["extended_reasoning"]["requested"] == "minimal"
    assert ApiConfig(provider="google", model="gemini-3.8-flash").payload_profile()["extended_reasoning"][
        "requested"
    ] == "disabled"


def test_committed_queue_carries_the_provider_check_outcomes() -> None:
    queue = {entry.model: entry for entry in load_model_queue(ROOT / "config" / "checkpoint9_models.json")}
    assert queue["claude-sonnet-5-5"].omit_temperature is True
    assert not any(entry.omit_temperature for name, entry in queue.items() if name != "claude-sonnet-5-5")

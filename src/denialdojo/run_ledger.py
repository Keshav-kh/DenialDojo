"""Exclusive execution claims and mutable operational monitoring, never evidence.

An unfinished claim is an uncertain/interrupted attempt, not permission to repeat
inference. A completed claim may be reused only by the caller's read-only replay.
"""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import time
import uuid
from pathlib import Path

from denialdojo.capture import redact_capture_value


def exclusive_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())


def atomic_json(path: Path, value) -> None:
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    exclusive_json(temporary, value)
    os.replace(temporary, path)


class RunLedger:
    def __init__(self, root: Path):
        self.root = Path(root)

    def directory(self, run_id: str) -> Path:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", run_id):
            raise ValueError("invalid run ID")
        return self.root / run_id

    def claim(self, run_id: str, metadata: dict) -> None:
        directory = self.directory(run_id)
        directory.parent.mkdir(parents=True, exist_ok=True)
        directory.mkdir()  # Atomic cross-process reservation before any invocation.
        now = time.time()
        exclusive_json(
            directory / "claim.json",
            {
                "run_id": run_id,
                "started_at": now,
                "supervisor_pid": os.getpid(),
                "metadata": metadata,
            },
        )
        atomic_json(
            directory / "status.json",
            {"outcome": "running", "started_at": now, "pid": None, "exit_code": None, "end_time": None},
        )
        self.heartbeat(run_id)

    def heartbeat(self, run_id: str, *, pid: int | None = None):
        atomic_json(self.directory(run_id) / "heartbeat.json", {"timestamp": time.time(), "pid": pid})

    def finish(self, run_id: str, outcome: str, exit_code: int | None):
        path = self.directory(run_id) / "status.json"
        previous = json.loads(path.read_text())
        if previous["outcome"] != "running":
            raise ValueError("a terminal operational status cannot be relabeled")
        if outcome not in {"complete", "failure", "timeout", "exception", "terminated"}:
            raise ValueError("invalid terminal operational outcome")
        if outcome == "complete" and exit_code != 0:
            raise ValueError("complete requires successful child exit")
        atomic_json(path, {**previous, "outcome": outcome, "exit_code": exit_code, "end_time": time.time()})

    def inspect(self, run_id: str, *, now: float | None = None, stale_after: float = 90) -> dict:
        directory = self.directory(run_id)
        status_path = directory / "status.json"
        status = json.loads(status_path.read_text()) if status_path.is_file() else {"outcome": "running"}
        if status["outcome"] == "running":
            heartbeat = directory / "heartbeat.json"
            try:
                last = json.loads(heartbeat.read_text())["timestamp"]
                age = (time.time() if now is None else now) - last
                stale = age < -5 or age > stale_after
            except (OSError, ValueError, KeyError, TypeError):
                stale = True
            if stale:
                status = {**status, "outcome": "interrupted_or_stale"}
        return {**status, "complete": status["outcome"] == "complete"}


def clean_child_environment() -> dict[str, str]:
    """Keep scheduler/module setup, exclude ambient credentials/proxy fallbacks."""
    excluded = re.compile(r"PASSWORD|SECRET|TOKEN|API_KEY|AUTHORIZATION|PROXY", re.I)
    return {key: value for key, value in os.environ.items() if not excluded.search(key)}


def _stop_child(child):
    if child.poll() is not None:
        return
    if os.name == "posix":
        os.killpg(child.pid, signal.SIGTERM)
    else:
        child.terminate()
    try:
        child.wait(timeout=5)
    except subprocess.TimeoutExpired:
        if os.name == "posix":
            os.killpg(child.pid, signal.SIGKILL)
        else:
            child.kill()
        child.wait(timeout=5)


def supervise(
    command: list[str], *, root: Path, run_id: str, timeout: float, metadata: dict | None = None, notify=None
) -> dict:
    if not command or timeout <= 0:
        raise ValueError("command and positive timeout required")
    if redact_capture_value(command) != command:
        raise ValueError("credentials are not permitted in a supervised command")
    ledger = RunLedger(root)
    ledger.claim(run_id, {**(metadata or {}), "command": command})
    directory = ledger.directory(run_id)
    child = None
    outcome = "exception"
    previous_handlers = {}

    def terminate(_signum, _frame):
        raise KeyboardInterrupt

    try:
        for sig in (signal.SIGTERM, signal.SIGINT):
            previous_handlers[sig] = signal.signal(sig, terminate)
        with (
            (directory / "stdout.log").open("x", encoding="utf-8") as stdout,
            (directory / "stderr.log").open("x", encoding="utf-8") as stderr,
        ):
            child = subprocess.Popen(
                command,
                stdout=stdout,
                stderr=stderr,
                shell=False,
                env=clean_child_environment(),
                start_new_session=os.name == "posix",
            )
            path = directory / "status.json"
            atomic_json(path, {**json.loads(path.read_text()), "pid": child.pid})
            deadline = time.monotonic() + timeout
            while child.poll() is None:
                ledger.heartbeat(run_id, pid=child.pid)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    outcome = "timeout"
                    _stop_child(child)
                    break
                try:
                    child.wait(timeout=min(30, remaining))
                except subprocess.TimeoutExpired:
                    continue
            else:
                outcome = "complete" if child.returncode == 0 else "failure"
    except KeyboardInterrupt:
        outcome = "terminated"
    except Exception:
        outcome = "exception"
    finally:
        if child is not None:
            _stop_child(child)
        for sig, handler in previous_handlers.items():
            signal.signal(sig, handler)
        ledger.finish(run_id, outcome, child.returncode if child else None)
    result = ledger.inspect(run_id)
    result["notification"] = "not_configured"
    if notify:
        try:
            notify(outcome)
            result["notification"] = "delivered"
        except Exception:
            result["notification"] = "failed"
    exclusive_json(directory / "summary.json", result)
    return result

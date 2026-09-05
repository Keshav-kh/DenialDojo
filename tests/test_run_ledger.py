import sys

import pytest

from denialdojo.run_ledger import RunLedger, supervise


def test_claim_precedes_execution_and_cannot_be_reused(tmp_path):
    ledger = RunLedger(tmp_path)
    ledger.claim("one", {"model_revision": "frozen"})
    with pytest.raises(FileExistsError):
        ledger.claim("one", {"model_revision": "frozen"})
    assert ledger.inspect("one", now=10**12)["outcome"] == "interrupted_or_stale"
    assert not ledger.inspect("one", now=10**12)["complete"]


def test_resume_requires_replay_of_completed_records_not_new_invocation(tmp_path):
    ledger = RunLedger(tmp_path)
    ledger.claim("one", {})
    ledger.finish("one", "complete", 0)
    with pytest.raises(FileExistsError):
        ledger.claim("one", {})
    assert ledger.inspect("one")["outcome"] == "complete"


@pytest.mark.parametrize(("code", "expected"), [(0, "complete"), (7, "failure")])
def test_supervisor_reports_actual_child_exit_and_notification(tmp_path, code, expected):
    notifications = []
    result = supervise(
        [sys.executable, "-c", f"raise SystemExit({code})"],
        root=tmp_path,
        run_id="child",
        timeout=10,
        notify=notifications.append,
    )
    assert result["outcome"] == expected and result["exit_code"] == code
    assert notifications == [expected]


def test_supervisor_timeout_does_not_mark_complete(tmp_path):
    result = supervise(
        [sys.executable, "-c", "import time; time.sleep(30)"], root=tmp_path, run_id="child", timeout=0.1
    )
    assert result["outcome"] == "timeout"
    assert result["complete"] is False


def test_supervisor_launch_failure_is_recorded(tmp_path):
    result = supervise([str(tmp_path / "missing-command")], root=tmp_path, run_id="child", timeout=1)
    assert result["outcome"] == "exception"


def test_notification_failure_does_not_reclassify_completed_job(tmp_path):
    def notify(_):
        raise RuntimeError("secret endpoint must not be logged")

    result = supervise([sys.executable, "-c", "pass"], root=tmp_path, run_id="child", timeout=10, notify=notify)
    assert result["outcome"] == "complete"
    assert result["notification"] == "failed"
    assert "secret endpoint" not in str(list(tmp_path.rglob("*.json")))

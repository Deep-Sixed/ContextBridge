import pytest

from contextbridge.task_ledger import TaskLedger, TaskTransitionError


def test_task_is_not_success_without_verified_transition(tmp_path):
    path = tmp_path / "tasks.sqlite3"
    ledger = TaskLedger(path)
    task = ledger.create(description="Check host")
    assert [e["state"] for e in ledger.history(task)] == ["requested"]
    with pytest.raises(TaskTransitionError):
        ledger.transition(task, "completed")
    ledger.transition(task, "authorized", detail="read-only")
    ledger.transition(task, "started", detail="dispatched")
    ledger.transition(task, "unknown", detail="response lost")
    assert TaskLedger(path).history(task)[-1]["state"] == "unknown"
    ledger.transition(task, "completed", detail="observed result verified")
    assert [e["state"] for e in ledger.history(task)] == [
        "requested", "authorized", "started", "unknown", "completed"
    ]
    with pytest.raises(TaskTransitionError):
        ledger.transition(task, "started")


def test_failed_task_terminal_and_missing_id(tmp_path):
    ledger = TaskLedger(tmp_path / "tasks.sqlite3")
    task = ledger.create(description="Denied operation")
    ledger.transition(task, "failed", detail="policy denied")
    with pytest.raises(TaskTransitionError):
        ledger.transition(task, "completed")
    with pytest.raises(TaskTransitionError):
        ledger.transition("missing", "authorized")


def test_invalid_payloads(tmp_path):
    ledger = TaskLedger(tmp_path / "tasks.sqlite3")
    with pytest.raises(TaskTransitionError):
        ledger.create(description="")
    task = ledger.create(description="Valid")
    with pytest.raises(TaskTransitionError):
        ledger.transition(task, "made_up")

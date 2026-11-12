"""Several environments in one command: `nudi send-nudis TASK TASK ...` and `send_environments`.

Most tests replace `send_nudis_async` with a recorder that keeps each environment's options and
returns or raises as the test needs. The rest run the real `send_nudis_async` over the analysis
recorders of the API tests, so no test calls Docker, Modal or a model.
"""

import asyncio
import json
import shutil
import signal
from pathlib import Path

import pytest
from pydantic import ValidationError

from nudi import cli, report, send, send_environments
from nudi.records import DiskFull
from nudi.run_state import MissingCredential
from test_api_cli import Analyses, events, logged
from test_runner import CONTRACT_TASK


def tasks(tmp_path, *names) -> list[Path]:
    """Copies of a supported task, each in a folder of its own name."""
    for name in names:
        shutil.copytree(CONTRACT_TASK, tmp_path / "tasks" / name)
    return [tmp_path / "tasks" / name for name in names]


class Runs:
    """Stands in for `send_nudis_async`: records each environment's options, starts and ends, and writes a small report.
    `outcomes` gives an environment a report status or an error to raise; `hold` seconds keep each one running."""

    def __init__(self, monkeypatch, outcomes=None, hold=0.0):
        self.calls, self.order, self.outcomes, self.hold, self.running, self.most = [], [], outcomes or {}, hold, 0, 0
        self.started = []
        monkeypatch.setattr(send, "send_nudis_async", self.send)

    async def send(self, task_dir, config=None, **options):
        name = Path(task_dir).name
        self.calls.append((name, options))
        self.started.append(asyncio.get_running_loop().time())
        self.order.append(("start", name))
        self.running += 1
        self.most = max(self.most, self.running)
        try:
            await asyncio.sleep(self.hold)
            outcome = self.outcomes.get(name, "complete")
            if isinstance(outcome, BaseException):
                raise outcome
            built = {"status": outcome, "answer": [f"{name} answer line", "second line"],
                     "configuration": {"known_cost": 0.25, "modal_cost": {"at_requests": 0.1, "at_limits": 0.2}}}
            options["output_dir"].mkdir(parents=True)
            (options["output_dir"] / "report.json").write_text(json.dumps(built))
            return built
        finally:
            self.running -= 1
            self.order.append(("end", name))

    def options(self, key) -> dict:
        return {name: options[key] for name, options in self.calls}


def command(*arguments) -> int:
    return cli.main(["send-nudis", *map(str, arguments)])


def summary(batch: Path) -> dict:
    return json.loads((batch / "summary.json").read_text())


def statuses(batch: Path) -> dict:
    return {row["name"]: row["status"] for row in summary(batch)["environments"]}


def test_one_task_runs_as_today_with_no_summary(tmp_path, monkeypatch, capsys):
    (task,) = tasks(tmp_path, "task-a")
    Analyses(monkeypatch)
    assert command(task, "--output", tmp_path / "run") == 0
    assert capsys.readouterr().out == (tmp_path / "run" / "report.md").read_text()
    assert not (tmp_path / "run" / "summary.json").exists() and not (tmp_path / "run" / "task-a").exists()


def test_two_tasks_write_one_run_folder_each_and_a_summary(tmp_path, monkeypatch, capsys):
    Analyses(monkeypatch)
    batch = tmp_path / "batch"
    assert command(*tasks(tmp_path, "task-a", "task-b"), "--output", batch, "--analysis", "hacking") == 0
    for name in ("task-a", "task-b"):
        assert {"run.json", "events.jsonl", "report.json", "report.md"} <= {path.name for path in (batch / name).iterdir()}
    assert sorted(path.name for path in batch.iterdir()) == ["summary.json", "summary.md", "task-a", "task-b"]
    assert capsys.readouterr().out == (batch / "summary.md").read_text()
    assert summary(batch)["status"] == "complete" and summary(batch)["exit_code"] == 0
    assert statuses(batch) == {"task-a": "complete", "task-b": "complete"}


@pytest.mark.parametrize("case", ["same folder name", "output not empty", "output inside a task", "credentials inside a task",
                                  "attack-from", "invalid configuration"])
def test_each_refusal_exits_2_before_any_environment_starts(tmp_path, monkeypatch, capsys, case):
    runs = Runs(monkeypatch)
    first, second = tasks(tmp_path, "task-a", "task-b")
    batch, extra = tmp_path / "batch", []
    if case == "same folder name":
        shutil.copytree(CONTRACT_TASK, tmp_path / "other" / "task-a")
        second = tmp_path / "other" / "task-a"
    elif case == "output not empty":
        batch.mkdir()
        (batch / "old.txt").write_text("earlier")
    elif case == "output inside a task":
        batch = second / "runs"
    elif case == "credentials inside a task":
        (second / ".env").write_text("NAME=value\n")
        extra = ["--credentials-file", second / ".env"]
    elif case == "attack-from":
        extra = ["--attack-from", tmp_path / "earlier"]
    else:
        extra = ["--episodes", "0"]
    assert command(first, second, "--output", batch, *extra) == 2
    assert capsys.readouterr().err.startswith("nudi: ")
    assert runs.calls == [] and not (batch / "summary.json").exists()
    if case == "invalid configuration":
        with pytest.raises(ValidationError):
            send_environments([first, second], output_dir=batch, episodes=0)


def test_the_spending_cap_is_split_over_the_admitted_environments(tmp_path, monkeypatch):
    """A task the opening check refuses receives no share."""
    runs = Runs(monkeypatch)
    first, second = tasks(tmp_path, "task-a", "task-b")
    (tmp_path / "tasks" / "not-a-task").mkdir()
    built = send_environments([first, second, tmp_path / "tasks" / "not-a-task"], output_dir=tmp_path / "batch", spending_cap=2)
    assert runs.options("spending_cap") == {"task-a": 1.0, "task-b": 1.0}
    refused = built["environments"][2]
    assert (refused["status"], refused["spending_cap"]) == ("refused", None) and "task.toml" in refused["error"]
    assert built["spending_cap"] == 2 and built["exit_code"] == 1
    runs = Runs(monkeypatch)
    send_environments([first, second], output_dir=tmp_path / "uncapped")
    assert runs.options("spending_cap") == {"task-a": None, "task-b": None}


@pytest.mark.parametrize("backend, total, count, at_once, share", [
    ("modal", 8, 2, 2, 4), ("modal", 8, 5, 4, 2), ("modal", 3, 2, 1, 3), ("docker", 8, 3, 1, 8)])
def test_concurrency_is_a_total_split_over_the_environments_at_once(tmp_path, monkeypatch, backend, total, count, at_once, share):
    monkeypatch.setattr(send, "MODAL_START_GAP", 0)
    runs = Runs(monkeypatch, hold=0.02)
    names = [f"task-{index}" for index in range(count)]
    built = send_environments(tasks(tmp_path, *names), output_dir=tmp_path / "batch", backend=backend, concurrency=total)
    assert runs.options("concurrency") == dict.fromkeys(names, share)
    assert runs.most == at_once and (built["at_once"], built["concurrency"]) == (at_once, total)
    if count > at_once:
        # The first environment beyond those at once starts only after one ends.
        assert runs.order.index(("start", names[at_once])) > next(index for index, item in enumerate(runs.order) if item[0] == "end")


def test_the_time_limit_is_one_deadline_split_over_rounds(tmp_path, monkeypatch):
    monkeypatch.setattr(send, "MODAL_START_GAP", 0)
    runs = Runs(monkeypatch)
    names = [f"task-{index}" for index in range(5)]
    built = send_environments(tasks(tmp_path, *names), output_dir=tmp_path / "batch", backend="modal", concurrency=8,
                              time_limit=60)
    assert built["rounds"] == 2 and runs.options("time_limit") == dict.fromkeys(names, 30)
    runs = Runs(monkeypatch)
    send_environments([tmp_path / "tasks" / name for name in names[:2]], output_dir=tmp_path / "unlimited")
    assert runs.options("time_limit") == {"task-0": None, "task-1": None}
    # The second round's start comes after the deadline of 0.06 s.
    runs = Runs(monkeypatch, hold=0.2)
    built = send_environments([tmp_path / "tasks" / name for name in names], output_dir=tmp_path / "late", backend="modal",
                              concurrency=8, time_limit=0.001)
    assert statuses(tmp_path / "late") == {**dict.fromkeys(names[:4], "complete"), "task-4": "not_started"}
    assert all(0 < limit <= 0.0005 for limit in runs.options("time_limit").values())
    assert (built["status"], built["exit_code"]) == ("partial", 1)


@pytest.mark.parametrize("duration, started, waits", [(0, 2, [0, 30]), (61, 1, [0])])
def test_environments_that_cannot_start_before_the_deadline_add_no_waits(tmp_path, monkeypatch, duration, started, waits):
    """Five tasks share four slots; neither a late launch nor an expired deadline adds launch waits."""
    names = [f"task-{index}" for index in range(5)]
    task_dirs = tasks(tmp_path, *names)
    calls, waited = [], []
    now = 1000.0
    sleep = asyncio.sleep
    monkeypatch.setattr(send, "MODAL_START_GAP", 30)

    async def recorded_sleep(delay):
        nonlocal now
        waited.append(delay)
        now += delay
        await sleep(0)

    async def completed(task_dir, config=None, **options):
        nonlocal now
        calls.append(Path(task_dir).name)
        now += duration
        return {"status": "complete"}

    async def batch():
        monkeypatch.setattr(asyncio.get_running_loop(), "time", lambda: now)
        monkeypatch.setattr(asyncio, "sleep", recorded_sleep)
        monkeypatch.setattr(send, "send_nudis_async", completed)
        return await send.send_environments_async(task_dirs, output_dir=tmp_path / "batch", backend="modal",
                                                  concurrency=8, time_limit=0.75)

    built = asyncio.run(batch())
    assert calls == names[:started]
    assert [row["status"] for row in built["environments"]] == ["complete"] * started + ["not_started"] * (5 - started)
    assert (built["status"], built["exit_code"]) == ("partial", 1)
    assert waited == waits


@pytest.mark.parametrize("backend, waits", [("modal", [30, 30]), ("docker", [])])
def test_the_first_modal_environments_start_30_seconds_apart(tmp_path, monkeypatch, backend, waits):
    runs, sleep, waited = Runs(monkeypatch), asyncio.sleep, []

    async def recorded(delay, *args):
        if delay >= 1:
            waited.append(delay)
            delay = 0
        return await sleep(delay, *args)

    monkeypatch.setattr(asyncio, "sleep", recorded)
    names = ["task-a", "task-b", "task-c"]
    send_environments(tasks(tmp_path, *names), output_dir=tmp_path / "batch", backend=backend)
    assert [round(delay) for delay in waited] == waits and [name for name, _ in runs.calls] == names


def test_an_environment_admitted_after_an_early_end_still_waits_its_modal_gap(tmp_path, monkeypatch):
    """Five Modal environments, four at once: the first one ends at once, so the fifth takes its slot before the other
    first starts. Every start still keeps the given order and the gap after the one before."""
    monkeypatch.setattr(send, "MODAL_START_GAP", 0.05)
    runs = Runs(monkeypatch)
    names = [f"task-{index}" for index in range(5)]
    send_environments(tasks(tmp_path, *names), output_dir=tmp_path / "batch", backend="modal")
    assert [name for name, _ in runs.calls] == names
    assert all(later - earlier >= 0.045 for earlier, later in zip(runs.started, runs.started[1:]))


def test_each_environment_names_itself_in_its_events_and_stderr(tmp_path, monkeypatch, capsys):
    Analyses(monkeypatch)
    batch = tmp_path / "batch"
    assert command(*tasks(tmp_path, "task-a", "task-b"), "--output", batch, "--analysis", "hacking") == 0
    lines = logged(capsys.readouterr().err)
    for name in ("task-a", "task-b"):
        texts = [item["text"] for item in events(batch / name)]
        assert texts and all(f" {name}: " in text for text in texts)
        assert f"nudi: {name}: hack inspector started" in lines
    assert lines and all(line.startswith(("nudi: task-a: ", "nudi: task-b: ")) for line in lines)
    assert command(tmp_path / "tasks" / "task-a", "--output", tmp_path / "one", "--analysis", "hacking") == 0
    assert "nudi: hack inspector started" in logged(capsys.readouterr().err)
    assert not any("task-a:" in item["text"] for item in events(tmp_path / "one"))


def test_failed_environments_leave_the_others_complete(tmp_path, monkeypatch, capsys):
    Runs(monkeypatch, outcomes={"task-b": MissingCredential("inspector: KEY is set nowhere"), "task-c": DiskFull("no space left"),
                                "task-d": RuntimeError("broke")})
    batch = tmp_path / "batch"
    assert command(*tasks(tmp_path, "task-a", "task-b", "task-c", "task-d"), "--output", batch) == 1
    assert statuses(batch) == {"task-a": "complete", "task-b": "refused", "task-c": "stopped", "task-d": "stopped"}
    rows = summary(batch)["environments"]
    assert [row["exit_code"] for row in rows] == [0, 2, 1, 1]
    assert "KEY is set nowhere" in rows[1]["error"] and "RuntimeError: broke" in rows[3]["error"]
    assert "nudi: task-b: refused: MissingCredential: inspector: KEY is set nowhere" in logged(capsys.readouterr().err)


def test_every_environment_refused_exits_2(tmp_path, monkeypatch):
    for name in ("task-a", "task-b"):
        (tmp_path / "tasks" / name).mkdir(parents=True)
    runs = Runs(monkeypatch)
    assert command(tmp_path / "tasks" / "task-a", tmp_path / "tasks" / "task-b", "--output", tmp_path / "batch") == 2
    assert runs.calls == [] and statuses(tmp_path / "batch") == {"task-a": "refused", "task-b": "refused"}
    assert "- Outcome: Could not start: no environment started.\n" in (tmp_path / "batch" / "summary.md").read_text()
    Runs(monkeypatch, outcomes={"task-c": MissingCredential("no key"), "task-d": MissingCredential("no key")})
    assert command(*tasks(tmp_path, "task-c", "task-d"), "--output", tmp_path / "started") == 2


@pytest.mark.parametrize("outcomes, code", [
    ({}, 0), ({"task-b": "time_limit"}, 1), ({"task-b": "partial"}, 1), ({"task-a": "time_limit", "task-b": "time_limit"}, 1)])
def test_the_command_exits_0_only_when_every_environment_would(tmp_path, monkeypatch, capsys, outcomes, code):
    Runs(monkeypatch, outcomes=outcomes)
    assert command(*tasks(tmp_path, "task-a", "task-b"), "--output", tmp_path / "batch") == code
    status = summary(tmp_path / "batch")["status"]
    assert status == ("partial" if "partial" in outcomes.values() else "time_limit" if outcomes else "complete")


def test_an_environment_not_started_makes_the_command_exit_1(tmp_path, monkeypatch):
    """On Docker one environment runs at a time, so the second starts after the deadline."""
    Runs(monkeypatch, hold=0.2)
    assert command(*tasks(tmp_path, "task-a", "task-b"), "--output", tmp_path / "batch", "--time-limit", "0.001") == 1
    assert statuses(tmp_path / "batch") == {"task-a": "complete", "task-b": "not_started"}


@pytest.mark.parametrize("signum, stop, code, words, warning", [
    (signal.SIGINT, "cancelled", 130, "you", "cancelled"), (signal.SIGTERM, "terminated", 143, "a termination signal", "stopped by a termination signal")])
def test_a_stop_writes_running_reports_marks_waiting_ones_and_prints_the_summary(tmp_path, monkeypatch, capsys, signum, stop, code,
                                                                                 words, warning):
    """Two of three Modal environments run at concurrency 4; Ctrl-C or SIGTERM comes while both inspect."""
    monkeypatch.setattr(send, "MODAL_START_GAP", 0)
    analyses, both = Analyses(monkeypatch), asyncio.Barrier(2)

    async def interrupted(run, *, focused_attempts, on_evidence=None, gate=None):
        analyses.calls.append(("inspect_hacks", run.config.output_dir.name))
        await both.wait()
        if run.config.output_dir.name == "task-a":
            signal.raise_signal(signum)
        await asyncio.sleep(30)

    monkeypatch.setattr(send, "inspect_hacks", interrupted)
    batch = tmp_path / "batch"
    assert command(*tasks(tmp_path, "task-a", "task-b", "task-c"), "--output", batch, "--backend", "modal", "--concurrency", "4",
                   "--analysis", "hacking") == code
    output, error = capsys.readouterr()
    assert output == (batch / "summary.md").read_text() and f"- Outcome: {report.BATCH[stop]}" in output
    assert logged(error)[-1] == f"nudi: stopped by {words}; summary written to {batch / 'summary.md'}"
    assert statuses(batch) == {"task-a": stop, "task-b": stop, "task-c": "not_started"}
    assert summary(batch)["status"] == stop and summary(batch)["exit_code"] == code
    assert [row["exit_code"] for row in summary(batch)["environments"]] == [code, code, None]
    for name in ("task-a", "task-b"):
        assert f"run: {warning} during hack and attack" in json.loads((batch / name / "report.json").read_text())["warnings"]
    assert not (batch / "task-c").exists()


def test_the_summary_lists_each_answer_line_cost_and_folder_without_a_combined_verdict(tmp_path, monkeypatch):
    """Each row keeps its report's verdict and how it ran; this report, from before headlines, has them first and last."""
    Runs(monkeypatch, outcomes={"task-b": "partial"})
    batch = tmp_path / "batch"
    built = send_environments(tasks(tmp_path, "task-a", "task-b"), output_dir=batch, spending_cap=1)
    assert "answer" not in built and "verdict" not in json.dumps(built)
    assert [row["answer"] for row in built["environments"]] == ["task-a answer line", "task-b answer line"]
    assert [row["execution"] for row in built["environments"]] == ["second line", "second line"]
    assert [row["known_cost"] for row in built["environments"]] == [0.25, 0.25]
    text = (batch / "summary.md").read_text()
    assert "## Answer" not in text
    for name in ("task-a", "task-b"):
        assert f"## {name}\n\n- Outcome: second line\n" in text and f"- Answer: {name} answer line\n" in text and str(batch / name) in text
    assert "$0.250000" in text and "$0.10 at requested CPU and memory, $0.20 if all used their limits" in text


def test_an_environment_error_reaches_the_summary_and_stderr_only_redacted(tmp_path, monkeypatch, capsys):
    """An error raised past a run is not redacted by it, so the batch redacts every configured credential value."""
    from_environment, from_file = "sk-batch-environment-0123456789-tail", "sk-batch-file-0123456789"
    monkeypatch.setenv("MERGE_GATEWAY_API_KEY", from_environment)
    # The file's value for the same variable is a prefix of the environment's, so it must not be replaced first.
    (tmp_path / "keys.env").write_text(f"OTHER_API_KEY={from_file}\nMERGE_GATEWAY_API_KEY={from_environment[:-5]}\n")
    config = tmp_path / "nudi.toml"
    config.write_text('[models.attacker]\nmodel = "openai/your-model"\napi_key_var = "OTHER_API_KEY"\n')
    Runs(monkeypatch, outcomes={"task-a": RuntimeError(f"provider echoed {from_environment}"),
                                "task-b": DiskFull(f"no space; key {from_file}")})
    batch = tmp_path / "batch"
    assert command(*tasks(tmp_path, "task-a", "task-b"), "--output", batch, "--config", config,
                   "--credentials-file", tmp_path / "keys.env") == 1
    output, error = capsys.readouterr()
    assert "RuntimeError: provider echoed [redacted]" in summary(batch)["environments"][0]["error"]
    for text in (output, error, (batch / "summary.json").read_text(), (batch / "summary.md").read_text()):
        assert from_environment not in text and from_file not in text and "tail" not in text

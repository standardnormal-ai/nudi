"""`nudi send-nudis TASK`: a thin command over `nudi.send.send_nudis`.

With several tasks it runs `nudi.send.send_environments`, prints `summary.md` instead of a report, also on Ctrl-C or SIGTERM,
and exits with the summary's code; each stderr line names its environment.

It prints the Markdown report and exits 0 when every selected step ran to its end, also with evidence left unresolved,
1 when a step failed or stopped, as at the spending cap or the time limit, or no space was left for a record, 2 when configuration or
startup fails before execution, an unreachable Docker daemon, a failed Modal preflight and too
little free space where records go included, 130 on Ctrl-C and 143 on SIGTERM. Each phase's start and end go
to stderr, each line the `text` of one event of `RUN/events.jsonl`, with a heartbeat line after 15 quiet minutes; Ctrl-C prints the written
report too. Ctrl-C, SIGTERM and a full records host print one line that says whether the report was written.

`nudi report RUN_DIR` writes `report.json` and `report.md` again from a run's records, with no model call or sandbox,
prints the report and exits as the run would have. A run whose log has no `run_end`, such as a killed one, or whose `run_end`
says it stopped, is reported as stopped; one whose process still runs on this host, or a folder without `run.json`, exits 2.

`nudi cost RUN_DIR` prints Modal's bill for a run's sandboxes and exits 0 once Modal has
reported it, otherwise one line saying why. It exits 1 when a later try can succeed, as before
Modal reports the last hour, and 2 when no bill will ever exist, for a run on another backend or
with no Modal sandbox, or for a folder without a readable `run.json`. It limits and stops nothing; the spending cap counts model cost only.
"""

import argparse
import importlib.metadata
import json
import logging
import os
import shlex
import socket
import subprocess
import sys
from pathlib import Path
from typing import get_args

from dotenv import dotenv_values
from pydantic import ValidationError

from nudi.records import Backend, DiskFull, RunRecord

# `nudi.send.Analysis`. The command imports nudi's run modules, which load LiteLLM and LangChain in seconds, only
# after its arguments parse, so help and argument errors return at once.
ANALYSES = ("full", "simulation", "hacking")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="nudi", epilog="related commands: nudi-view RUN opens a run in the terminal")
    parser.add_argument("--version", action="version", version=f"nudi {version()}")
    commands = parser.add_subparsers(dest="command", required=True)
    send = commands.add_parser("send-nudis", help="run the selected analyses of one or more Harbor tasks and write their reports")
    send.add_argument("task", type=Path, nargs="+",
                      help="local Harbor task directories, never modified; with several, --output is a batch folder with "
                           "one run folder for each, and the spending cap, concurrency and time limit are totals split over them")
    send.add_argument("--config", type=Path, help="TOML file of configuration fields, with models under [models.<role>]")
    send.add_argument("--output", dest="output_dir", type=Path, help="run directory for records and the report")
    send.add_argument("--analysis", choices=ANALYSES, help="default full")
    send.add_argument("--episodes", type=int, help="ordinary Simulator episodes, default 12")
    send.add_argument("--focused-attempts", type=int, help="total focused attempts per grader inspector or hack inspector category, default 2")
    send.add_argument("--isolated-inspections", action="store_true", default=None,
                      help="runs one grader inspector session per ordinary episode (inspector_swarm), several at a "
                           "time within the run's concurrency; default off (holistic_inspection)")
    send.add_argument("--attacker-tries", type=int, help="maximum Attacker attempts per candidate and hint level, default 1")
    send.add_argument("--discovery-attempts", type=int, help="total no-hint attempts, which start with the hack inspector, default 1")
    send.add_argument("--minimal-hints", action=argparse.BooleanOptionalAction, default=None,
                      help="attempt each candidate whose full hint reproduced it with the minimal hint too; default on")
    send.add_argument("--attack-from", type=Path,
                      help="an earlier run directory of the same task: copy its inspection records and run only the attack; "
                           "the earlier directory is only read")
    send.add_argument("--requirements", type=Path,
                      help="TOML file of the task's approved requirements, each with the check observation that measures it; "
                           "without it the report calls no work correct and no route a violation of the task")
    send.add_argument("--spending-cap", type=float, help="US dollar cap on known inference cost; no default")
    send.add_argument("--time-limit", type=float,
                      help="whole-run limit in minutes; at it the run stops, cleans up and reports; no default")
    send.add_argument("--credentials-file", type=Path, help="dotenv file of credentials")
    send.add_argument("--workspace-memory-mb", type=int,
                      help="Inspector workspace memory limit in MiB; default on Docker the smaller of 512 and the task's, "
                           "on Modal the task's")
    send.add_argument("--backend", choices=get_args(Backend),
                      help="where episodes and sandboxes run, default docker; modal needs a Modal credential")
    send.add_argument("--concurrency", type=int,
                      help="containers at once, default 16: the limit on Modal, a cap on Docker's capacity")
    rebuild = commands.add_parser("report", help="write a run's report again from its records, such as after nudi was killed")
    rebuild.add_argument("run_dir", type=Path, help="the run directory, with its run.json")
    rebuild.add_argument("--credentials-file", type=Path, help="the run's dotenv file of credentials, so the report redacts them")
    bill = commands.add_parser("cost", help="print Modal's bill for a run's sandboxes once Modal has reported it")
    bill.add_argument("run_dir", type=Path, help="the run directory, with its run.json")
    options = vars(parser.parse_args(argv))
    from nudi import report
    from nudi import send as send_module
    from nudi.run_state import BackendUnavailable, CapacityError

    command = options.pop("command")
    tasks, config = options.pop("task", None) or [None], options.pop("config", None)
    options = {key: value for key, value in options.items() if value is not None}
    written, several = None, len(tasks) > 1
    kind = "summary" if several else "report"

    def outcome() -> str:
        return f"{kind} written to {written}" if written and written.exists() else f"no {kind} was written"

    logger, handler = logging.getLogger("nudi"), logging.StreamHandler()
    # A run's line is its event's text (`run_state.event`); `nudi cost` prints one reason.
    clock = "" if command == "cost" else "%(asctime)s "
    handler.setFormatter(Lines(f"nudi: {clock}%(message)s", "%H:%M:%S"))
    level = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    library = None
    try:
        if command == "cost":
            return cost(options["run_dir"])
        if command == "report":
            return rewrite(options["run_dir"], options.get("credentials_file"))
        written = send_module.configure(tasks[0], config, options).output_dir / f"{kind}.md"
        # With a root handler, Python's last-resort handler no longer prints libraries' warnings on stderr.
        library = logging.FileHandler(written.parent / "library.log", delay=True)
        library.setLevel(logging.WARNING)
        library.addFilter(lambda record: not record.name.startswith("nudi"))
        logging.getLogger().addHandler(library)
        if several:
            built = send_module.send_environments(tasks, config, **options)
            print(written.read_text(), end="")
            return built["exit_code"]
        result = send_module.send_nudis(tasks[0], config, **options)
    except ValidationError as error:
        print(f"nudi: {'; '.join(map(problem, error.errors()))}", file=sys.stderr)
        return 2
    except (ValueError, OSError, CapacityError, BackendUnavailable) as error:
        print(f"nudi: {error}", file=sys.stderr)
        return 2
    except subprocess.CalledProcessError as error:
        # The startup capacity check runs `docker info`; an unavailable daemon fails it.
        print(f"nudi: Docker is unavailable: `{shlex.join(error.cmd)}` exited {error.returncode}: "
              f"{(error.stderr or error.output or '').strip()}", file=sys.stderr)
        return 2
    except DiskFull as error:
        print(f"nudi: stopped: {error}; {outcome()}", file=sys.stderr)
        return 1
    except KeyboardInterrupt as stop:
        # Most measured runs ended with a stop, so a stop prints the report as a finished run does.
        if written and written.exists():
            print(written.read_text(), end="")
        terminated = isinstance(stop, send_module.Terminated)
        print(f"nudi: stopped by {'a termination signal' if terminated else 'you'}; {outcome()}", file=sys.stderr)
        return 143 if terminated else 130
    finally:
        logger.removeHandler(handler)
        logger.setLevel(level)
        if library:
            logging.getLogger().removeHandler(library)
            library.close()
    print(report.markdown(result), end="")
    return 0 if result["status"] == "complete" else 1


class Lines(logging.Formatter):
    """An event's own `text`, so stderr and the event log never disagree; any other record as formatted."""

    def format(self, record: logging.LogRecord) -> str:
        event = getattr(record, "event", None)
        return event["text"] if event else super().format(record)


def version() -> str:
    try:
        return importlib.metadata.version("nudi")
    except importlib.metadata.PackageNotFoundError:
        return "unknown: run from a checkout that is not installed"


def problem(error: dict) -> str:
    """One configuration error as a phrase; a missing output directory names its flag."""
    if error["type"] == "missing" and error["loc"] == ("output_dir",):
        return "--output is required"
    return f"{'.'.join(map(str, error['loc']))}: {error['msg']}" if error["loc"] else error["msg"]


def saved_record(run_dir: Path) -> RunRecord:
    """The run's `run.json`, or ValueError naming the file when it is missing or unreadable."""
    path = run_dir / "run.json"
    if not path.is_file():
        raise ValueError(f"{run_dir} has no run.json, so it is not a nudi run folder")
    try:
        return RunRecord.model_validate_json(path.read_text())
    except ValidationError as error:
        raise ValueError(f"{path}: {'; '.join(map(problem, error.errors()))}") from None


def cost(run_dir: Path) -> int:
    from nudi import report

    record = saved_record(run_dir)
    if (billed := report.billed_cost(record)) is None:
        # billed_cost logged the reason; a run with no Modal sandbox will never have a bill.
        return 1 if record.backend == "modal" and record.modal else 2
    print(f"Modal billed ${billed:.2f} for the sandboxes in app nudi-{record.run_id}, metered before credits; "
          "the host that ran nudi is not counted")
    return 0


def rewrite(run_dir: Path, credentials_file: Path | None) -> int:
    """`nudi report RUN_DIR`: the report again from the run's records. The run's credentials, from the environment
    and `credentials_file`, are redacted as in the run's own report."""
    from nudi import report

    record = saved_record(run_dir)
    if credentials_file and not credentials_file.is_file():
        raise ValueError(f"credentials file {credentials_file} does not exist")
    events = []
    if (run_dir / "events.jsonl").is_file():
        for line in (run_dir / "events.jsonl").read_text().splitlines():
            try:
                events.append(json.loads(line))
            except ValueError:
                pass  # A killed process can leave its last line cut.
    start = next((item for item in events if item.get("kind") == "run_start"), {})
    end = next((item for item in reversed(events) if item.get("kind") == "run_end"), None)
    if end is None and running(start):
        raise ValueError(f"nudi (pid {start['pid']}) is still running this run; it writes the report when it ends")
    present = report.retained(run_dir, record)
    selected = [name for name in report.ANALYSES if present[name] or name in start.get("analyses", ()) or name in record.failed_phases]
    file = dotenv_values(credentials_file) if credentials_file else {}
    names = {model.key_name() for model in record.models.values()}
    secrets = [value for name in names for value in (file.get(name), os.environ.get(name)) if value]
    # A run that stopped or was interrupted keeps its stop, also when every analysis was saved before it, as when the last
    # report write failed or a stop came during the final deletion of state copies.
    stop = ("the nudi process ended without closing out the run" if end is None
            else end.get("error") or "the run stopped" if end.get("status") == "stopped"
            else "the run was interrupted" if end.get("status") == "cancelled" else None)
    written, text = report.write(run_dir, secrets, selected, stop)
    print(text.read_text(), end="")
    return 0 if json.loads(written.read_text())["status"] == "complete" else 1


def running(start: dict) -> bool:
    """Whether the process of the run that `start`, its `run_start` event, began still runs. Only a process on this
    host can be checked; a run started on another host counts as ended. An older log names no host."""
    pid = start.get("pid")
    if pid is None or start.get("host", socket.gethostname()) != socket.gethostname():
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        pass  # Another user's process.
    return True

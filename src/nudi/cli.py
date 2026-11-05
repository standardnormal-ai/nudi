"""`nudi send-nudis TASK`: a thin command over `nudi.api.send_nudis`.

It prints the Markdown report and exits 0 when every selected analysis is complete,
1 when the report is partial or no space was left for a record, 2 when configuration or
startup fails before execution, an unreachable Docker daemon, a failed Modal preflight and too
little free space where records go included, and 130 on Ctrl-C. Each phase's start and end go
to stderr; Ctrl-C and a full records host print one line that says whether the report was written.
"""

import argparse
import logging
import shlex
import subprocess
import sys
from pathlib import Path
from typing import get_args

from nudi import api, report
from nudi.records import Backend, DiskFull
from nudi.workflow import BackendUnavailable, CapacityError


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="nudi")
    commands = parser.add_subparsers(dest="command", required=True)
    send = commands.add_parser("send-nudis", help="run the selected analyses of one Harbor task and write its report")
    send.add_argument("task", type=Path, help="the local Harbor task directory; it is never modified")
    send.add_argument("--config", type=Path, help="TOML file of configuration fields, with models under [models.<role>]")
    send.add_argument("--output", dest="output_dir", type=Path, help="run directory for records and the report")
    send.add_argument("--analysis", choices=get_args(api.Analysis), help="default full")
    send.add_argument("--episodes", type=int, help="ordinary Simulator episodes, default 20")
    send.add_argument("--focused-attempts", type=int, help="total focused attempts per grader inspector or hack inspector category, default 2")
    send.add_argument("--isolated-inspections", action="store_true", default=None,
                      help="runs one grader inspector per ordinary episode (inspector_swarm), about 3 to 7 minutes "
                           "each; default off (holistic_inspection)")
    send.add_argument("--attacker-tries", type=int, help="maximum Attacker attempts per candidate and hint level, default 2")
    send.add_argument("--discovery-attempts", type=int, help="total no-hint discovery attempts, default 1")
    send.add_argument("--spending-cap", type=float, help="US dollar cap on known inference cost; no default")
    send.add_argument("--credentials-file", type=Path, help="dotenv file of credentials")
    send.add_argument("--workspace-memory-mb", type=int,
                      help="Inspector workspace memory limit in MiB; default the smaller of 512 and the task's")
    send.add_argument("--backend", choices=get_args(Backend),
                      help="where episodes and sandboxes run, default docker; modal needs a Modal credential")
    send.add_argument("--concurrency", type=int,
                      help="containers at once, default 8: the limit on Modal, a cap on Docker's capacity")
    options = vars(parser.parse_args(argv))
    del options["command"]
    task, config = options.pop("task"), options.pop("config")
    options = {key: value for key, value in options.items() if value is not None}
    written = None

    def outcome() -> str:
        return f"report written to {written}" if written and written.exists() else "no report was written"

    logger, handler = logging.getLogger("nudi"), logging.StreamHandler()
    handler.setFormatter(logging.Formatter("nudi: %(message)s"))
    level = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    try:
        written = api.configure(task, config, options).output_dir / "report.md"
        result = api.send_nudis(task, config, **options)
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
    except KeyboardInterrupt:
        print(f"nudi: cancelled; {outcome()}", file=sys.stderr)
        return 130
    finally:
        logger.removeHandler(handler)
        logger.setLevel(level)
    print(report.markdown(result), end="")
    return 0 if result["status"] == "complete" else 1

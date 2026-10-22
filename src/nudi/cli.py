"""`nudi send-nudis TASK`: a thin command over `nudi.api.send_nudis`.

It prints the Markdown report and exits 0 when every selected analysis is complete,
1 when the report is partial, and 2 when configuration or startup fails before execution.
"""

import argparse
import shlex
import subprocess
import sys
from pathlib import Path
from typing import get_args

from nudi import api, report
from nudi.workflow import CapacityError


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="nudi")
    commands = parser.add_subparsers(dest="command", required=True)
    send = commands.add_parser("send-nudis", help="run the selected analyses of one Harbor task and write its report")
    send.add_argument("task", type=Path, help="the local Harbor task directory; it is never modified")
    send.add_argument("--config", type=Path, help="TOML file of configuration fields, with models under [models.<role>]")
    send.add_argument("--output", dest="output_dir", type=Path, help="run directory for records and the report")
    send.add_argument("--analysis", choices=get_args(api.Analysis), help="default full")
    send.add_argument("--episodes", type=int, help="ordinary Simulator episodes, default 20")
    send.add_argument("--focused-attempts", type=int, help="total focused Inspector attempts per category, default 3")
    send.add_argument("--attacker-tries", type=int, help="maximum Attacker attempts per hint level, default 2")
    send.add_argument("--spending-cap", type=float, help="US dollar cap on known inference cost; no default")
    send.add_argument("--credentials-file", type=Path, help="dotenv file of credentials")
    options = vars(parser.parse_args(argv))
    del options["command"]
    task, config = options.pop("task"), options.pop("config")
    try:
        result = api.send_nudis(task, config, **{key: value for key, value in options.items() if value is not None})
    except (ValueError, OSError, CapacityError) as error:
        print(f"nudi: {error}", file=sys.stderr)
        return 2
    except subprocess.CalledProcessError as error:
        # The startup capacity check runs `docker info`; an unavailable daemon fails it.
        print(f"nudi: Docker is unavailable: `{shlex.join(error.cmd)}` exited {error.returncode}: "
              f"{(error.stderr or error.output or '').strip()}", file=sys.stderr)
        return 2
    print(report.markdown(result), end="")
    return 0 if result["status"] == "complete" else 1

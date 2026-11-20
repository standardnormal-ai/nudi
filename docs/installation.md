# Installation

nudi needs Python 3.12, a sandbox backend (Docker or a Modal account) and an API key for an OpenAI-compatible inference provider.

## Requirements

- Python 3.12 on the host that runs nudi.
- A local Harbor task folder with `task.toml`, `instruction.md`, its environment (`environment/Dockerfile` or a declared `docker_image`) and its grader (`tests/test.sh` and supporting files). The task environment needs Python 3 for inspector checks. Modal does not support tasks with `environment/docker-compose.yaml`, and Docker does not support tasks that declare GPUs. See [Get tasks](#get-tasks).
- Docker, or a Modal account for `--backend modal`, which needs no Docker. On Docker, nudi runs as many episodes at once as the task's declared CPUs and memory fit in 90% of Docker's CPUs and memory. On a Docker host with 2 CPUs, sandboxes ran one at a time.
- At least 10 GiB free where records go and where Docker stores its data. See [Disk space](#disk-space).
- An API key for the simulator, inspector and attacker roles, in a credentials file outside the task folder or in an environment variable. See [Configure models and credentials](#configure-models-and-credentials).
- A new or empty output directory outside the task folder, passed with `--output` or set in TOML.
- Time: plan for hours. [Run time and cost](usage.md#run-time-and-cost) lists what drives it.
- Cost: there is no spending cap unless you set `--spending-cap`, and the cap counts known inference cost only. Modal bills its sandboxes separately.

One measured setup was `nudi send-nudis <task> --backend modal --analysis hacking --episodes 2 --concurrency 24`, with DeepSeek v4.1 flash 1017 for nudi's agents. Three tasks took about 4 h 20 min ($1.41 model cost), 5 h 16 min ($2.91) and 5 h 10 min ($1.62). Modal compute is billed on top: `report.json` records estimates under `configuration.modal_cost`, about $0.40 to $0.65 per run at requested sizes and up to about $5 to $7.50 at resource limits. These are measurements and estimates, not bounds. [Usage](usage.md#run-an-analysis) has the full command.

A run's first line states what nudi found on the host: the backend, the CPUs and memory, the free space, the spending cap and the concurrency.

### Disk space

nudi refuses to start with less than 10 GiB free. It checks this once, at the start; it is not a bound on what a run uses. In one measured run the state copies reached 8.5 GB in all. On Docker, nudi does not copy a container whose writable layer, as Docker reports it, exceeds 2 GiB.

nudi measures Docker's free space only for a daemon on the same host that it reaches through a local `unix://` socket. It cannot measure Docker Desktop, another virtual machine or a remote daemon. On Docker Desktop, Colima or OrbStack, check the virtual machine's disk size in its settings; `docker system df` shows what Docker already uses.

A full Docker disk fails each build, start or copy, and three failed starts in a row of the task's environment stop the run. The hack inspector may test whether a task can exhaust disk space by filling its sandbox's disk. On Docker this fills the disk where Docker stores data until the sandbox is removed, and nudi does not limit it.

## Install

nudi is on PyPI. Install it as a command-line tool with uv or pipx, which put it in its own environment:

```sh
uv tool install --python 3.12 "nudi[modal]"
# or
pipx install --python python3.12 "nudi[modal]"
nudi --version
```

`nudi --version` prints the installed version from the package metadata. The `[modal]` extra adds the Modal backend; drop it if you only use Docker. To upgrade, run `uv tool upgrade nudi` or `pipx upgrade nudi`.

Without Python 3.12, install it first, for example with `uv python install 3.12`, `brew install python@3.12` or from python.org.

### Install from a git tag

To install a version straight from its git tag, for example `v0.5.1`, use a virtual environment:

```sh
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install "nudi[modal] @ git+https://github.com/standardnormal-ai/nudi.git@v0.5.1"
nudi --version
```

With uv, `uv venv --python 3.12` followed by `uv pip install` with the same package spec does the same.

Only the direct dependencies are pinned, in [pyproject.toml](../pyproject.toml). Their own dependencies resolve at install time, so two installs can differ in those.

The terminal viewer `nudi-view` is a separate Go program and needs Go 1.27.3 or later to build; see [Viewer](usage.md#viewer).

## Get tasks

nudi reads Harbor task folders. The `harbor` command installed with nudi downloads them from the Harbor registry, for example Terminal Bench 4.0.0:

```sh
harbor download terminal-bench/terminal-bench@4.0.0 -o tasks
```

Harbor writes each task to `<output-dir>/<dataset-name>/<task-name>/`. Pass one task folder to `nudi send-nudis`, or several, as in [Several environments](usage.md#several-environments).

## Configure models and credentials

Without `--config`, every role uses `openai/deepseek/deepseek-v4.1-flash-1017` through the Merge gateway at `https://api-gateway.merge.dev/v1/openai` and reads its key from `MERGE_GATEWAY_API_KEY`. The key must have access to that model. Put `MERGE_GATEWAY_API_KEY=your-key` in a credentials file outside the task folder and pass `--credentials-file /path/to/credentials.env`, or set the environment variable.

For any other OpenAI-compatible provider or gateway, write `nudi.toml` with all three roles:

```toml
output_dir = "runs/first"

[models.simulator]
model = "openai/your-model"
api_base = "https://your-gateway.example.com/v1"
api_key_var = "INFERENCE_API_KEY"

[models.inspector]
model = "openai/your-model"
api_base = "https://your-gateway.example.com/v1"
api_key_var = "INFERENCE_API_KEY"

[models.attacker]
model = "openai/your-model"
api_base = "https://your-gateway.example.com/v1"
api_key_var = "INFERENCE_API_KEY"
```

Replace `your-model` with the provider's model ID and the `api_base` with its OpenAI-compatible base URL. Keep the `openai/` prefix: it selects the OpenAI-compatible API. `api_key_var` names the variable that holds the key; the key itself never goes in the TOML file. Put it in a credentials file outside the task folder:

```sh
# /path/to/credentials.env
INFERENCE_API_KEY=your-key
```

Then run:

```sh
nudi send-nudis /path/to/task --config nudi.toml --credentials-file /path/to/credentials.env
```

nudi looks up the key in the credentials file first, then in the environment. [Models](usage.md#models) lists the other model settings.

## Check Docker

```sh
docker info
```

Docker needs enough CPU and memory for the task's declared resources and for inspection containers; nudi checks the capacity at startup. A run keeps up to `--concurrency` sandboxes alive at once, inspection workspaces and experiments included, and a container that does not fit waits until another ends. One inspection workspace may still admit one experiment, even at `--concurrency 1`, and a task's helper containers can exceed the setting.

## Optional Modal backend

Install with the `[modal]` extra, as above, then authenticate:

```sh
modal setup
```

Run with `--backend modal` once a Modal account with sandbox access and billing is authenticated. Inference credentials are still required.

Continue with [Usage](usage.md) or return to the [README](../readme.md).

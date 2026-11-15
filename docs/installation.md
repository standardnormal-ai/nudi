# Installation

A run needs either a running Docker daemon or a Modal account for its sandboxes. nudi also requires Python 3.12, and model calls require credentials for the configured inference provider.

## Requirements

- Python 3.12 on the host that runs nudi.
- A local Harbor task folder with `task.toml`, `instruction.md`, its environment (`environment/Dockerfile` or a declared `docker_image`), and its grader (`tests/test.sh` and supporting files). Python 3 must be available inside the task environment for inspector checks. Modal does not support tasks with `environment/docker-compose.yaml`.
- Docker, or a Modal account for `--backend modal`, which needs no Docker. On Docker, nudi runs as many episodes at once as the task's declared CPUs and memory fit within 90% of Docker's CPUs and memory. On a Docker host with 2 CPUs, sandboxes ran one at a time.
- At least 10 GiB free where records go, and where Docker stores its data. nudi refuses to start with less. This minimum is checked once at the start and is no bound on what a run uses. nudi measures Docker's space only for a daemon on the same host that it reaches through a local `unix://` socket, not for Docker Desktop, another virtual machine or a remote daemon. On Docker Desktop, Colima or OrbStack, check the virtual machine's disk size in its settings; `docker system df` shows what Docker already uses. A full Docker disk fails each build, start or copy; three failed starts in a row of the task's environment stop the run. On Docker, nudi does not copy a container whose writable layer, as Docker reports it, exceeds 2 GiB. In one measured run the copies reached 8.5 GB in all. The hack inspector may test whether a task can exhaust disk space by filling its sandbox's disk. On Docker this fills the disk where Docker stores data until the sandbox is removed; nudi does not limit it.
- An OpenAI-compatible inference provider and an API key for the simulator, inspector and attacker roles. Supply keys through a credentials file outside the task folder, or through environment variables. Supply `nudi.toml` when changing providers, as described below.
- A new or empty output directory outside the task folder, passed with `--output` or set in TOML.
- Time: plan for hours. The measured setup was `nudi send-nudis <task> --backend modal --analysis hacking --episodes 2`, with DeepSeek v4.1 flash 1017 for nudi's agents and `--concurrency 24`. Three tasks took about 4 h 20 min ($1.41 model cost), 5 h 16 min ($2.91), and 5 h 10 min ($1.62). Modal compute is billed separately: `report.json` records estimates under `configuration.modal_cost`, about $0.40 to $0.65 per run at requested sizes, up to about $5 to $7.50 at resource limits. These are measurements and compute estimates, not bounds. See [Usage](usage.md#run-an-analysis) for the full command.
- Cost: there is no spending cap unless you set `--spending-cap`. The cap counts known inference cost only; Modal bills its sandboxes separately.

A run's first line states what it found: the backend, the CPUs and memory, the free space, the spending cap and the concurrency.

## Install v0.5.0

Install the release tag in a virtual environment:

```sh
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install "nudi @ git+https://github.com/standardnormal-ai/nudi.git@v0.5.0"
nudi --version
nudi --help
```

`nudi --version` prints the installed version, from the package metadata.

Without `python3.12`, install Python 3.12 first, for example with `uv python install 3.12`, `brew install python@3.12` or from python.org.

Only the direct dependencies are pinned, in [pyproject.toml](../pyproject.toml); the packages they depend on resolve at install time, so two installs can differ in those.

The terminal viewer `nudi-view` is a separate Go program and needs Go 1.27.3 or later to build; see [Viewer](usage.md#viewer).

## Configure credentials

Without `--config`, every role uses the default model, `openai/deepseek/deepseek-v4.1-flash-1017` through the Merge gateway at `https://api-gateway.merge.dev/v1/openai`, and reads its key from `MERGE_GATEWAY_API_KEY`.

For that setup, put `MERGE_GATEWAY_API_KEY=your-key` in a credentials file outside the task folder and pass `--credentials-file /path/to/credentials.env`. The key must have access to that model. An environment variable with the same name also works.

To use another OpenAI-compatible inference provider, set its API key in your shell:

```sh
export INFERENCE_API_KEY='your-key'
```

Create `nudi.toml` using the [model configuration example](usage.md#models), and set your provider's endpoint and model for all three roles. Pass `--config nudi.toml` when running nudi. You can also load the key from a dotenv file with `--credentials-file /path/to/credentials.env`.

## Check Docker

```sh
docker info
```

Docker needs enough CPU and memory for the task's declared resources and inspection containers. nudi checks available capacity at startup. A run keeps up to `--concurrency` sandboxes alive at once, including inspection workspaces and experiments; a container that does not fit waits until another ends. One inspection workspace may still admit one experiment, even at `--concurrency 1`, and a task's helper containers can exceed the setting.

## Optional Modal backend

```sh
python -m pip install "nudi[modal] @ git+https://github.com/standardnormal-ai/nudi.git@v0.5.0"
modal setup
```

Run with `--backend modal` after authenticating a Modal account with sandbox access and billing enabled. Inference credentials are still required.

Continue with [Usage](usage.md) or return to the [README](../readme.md).

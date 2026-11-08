# Installation

A run needs either a running Docker daemon or a Modal account for its sandboxes. nudi also requires Python 3.12, and model calls require credentials for the configured inference provider.

## Requirements

- Python 3.12 on the host that runs nudi.
- Docker, or a Modal account for `--backend modal`, which needs no Docker. On Docker, nudi runs as many episodes at once as the task's declared CPUs and memory fit within 90% of Docker's CPUs and memory. On a Docker host with 2 CPUs, sandboxes ran one at a time.
- At least 10 GiB free where records go, and where Docker stores its data. nudi refuses to start with less. This minimum is checked once at the start and is no bound on what a run uses. nudi measures Docker's space only for a daemon on the same host that it reaches through a local `unix://` socket, not for Docker Desktop, another virtual machine or a remote daemon. On Docker Desktop, Colima or OrbStack, check the virtual machine's disk size in its settings; `docker system df` shows what Docker already uses. A full Docker disk fails each build, start or copy; three failed starts in a row of the task's environment stop the run. On Docker, nudi does not copy a container whose writable layer, as Docker reports it, exceeds 2 GiB. In one measured run the copies reached 8.5 GB in all. The hack inspector may test whether a task can exhaust disk space by filling its sandbox's disk. On Docker this fills the disk where Docker stores data until the sandbox is removed; nudi does not limit it.
- An OpenAI-compatible inference provider and an API key for the simulator, inspector and attacker roles.
- Time: plan for hours. One full analysis on a 2-CPU Docker host with `--episodes 5 --focused-attempts 1 --attacker-tries 1` was stopped after about 5 hours, at about 7.5 minutes per Simulator episode; finishing it would have taken an estimated 6 hours. The defaults are 12, 2 and 1, and each added episode or attempt adds time. `--time-limit` bounds a run.
- Cost: there is no spending cap unless you set `--spending-cap`. The cap counts known inference cost only; Modal bills its sandboxes separately.

A run's first line states what it found: the backend, the CPUs and memory, the free space, the spending cap and the concurrency.

## Install from source

Clone the repository and install from its checkout:

```sh
git clone https://github.com/standardnormal-ai/nudi
cd nudi
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
nudi --version
nudi --help
```

`nudi --version` prints the installed version, from the package metadata.

Without `python3.12`, install Python 3.12 first, for example with `uv python install 3.12`, `brew install python@3.12` or from python.org.

Only the direct dependencies are pinned, in [pyproject.toml](../pyproject.toml); the packages they depend on resolve at install time, so two installs can differ in those.

The terminal viewer `nudi-view` is a separate Go program and needs Go 1.27.3 or later to build; see [Viewer](usage.md#viewer).

## Configure credentials

Without `--config`, every role uses the default model, `openai/deepseek/deepseek-v4.1-flash-1017` through the Merge gateway at `https://api-gateway.merge.dev/v1/openai`, and reads its key from `MERGE_GATEWAY_API_KEY`.

To use another OpenAI-compatible inference provider, set its API key in your shell:

```sh
export INFERENCE_API_KEY='your-key'
```

Create `nudi.toml` using the [model configuration example](usage.md#models), and set your provider's endpoint and model for all three roles. Pass `--config nudi.toml` when running nudi. You can also load the key from a dotenv file with `--credentials-file /path/to/credentials.env`.

## Check Docker

```sh
docker info
```

Docker needs enough CPU and memory for the task's declared resources and inspection containers. nudi checks available capacity at startup. A run keeps up to `--concurrency` sandboxes alive at once, including inspection workspaces and experiments. One inspection workspace may still admit one experiment, even at `--concurrency 1`, and a task's helper containers can exceed the setting.

## Optional Modal backend

```sh
python -m pip install -e '.[modal]'
modal setup
```

Run with `--backend modal` after configuring your Modal account. Inference credentials are still required.

Continue with [Usage](usage.md) or return to the [README](../readme.md).

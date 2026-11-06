# Installation

nudi requires Python 3.12 and a running Docker daemon for local sandboxes. Model calls require credentials for the configured inference provider.

## Install from source

From a checkout of this repository:

```sh
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
nudi --help
```

Dependencies are pinned in [pyproject.toml](../pyproject.toml). Install from this checkout to use this project's package and dependency versions.

## Configure credentials

Use an OpenAI-compatible inference provider. Set its API key in your shell:

```sh
export INFERENCE_API_KEY='your-key'
```

Create `nudi.toml` using the [model configuration example](usage.md#models), and set your provider's endpoint and model for all three roles. Pass `--config nudi.toml` when running nudi. You can also load the key from a dotenv file with `--credentials-file /path/to/credentials.env`.

## Check Docker

```sh
docker info
```

Docker needs enough CPU and memory for the task's declared resources and inspection containers. nudi checks available capacity at startup.

## Optional Modal backend

```sh
python -m pip install -e '.[modal]'
modal setup
```

Run with `--backend modal` after configuring your Modal account. Inference credentials are still required.

Continue with [Usage](usage.md) or return to the [README](../readme.md).

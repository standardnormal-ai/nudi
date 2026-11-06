# Usage

See [Installation](installation.md) for Python, sandbox and inference setup. First create `nudi.toml` with your provider's settings as described under [Models](#models).

## Run an analysis

Pass a local Harbor task directory containing its task configuration, instructions, environment and grader:

```sh
nudi send-nudis /path/to/task --config nudi.toml --output runs/first
```

The output directory must be new or empty. nudi copies the task for its work and preserves the original task directory.

The default `full` analysis runs hack inspection, Attacker attempts, ordinary simulation and grader inspection. Select a subset with `--analysis`:

```sh
nudi send-nudis /path/to/task --config nudi.toml --analysis hacking --output runs/hacking
nudi send-nudis /path/to/task --config nudi.toml --analysis simulation --episodes 20 --output runs/simulation
```

## Options

| Option | Default | Meaning |
| --- | --- | --- |
| `--analysis` | `full` | `full`, `hacking` or `simulation` |
| `--episodes` | `20` | Ordinary Simulator episodes |
| `--focused-attempts` | `2` | Focused attempts per grader inspector or hack inspection category |
| `--attacker-tries` | `2` | Maximum Attacker attempts per candidate and hint level |
| `--discovery-attempts` | `1` | Independent Attacker attempts without hints |
| `--isolated-inspections` | Off | Inspect each ordinary episode in a separate grader investigation |
| `--backend` | `docker` | `docker` or `modal` |
| `--concurrency` | `8` | Container limit, also constrained by local Docker capacity |
| `--spending-cap` | Unset | Stop admitting model calls when known inference cost reaches this USD amount |
| `--time-limit` | Unset | Whole-run limit in minutes. At the limit the run stops, cleans up and reports, as Ctrl-C does |
| `--credentials-file` | Unset | Dotenv file of inference credentials |
| `--config` | Unset | TOML configuration file |
| `--output` | Required, here or in TOML | New or empty run directory |

Calls already admitted can exceed the spending cap. Unknown inference costs remain unknown; the cap is not a strict billing limit. Modal sandbox costs are separate from the inference cap.

Some tasks take hours, so the time limit has no default. On Modal, each sandbox of a time-limited run also gets a lifetime of the limit plus 15 minutes, at most 24 hours.

Use `nudi send-nudis --help` for the complete CLI options.

## Models

Configure your OpenAI-compatible provider for the `simulator`, `inspector` and `attacker` roles under `[models.<role>]`. Set all three roles so every model call uses your chosen provider. Each configured role replaces that role's default model settings in full.

Replace `your-model` with your provider's model ID and `https://api.your-provider.com/v1` with its OpenAI-compatible base URL. Keep the `openai/` prefix to select the OpenAI-compatible API:

```toml
output_dir = "runs/configured"
analysis = "full"
episodes = 20

[models.simulator]
model = "openai/your-model"
api_base = "https://api.your-provider.com/v1"
api_key_var = "INFERENCE_API_KEY"

[models.inspector]
model = "openai/your-model"
api_base = "https://api.your-provider.com/v1"
api_key_var = "INFERENCE_API_KEY"

[models.attacker]
model = "openai/your-model"
api_base = "https://api.your-provider.com/v1"
api_key_var = "INFERENCE_API_KEY"
```

Save it as `nudi.toml`, then run:

```sh
nudi send-nudis /path/to/task --config nudi.toml
```

CLI options override TOML values. Relative `output_dir` and `credentials_file` paths in TOML resolve against the configuration file's directory. `api_key_var` names an environment variable; keep credentials out of the TOML file.

## Reports

Each run writes `report.md` and `report.json` beside its retained records and evidence. The CLI also prints the Markdown report. Completion refers to the selected analyses. An incomplete investigation or missing evidence must not be read as evidence that a task has no flaws.

Grader classification rates require a supported binary reward contract. Unresolved cases are reported separately. Grading analysis for non-binary rubric totals is not supported.

| Exit code | Meaning |
| --- | --- |
| `0` | Selected analyses complete, or the time limit reached with no phase failed before it |
| `1` | Partial result, including a phase that failed before the time limit, or records storage exhausted |
| `2` | Invalid configuration or startup failure |
| `130` | Interrupted with Ctrl-C; the written report is printed too |

## Modal cost

On Modal, the report shows an estimated sandbox cost range. Each run's sandboxes go in their own Modal App, `nudi-<run id>`, so the real bill can be read later:

```sh
nudi cost runs/first
```

It prints Modal's bill for that run's sandboxes and exits `0`, or prints one line saying why not, such as when to try again, and exits `1`. Modal reports whole hours, about 10 minutes after each hour ends, and only on Team and Enterprise plans. The bill is before credits and covers sandboxes only. nudi monitors this cost and never limits it.

## Python API

```python
from nudi import send_nudis

result = send_nudis(
    "/path/to/task",
    config="nudi.toml",
    output_dir="runs/python",
    analysis="hacking",
)
```

Use `await send_nudis_async(...)` from an existing async event loop. The Python API accepts the same configuration fields as the CLI, using underscores in option names.

Return to the [README](../readme.md).

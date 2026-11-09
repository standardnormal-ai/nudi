# report.json and summary.json fields

The fields a script or coding agent reads. Both files hold more; [Usage](usage.md#reports) explains them. Keys not listed here can change without notice.

## report.json

| Field | Type | Values |
| --- | --- | --- |
| `schema_version` | integer | `1`. Raised when a listed field changes meaning or goes away; absent in reports written before it |
| `status` | string | `complete`: every selected step ran to its end. `time_limit`: the time limit ended the run with no phase failed before it. `partial`: a step failed, stopped, as at the spending cap, or never ran. `stopped`: written by `nudi report` for a run whose process ended without closing it out |
| `outcome` | string | The Answer's first line: how the run ended, in plain words |
| `answer` | list of strings | `outcome`, then the verdict line, then a few lines on what was found |
| `unfinished` | object | Each step that did not run to its end, mapped to its status |
| `unresolved` | list of strings | Each step that ran to its end with evidence left unresolved |
| `analyses` | object | Each selected step, `simulation`, `grader`, `hack` or `attack`, mapped to its status, such as `complete`, `partial`, `cancelled`, `spending_exhausted`, `running` or `not run` |
| `attack.problems` | list | One entry per problem, below; `attack` is null when the attack was not selected |
| `labels.counts` | object | Ordinary episodes per grader inspector label: `accepted_invalid`, `rejected_valid`, `legitimate`, `unknown`, `unavailable`, `ungrounded` or `unreviewed`; only labels that occur appear. `labels` is null without a grader inspection |
| `configuration.known_cost` | number | Known inference cost in US dollars |
| `configuration.unknown_cost_calls`, `configuration.cancelled_calls` | integer | Calls whose cost is unknown, and calls cancelled in flight; the known cost excludes both |
| `configuration.unknown_reasons` | object | Each reason a call has no price, mapped to its count |
| `inspections.<inspector>.open` | list | What kept a category, or a grader inspector's ordinary episode, unsettled when the inspection ended: each entry's `id` (an experiment, episode or category), `category` (null for an ordinary episode), `reason` and `next` step. Empty when nothing was left open; absent in older reports |
| `warnings` | list of strings | Everything that limits the results |

The exit code follows `status`: `0` for `complete`, `1` for the others, `time_limit` included.

Each entry of `attack.problems`:

| Field | Type | Values |
| --- | --- | --- |
| `id` | string or null | `P1`, `P2` ... from the hack inspector, `G1` ... from the grader inspector, `A1` ... from an Attacker with no hint; null in older reports |
| `source` | string or null | `hack inspector`, `grader inspector` or `Attacker` |
| `level` | integer | 2 to 5, which orders the problems, as in [Usage](usage.md#reports) |
| `label` | string | The level's words, such as `●●●○○ exploit executable by learner with full information`, or `Correct work failed` and how an Attacker reproduced it; for a problem a rerun kept and did not find again, `evidenced in run DIR at LABEL; not found again here` |
| `exploited_with` | string | The least information under which an Attacker exploit was observed, `none`, `minimal` or `full`, an order and not the help needed; otherwise `not_exploited`, `no_guidance` or `unknown`. Older reports have `help_needed` |
| `conditions` | list of objects | Each condition an Attacker tried it under, in order: `condition` (`full`, `minimal`, `none` aimed at it; `elsewhere_full`, `elsewhere_minimal`, `elsewhere_none` aimed at another problem, listed only when one of those attempts exploited it; or `independent`, the no-hint search), `attempts` started, how many `exploited` it, the Attacker `model` and the `status` |
| `scope` | string or null | Where its findings were evidenced, `package` or `native` (native when any is); null without the inspections. At level 2 `report.md` and the viewer give it after the label |
| `cause` | string | One line |
| `findings` | list of strings | The inspector findings this cause explains, as `hack-INDEX` or `grader-INDEX` |
| `candidate` | string or null | The finding the attack tested |
| `reproduced` | boolean | An Attacker reproduced it |
| `cases` | list of objects | Each finding or Attacker exploit as the judge read it: `id`, `check`, `outcome`, `mechanism`, `location`, `capture_point` |
| `origin` | string or null | The earlier run a rerun took the problem from |
| `earlier_exploited_with` | string or null | Its `exploited_with` in that earlier run |

`attack.leads` lists the problems of an older record that no evidence confirmed, each with its `id` and `cause`; they have no level.

### Names of the inspectors

Each file spells the same inspector by field:

| Where | Hack inspector | Grader inspector | Attack |
| --- | --- | --- | --- |
| `attack.problems[].source` | `hack inspector` | `grader inspector` | `Attacker` |
| `attack.candidates[].source`, keys of `inspections` | `hack_inspector` | `grader_inspector` | |
| Keys of `analyses`, `unfinished`, `unresolved`; `phase` and `inspector` in `events.jsonl` | `hack` | `grader` | `attack` |

`--analysis hacking` selects the steps `hack` and `attack`, `--analysis simulation` the steps `simulation` and `grader`.

## summary.json

A batch of several environments writes `summary.json` in the batch folder.

| Field | Type | Values |
| --- | --- | --- |
| `status` | string | `complete`, `time_limit`, `partial`, `cancelled` after Ctrl-C or `terminated` after SIGTERM. A batch in which no environment started is `partial` with `exit_code` `2` |
| `exit_code` | integer | The command's exit code |
| `environments` | list | One row per task, below |

Each row of `environments`:

| Field | Type | Values |
| --- | --- | --- |
| `name`, `task_dir`, `run_dir` | string | The run folder's name, the task and the run folder |
| `status` | string | `complete`, `time_limit`, `partial`, `stopped`, `refused`, `not_started`, `cancelled` or `terminated`, as the table in [Usage](usage.md#several-environments) explains |
| `exit_code` | integer or null | The exit code the environment would have alone; null for `not_started` |
| `execution` | string or null | The run's `outcome`; null when no report was written, as for a refused environment, whose reason is in `error` |
| `answer` | string or null | The run's verdict line |
| `known_cost` | number or null | From its `report.json` |
| `error` | string or null | Why it was refused or stopped |

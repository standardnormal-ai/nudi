# report.json and summary.json fields

The fields a script or coding agent reads. Both files hold more; [Usage](usage.md#reports) explains them. Keys not listed here can change without notice.

## report.json

| Field | Type | Values |
| --- | --- | --- |
| `schema_version` | integer | `1`. Raised when a listed field changes meaning or goes away; absent in reports written before it |
| `status` | string | `complete`: every selected step ran to its end. `time_limit`: the time limit ended the run with no phase failed before it. `partial`: a step failed, stopped, as at the spending cap, or never ran. `stopped`: the model provider refused a call for the account, or written by `nudi report` for a run whose process ended without closing it out. `running`: the report so far, which the run rewrites after each confirmation while it goes; the final report replaces it |
| `outcome` | string | The Answer's first line: how the run ended, in plain words |
| `answer` | list of strings | `outcome`, then the verdict line, then one line per problem with its label and how many assessed attempts exploited it, and lines only when present: what no problem holds, each hack family a deserved reward used, an attack-only rerun |
| `unfinished` | object | Each step that did not run to its end, mapped to its status |
| `unresolved` | list of strings | Each step that ran to its end with evidence left unresolved |
| `elapsed` | number or null | The run's duration in seconds, from its start to the end of its analyses; null when the record lacks either time, as after a killed process |
| `stop` | object or null | Why the run stopped before its end; null for a run that ended on its own. `kind`: `cancelled` (Ctrl-C), `terminated` (SIGTERM), `time_limit`, `spending_cap`, `provider_refused` (the model provider refused a call for the account) or `stopped` (`nudi report` for a run that did not close out); `phase`, the step it stopped, or the steps joined by `and`, null when not recorded; `minutes`, the time limit, null when not recorded; `reason`, the words `nudi report` gives or the provider's refusal, otherwise null |
| `phase_errors` | object | Each step that raised an error, mapped to that error |
| `ungrouped` | list of strings | Evidenced inspector findings, each check's latest reading, that no entry of `attack.problems` includes, as `grader-INDEX` or `hack-INDEX`; all of them when the attack was not selected |
| `analyses` | object | Each selected step, `simulation`, `grader`, `hack` or `attack`, mapped to its status, such as `complete`, `partial`, `cancelled`, `spending_exhausted`, `running` or `not run`; in a report so far, `not started` for one with no record yet |
| `attack.problems` | list | One entry per problem, below; `attack` is null when the attack was not selected |
| `attack.attempts[].failed` | string or null | The agent whose failure ended the attempt, `Attacker` (its `status` is then the Attacker's failure, such as `episode_failure` when the episode ended without a reward and without a model call) or `attack inspector` (the Attacker's `rewards` stay); null otherwise and in older reports |
| `labels.counts` | object | Ordinary episodes per grader inspector label: `accepted_invalid`, `rejected_valid`, `legitimate`, `unknown`, `unavailable`, `ungrounded` or `unreviewed`; only labels that occur appear. `labels` is null without a grader inspection |
| `configuration.known_cost` | number | Known inference cost in US dollars |
| `configuration.unknown_cost_calls`, `configuration.cancelled_calls` | integer | Calls whose cost is unknown, and calls cancelled in flight; the known cost excludes both |
| `configuration.unknown_reasons` | object | Each reason a call has no price, mapped to its count |
| `attack.attempts[].status` `no_reward` | string | The Attacker made model calls and the grader wrote no reward: nothing to judge, and no failure to run, so `failed` is null |
| `ordinary.no_reward` | object | Each Simulator episode without a finite reward mapped to its `model_calls`; empty when every episode has one |
| `ordinary.retries` | object | Each fresh Simulator episode mapped to the one it replaced, an episode that ended without a reward and without a model call; the replaced one keeps its failures |
| `ordinary.groups[].episode_rewards` | object | Each ordinary episode of the group mapped to its rewards by key; null for a value that is not a finite number |
| `ordinary.groups[].rewards.<key>.flags` | list | Each reward pattern: `flag` (`identical_rewards`, `low_minority` or `high_minority`), its `episodes`, `text`, `quartiles` (Q1 and Q3 of a minority flag, else null), `fence` (the outer fence, Q1 - 3 IQR or Q3 + 3 IQR, else null), `minimum` (the usable rewards a flag needs) and `recorded`: for each of its episodes `agent_timeout`, `verifier_timeout`, `errors` (error types) and `refusals` (refusal signals). A flag is not a finding and changes no rate or result |
| `inspections.<inspector>.open` | list | What kept a category, or a grader inspector's ordinary episode, unsettled when the inspection ended: each entry's `id` (an experiment, episode or category), `category` (null for an ordinary episode), `reason` and `next` step. Empty when nothing was left open; absent in older reports |
| `inspections.<inspector>.findings.<result>[].claim.use` | object or null | A hack or grader inspector reading's hack family route that its episode used: `category`, the family, a lower-case name of at most 64 letters, digits, spaces, `_` or `-`, and `rule`, the task's own rule on that route, `forbids` or `allows` (the check's `requirement` states it) or `none` (the task states no rule); null when the reading records none, and absent in older reports |
| `inspections.<inspector>.suspected` | list | Each suspected exploit, `report.md`'s "●○○○○ suspected exploit": its `category` and `check`, a measured experiment, not replaced by a later one, whose latest reading ended unknown, unfinished included, in a category where no evidenced reading has the same case: the same case name, episode or package, location and capture point. Never a problem. Absent in older reports |
| `warnings` | list of strings | Everything that limits the results |

The exit code follows `status`: `0` for `complete`, `1` for the others, `time_limit` included.

Each entry of `attack.problems`:

| Field | Type | Values |
| --- | --- | --- |
| `id` | string or null | `P1`, `P2` ... from the hack inspector, `G1` ... from the grader inspector, `A1` ... from an Attacker with no hint; null in older reports |
| `source` | string or null | `hack inspector`, `grader inspector` or `Attacker` |
| `level` | integer | 2 to 5, which orders the problems, as in [Usage](usage.md#reports) |
| `label` | string | The level's words, such as `●●●○○ exploit executable by learner with full information`, with ` (its help was for another problem)` after them for an `elsewhere_` value, or `Correct work failed` and how an Attacker reproduced it; for a problem a rerun kept and did not find again, `evidenced in run DIR at LABEL; not found again here` |
| `exploited_with` | string | The least information under which an Attacker exploit was observed, `none`, `minimal`, `elsewhere_minimal`, `full` or `elsewhere_full`, an order and not the help needed; `elsewhere_` means only an attempt given that help for another problem exploited it; otherwise `not_exploited`, `no_guidance` or `unknown`. Older reports have `help_needed` |
| `conditions` | list of objects | Each condition an Attacker tried it under, in order: `condition` (`full`, `minimal`, `none` aimed at it; `elsewhere_full`, `elsewhere_minimal`, `elsewhere_none` aimed at another problem, listed only when one of those attempts exploited it; or `independent`, the no-hint search), `attempts` assessed, how many `exploited` it, the Attacker `model`, the `status`, and, when any, `not_assessed`, the attempts that did not run or were not judged, such as at an inference failure, a cancellation or a timeout without reward, each with its `episode`, `status`, `reward` and `error`; they are not in `attempts` |
| `scope` | string or null | Where its findings were evidenced, `package` or `native` (native when any is); null without the inspections. At level 2 `report.md` and the viewer give it after the label |
| `cause` | string | The judge's one sentence naming what the grader wrongly trusts, from the verdict that made the problem; its first finding's mechanism when that judge call failed, and in older reports |
| `findings` | list of strings | The inspector findings this cause explains, as `hack-INDEX` or `grader-INDEX` |
| `candidate` | string or null | The finding the attack tested |
| `reproduced` | boolean | An Attacker reproduced it |
| `outcome` | string or null | `accepted_invalid` (incorrect work passed) or `rejected_valid` (correct work failed), from its findings and cases; null when they disagree or record none |
| `family` | string or null | For a problem whose findings are all hack findings of category `other`, the hack family its first reading proposed, a short phrase; null otherwise and in older reports |
| `evidenced_by_inspector` | boolean or null | The latest reading of one of its inspector findings is evidenced; false for a problem only an Attacker found; null without the inspections |
| `cases` | list of objects | Each finding or Attacker exploit as the judge read it: `id`, `check`, `outcome`, `mechanism`, `category`, `family` (an `other` reading's), `location`, `capture_point`, each present when known, and its verdict's `cause`, the trust it matched, and `reason`, one sentence on why; both null when the judge call failed, and absent in older reports. Two readings of one Attacker attempt are two cases, while `members` lists the attempt once |
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

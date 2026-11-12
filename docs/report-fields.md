# report.json and summary.json fields

The fields a script or coding agent reads. Both files hold more; [Usage](usage.md#reports) explains them. Keys not listed here can change without notice.

## report.json

| Field | Type | Values |
| --- | --- | --- |
| `schema_version` | integer | `2`; `1` before `problems` replaced `attack.problems` levels by group. Raised when a listed field changes meaning or goes away; absent in reports written before it |
| `status` | string | `complete`: every selected step ran to its end. `time_limit`: the time limit ended the run with no phase failed before it. `partial`: a step failed, stopped, as at the spending cap, or never ran. `stopped`: the model provider refused a call for the account, or written by `nudi report` for a run whose process ended without closing it out. `running`: the report so far, which the run rewrites after each confirmation while it goes; the final report replaces it |
| `outcome` | string | The Answer's first line: how the run ended, in plain words |
| `answer` | list of strings | `outcome`, then the verdict line, then one line per problem with a level, by its id: its reward, the marks its check measured, its level's words and how many assessed attempts reproduced it, then one line per reading without marks: what its check measured and why nudi makes no claim from it |
| `unfinished` | object | Each step that did not run to its end, mapped to its status |
| `unresolved` | list of strings | Each step that ran to its end with evidence left unresolved |
| `elapsed` | number or null | The run's duration in seconds, from its start to the end of its analyses; null when the record lacks either time, as after a killed process |
| `stop` | object or null | Why the run stopped before its end; null for a run that ended on its own. `kind`: `cancelled` (Ctrl-C), `terminated` (SIGTERM), `time_limit`, `spending_cap`, `provider_refused` (the model provider refused a call for the account) or `stopped` (`nudi report` for a run that did not close out); `phase`, the step it stopped, or the steps joined by `and`, null when not recorded; `minutes`, the time limit, null when not recorded; `reason`, the words `nudi report` gives or the provider's refusal, otherwise null |
| `phase_errors` | object | Each step that raised an error, mapped to that error |
| `problems` | list | One entry per problem, below, each with its own level and counts; no agent merges two |
| `ungrouped` | list of strings | Inspector problems the judge named no problem for, as `grader-INDEX` or `hack-INDEX`; all of them when the attack was not selected |
| `analyses` | object | Each selected step, `simulation`, `grader`, `hack` or `attack`, mapped to its status, such as `complete`, `partial`, `cancelled`, `spending_exhausted`, `running` or `not run`; in a report so far, `not started` for one with no record yet |
| `attack.problems` | list | The same entries as `problems`; `attack` is null when the attack was not selected |
| `attack.attempts[].reproduced` | boolean or null | The rerun of the target's check on the attempt's episode measured the target's marks as the target's own reading did (`true`), otherwise (`false`), or gave no result (`null`, also before a rerun and for a no-hint attempt) |
| `attack.attempts[].rerun` | string or null | Why `reproduced` is not `true` for an aimed attempt, such as the target's reading changed since the attempt started, or no rerun was recorded; null otherwise |
| `attack.attempts[].sources` | list of strings | The findings whose guidance the attempt ran: first the reading it used, the latest one of its check when the attempt started, then the others its problem held |
| `attack.attempts[].counts_for` | string or null | The id of the problem this attempt reproduced, which only a confirming rerun gives; null otherwise |
| `attack.attempts[].created` | string or null | The id of the problem this attempt's exploit became, one no rerun confirmed or a no-hint one; null otherwise |
| `attack.attempts[].failed` | string or null | The agent whose failure ended the attempt, `Attacker` (its `status` is then the Attacker's failure, such as `episode_failure` when the episode ended without a reward and without a model call) or `attack inspector` (the Attacker's `rewards` stay); null otherwise and in older reports |
| `labels.counts` | object | Ordinary episodes per grader inspector label: `accepted_invalid`, `rejected_valid`, `legitimate`, `unknown`, `unavailable`, `ungrounded` or `unreviewed`; only labels that occur appear. `labels` is null without a grader inspection |
| `configuration.known_cost` | number | Known inference cost in US dollars |
| `configuration.unknown_cost_calls`, `configuration.cancelled_calls` | integer | Calls whose cost is unknown, and calls cancelled in flight; the known cost excludes both |
| `configuration.unknown_reasons` | object | Each reason a call has no price, mapped to its count |
| `attack.attempts[].status` `no_reward` | string | The Attacker made model calls and the grader wrote no reward: nothing to judge, and no failure to run, so `failed` is null; `error` says why |
| `ordinary.no_reward` | object | Each Simulator episode without a finite reward mapped to its `model_calls`; empty when every episode has one |
| `ordinary.retries` | object | Each fresh Simulator episode mapped to the one it replaced, an episode that ended without a reward and without a model call; the replaced one keeps its failures |
| `ordinary.groups[].episode_rewards` | object | Each ordinary episode of the group mapped to its rewards by key; null for a value that is not a finite number |
| `ordinary.groups[].rewards.<key>.flags` | list | Each reward pattern: `flag` (`identical_rewards`, `low_minority` or `high_minority`), its `episodes`, `text`, `quartiles` (Q1 and Q3 of a minority flag, else null), `fence` (the outer fence, Q1 - 3 IQR or Q3 + 3 IQR, else null), `minimum` (the usable rewards a flag needs) and `recorded`: for each of its episodes `agent_timeout`, `verifier_timeout`, `errors` (error types) and `refusals` (refusal signals). A flag is not a finding and changes no rate or result |
| `inspections.<inspector>.open` | list | What kept a category, or a grader inspector's ordinary episode, unsettled when the inspection ended: each entry's `id` (an experiment, episode or category), `category` (null for an ordinary episode), `reason` and `next` step. Empty when nothing was left open; absent in older reports |
| `inspections.<inspector>.findings.<result>[].claim.marks` | list of strings | The observation names of its check that show the exploit; a reading without marks proves none, stays in `open` until it names them, and is a problem without a level |
| `inspections.<inspector>.suspected` | list | Each suspected exploit, `report.md`'s "●○○○○ suspected exploit": its `category` and `check`, a measured experiment, not replaced by a later one, whose latest reading ended unknown, unfinished included, in a category where no evidenced reading has the same case: the same case name, episode or package, location and capture point. Never a problem. Absent in older reports |
| `warnings` | list of strings | Everything that limits the results |

The exit code follows `status`: `0` for `complete`, `1` for the others, `time_limit` included.

Each entry of `problems`:

| Field | Type | Values |
| --- | --- | --- |
| `id` | string | `P1`, `P2` ... from the hack inspector, `G1` ... from the grader inspector, `A1` ... from an Attacker, as the judge numbered them; otherwise the finding id, `hack-INDEX`, `grader-INDEX`, or an Attacker's episode |
| `finding` | string | The finding or Attacker episode the problem comes from |
| `source` | string | Who found it: `hack inspector`, `grader inspector` or `Attacker` |
| `type` | string or null | `hack`, `false_positive` (invalid work the grader inspector saw accepted in the simulations) or `false_negative` (correct work failed), only when the approved requirement list confirms it: the reading reads an approved requirement violated, or for correct work failed every approved requirement supported. Null otherwise, also for a problem with marks and a level |
| `text` | string | Only for a reading without marks: what its check measured |
| `reason` | string or null | For a reading without marks, why nudi makes no claim from it; for work the grader failed that the list does not confirm, why completeness is unknown; null otherwise |
| `level` | integer or null | 2 to 5, which orders the problems, as in [Usage](usage.md#reports): the least help under which an Attacker exploit counted for it, else 2; for a problem an Attacker found, the help its own Attacker had. Null only for a reading without marks |
| `label` | string or null | The level's words, such as `●●●○○ exploit executable by learner with full information`, or for work the grader failed `Correct work failed` when the list confirms the work correct, else `Work the grader failed`, then how an Attacker reproduced it |
| `note` | object | Present only when an agent read it as another problem: `target`, that problem's id, and `kind`, `same_as`. It changes no level, count or scheduling |
| `conditions` | list of objects | For an inspector problem, each condition an Attacker tried it under, in order: `condition` (`full`, `minimal`, `none`), `attempts` assessed, how many `exploited` it, as only a confirming rerun counts, the Attacker `model`, the `status`, and, when any, `not_assessed`, the attempts that did not run or were not judged, each with its `episode`, `status`, `reward` and `error` |
| `attempts`, `reproduced` | integer or null | Assessed attempts aimed at it and how many reproduced it; null for an Attacker problem and without the attack |
| `help`, `target`, `kind` | string or null | For an Attacker problem: the help it had, the problem its help was for, and `discovery`, `other` (the rerun of its target's check did not reproduce the target), `unattributed` (the rerun gave no result) or `reproduction` (of a target no current problem holds); null for an inspector problem |
| `outcome`, `scope`, `reward`, `check` | | Its reading's outcome, `package` or `native`, reward and check |
| `marks` | object | Each mark of its reading mapped to the value its check measured |
| `requirement` | string or null | The approved requirement its reading reads violated; null without one or without an approved list |
| `unresolved`, `family` | | What its reading leaves open, and the hack family an `other` reading proposed |
| `cause`, `findings`, `members`, `cases` | | The judge's problem that took this id: its cause, findings, members and the cases it read; empty otherwise |
| `origin` | string or null | The earlier run a rerun took the problem from |

Older records keep their fields; a field they lack reads unknown. `exploited_with`, `exploited_by`, `evidenced_by_inspector`, `candidate`, the `elsewhere_` conditions and `claim.use` are gone.

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

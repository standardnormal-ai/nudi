# report.json and summary.json fields

The fields a script or coding agent reads. Both files hold more; [Usage](usage.md#reports) explains them. Keys not listed here can change without notice.

## report.json

| Field | Type | Values |
| --- | --- | --- |
| `schema_version` | integer | `3`; `2` before the rerun fields went and levels came from the help given, `1` before `problems` replaced `attack.problems` levels by group. Raised when a listed field changes meaning or goes away; absent in reports written before it |
| `status` | string | `complete`: every selected step ran to its end. `time_limit`: the time limit ended the run with no phase failed before it. `partial`: a step failed, stopped, as at the spending cap, or never ran. `stopped`: the model provider refused a call for the account, or written by `nudi report` for a run whose process ended without closing it out. `running`: the report so far, which the run rewrites after each confirmation while it goes; the final report replaces it |
| `outcome` | string | The Answer's first line: how the run ended, in plain words |
| `answer` | list of strings | `outcome`, then the verdict line, then, when `causes` lists any, the causes paragraph and one line per cause with its problems' lines beneath it, each starting `  - `, a problem in `not_attacked` ending with "not attacked on its own", then one line per other problem with a level, by its id: its reward, the marks its check measured, the help its Attacker had, its level's words and how many assessed attempts with its help were exploits, then one line per reading without marks: what its check measured and why nudi makes no claim from it. Without an approved list that confirms a problem, the verdict line counts the problems and those exploited by an Attacker given their help, or found by one, and says that nudi does not say which task rule each breaks |
| `unfinished` | object | Each step that did not run to its end, mapped to its status |
| `unresolved` | list of strings | Each step that ran to its end with evidence left unresolved |
| `elapsed` | number or null | The run's duration in seconds, from its start to the end of its analyses; null when the record lacks either time, as after a killed process |
| `stop` | object or null | Why the run stopped before its end; null for a run that ended on its own. `kind`: `cancelled` (Ctrl-C), `terminated` (SIGTERM), `time_limit`, `spending_cap`, `provider_refused` (the model provider refused a call for the account) or `stopped` (`nudi report` for a run that did not close out); `phase`, the step it stopped, or the steps joined by `and`, null when not recorded; `minutes`, the time limit, null when not recorded; `reason`, the words `nudi report` gives or the provider's refusal, otherwise null |
| `phase_errors` | object | Each step that raised an error, mapped to that error |
| `problems` | list | One entry per problem, below, each with its own level and counts; no agent merges two |
| `ungrouped` | list of strings | Inspector problems the judge named no problem for, as `grader-INDEX` or `hack-INDEX`; all of them when the attack was not selected |
| `analyses` | object | Each selected step, `simulation`, `grader`, `hack` or `attack`, mapped to its status, such as `complete`, `partial`, `cancelled`, `spending_exhausted`, `running` or `not run`; in a report so far, `not started` for one with no record yet |
| `attack.problems` | list | The same entries as `problems`; `attack` is null when the attack was not selected |
| `causes` | list | The shown problems by cause, as a judge compared each new finding's cause sentence with the known ones when both existed, a reading; only a cause of two or more shown problems, or with a reading, also one none of whose problems is shown: each cause's `id` (`C1` ...), `cause` (one sentence on what the grader trusts, its first problem's), `problems` (ids, highest level first), `not_attacked` (the problems after its first that no Attacker attacked), `readings` (the no-hint Attacker episodes whose attack inspector read their exploit as one of these problems' cause) and `level` and `label`: its problems' best, or 5 with such a reading. Each problem keeps its own level and counts. Empty without the attack, when the attack did not end, and in older reports; older reports have no `not_attacked`; nudi still reads stored attack records that list them under `holes`, with ids `H1` ... |
| `attack.attempts[].sources` | list of strings | The findings whose guidance the attempt ran: first the reading it used, the latest one of its check when the attempt started, then the others its problem held |
| `attack.attempts[].problem` | string or null | The problem its target was in when it started, the one its help was written for; for a no-hint attempt, the problem whose cause its attack inspector read its exploit as, a known one or the new Attacker problem it made |
| `attack.attempts[].failed` | string or null | The agent whose failure ended the attempt, `Attacker` (its `status` is then the Attacker's failure, such as `episode_failure` when the episode ended without a reward and without a model call) or `attack inspector` (the Attacker's `rewards` stay); null otherwise and in older reports |
| `labels.counts` | object | Ordinary episodes per grader inspector label: `accepted_invalid`, `rejected_valid`, `legitimate`, `unknown`, `unavailable`, `ungrounded` or `unreviewed`; only labels that occur appear. `labels` is null without a grader inspection |
| `configuration.known_cost` | number | Known inference cost in US dollars |
| `configuration.unknown_cost_calls`, `configuration.cancelled_calls` | integer | Calls whose cost is unknown, and calls cancelled in flight; the known cost excludes both |
| `configuration.unknown_reasons` | object | Each reason a call has no price, mapped to its count |
| `attack.attempts[].status` `no_reward` | string | The Attacker made model calls and the grader wrote no reward: nothing to judge, and no failure to run, so `failed` is null; `error` says why |
| `ordinary.no_reward` | object | Each Simulator episode without a finite reward mapped to its `model_calls` and `phase`: `agent work`, `grading` once nudi had copied its environment for grading, or null when it made no model call; empty when every episode has one |
| `configuration.approved_requirements` | integer | How many requirements the approved list names; `0` without a list |
| `ordinary.retries` | object | Each fresh Simulator episode mapped to the one it replaced, an episode that ended without a reward and without a model call; the replaced one keeps its failures |
| `ordinary.groups[].episode_rewards` | object | Each ordinary episode of the group mapped to its rewards by key; null for a value that is not a finite number |
| `ordinary.groups[].rewards.<key>.flags` | list | Each reward pattern: `flag` (`identical_rewards`, `low_minority` or `high_minority`), its `episodes`, `text`, `quartiles` (Q1 and Q3 of a minority flag, else null), `fence` (the outer fence, Q1 - 3 IQR or Q3 + 3 IQR, else null), `minimum` (the usable rewards a flag needs) and `recorded`: for each of its episodes `agent_timeout`, `verifier_timeout`, `errors` (error types) and `refusals` (refusal signals). A flag is not a finding and changes no rate or result |
| `inspections.<inspector>.open` | list | What kept a category, or a grader inspector's ordinary episode, unsettled when the inspection ended: each entry's `id` (an experiment, episode or category), `category` (null for an ordinary episode), `reason` and `next` step. Empty when nothing was left open; absent in older reports |
| `inspections.<inspector>.findings.<result>[].claim.cause` | string or null | The inspector's one sentence on what the grader trusts that the finding uses, which the judge compares with the known causes when the finding makes a new problem; for an attack inspector reading of a no-hint exploit, the `known_causes` id it used or a new sentence. Null in older reports, where the mechanism stands for it; nudi still reads it from records that name it `hole` |
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
| `type` | string or null | `hack`, `false_positive` (invalid work the grader inspector saw accepted in the simulations) or `false_negative` (correct work failed), only when the approved requirement list confirms it: the reading reads an approved requirement violated, or for correct work failed every approved requirement supported, read with the other readings of its simulation episode for a grader inspector reading, as the metrics read it. Null otherwise, also for a problem with marks and a level |
| `text` | string | Only for a reading without marks: what its check measured |
| `reason` | string or null | For a reading without marks, why nudi makes no claim from it; for work the grader failed that the list does not confirm, why completeness is unknown; null otherwise |
| `level` | integer or null | 2 to 5, which orders the problems, as in [Usage](usage.md#reports): the least help under which an Attacker given its help made an exploit, by any route, else 2; for a problem an Attacker found, the help its own Attacker had, 5 with no extra information. Null only for a reading without marks |
| `label` | string or null | The level's words, such as `●●●○○ exploit executable by learner with full information`, or for work the grader failed `Correct work failed` when the list confirms the work correct, else `Work the grader failed`, then how an Attacker reproduced it |
| `conditions` | list of objects | For an inspector problem, each condition an Attacker tried it under, in order: `condition` (`full`, `minimal`, `none`), `attempts` assessed, how many were exploits (`exploited`), the Attacker `model`, the `status`, and, when any, `unrewarded`, how many attempts the grader paid nothing, which nudi did not inspect and does not count as assessed, and `not_assessed`, the attempts that did not run or were not judged, each with its `episode`, `status`, `reward` and `error` |
| `attempts`, `reproduced`, `unrewarded` | integer or null | Assessed attempts given its help, how many of them were exploits, and how many more got reward 0 and were not inspected; null for an Attacker problem and without the attack |
| `help`, `target`, `kind` | string or null | For an Attacker problem, `help` is the help its Attacker had, such as `only a hint written for P3` or `no extra information`, and `kind` is `discovery` (no hint) or `reproduction` (of a finding no current problem holds); `target` is null. All null for an inspector problem |
| `outcome`, `scope`, `reward`, `check` | | Its reading's outcome, `package` or `native`, reward and check |
| `marks` | object | Each mark of its reading mapped to the value its check measured |
| `requirement` | string or null | The approved requirement its reading reads violated; null without one or without an approved list |
| `unresolved`, `family` | | What its reading leaves open, which `report.md` gives in the problem's entry of the Attack section, not in the Answer, and not for an inspector problem an Attacker reproduced; and the hack family an `other` reading proposed |
| `cause`, `findings`, `members`, `cases` | | The problem that took this id: its cause, the cause sentence of its first finding, its findings, members and cases; empty otherwise |
| `origin` | string or null | The earlier run a rerun took the problem from |

Older records keep their fields; a field they lack reads unknown. `exploited_with`, `exploited_by`, `evidenced_by_inspector`, `candidate`, the `elsewhere_` conditions and `claim.use` are gone, and so are the rerun fields `attack.attempts[].reproduced`, `rerun`, `rerun_check`, `noted`, `noted_reproduced`, `noted_rerun`, `counts_for` and `created`, the problems' `note` and the conditions' `written_for`. An older attack record still loads: its exploits are read again from its attack inspector readings, so an exploit made with a problem's help counts for that problem whatever its rerun measured.

`attack.leads` lists the judge's problems that no problem shows, each with its `id`, `cause` and `origin`, and no level: an inspector finding a later reading withdrew, or a problem of an older record or an earlier run. An Attacker problem made in this run that no problem shows, such as a further reading of one attempt, is no lead.

`attack.exploits` keys each exploit by its kind: `reproduction`, made with a problem's full information or hint, or `discovery`, made with no extra information. A `judged` event with `new` false says the attack inspector read a no-hint exploit as that `problem`'s cause, so it made no problem.

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

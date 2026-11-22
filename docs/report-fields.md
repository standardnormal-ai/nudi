# report.json and summary.json fields

These are the fields a script or coding agent reads. Both files hold more, and [Usage](usage.md#reports) explains them. Keys not listed here can change without notice.

## report.json

| Field | Type | Values |
| --- | --- | --- |
| `schema_version` | integer | `4`. Earlier values: `3` before `causes` held each finding and the per-finding list was removed, `2` before the rerun fields were removed and levels came from the help given, `1` before levels by group were replaced. It goes up when a listed field changes meaning or is removed. Absent in reports written before it existed |
| `status` | string | `complete`: every selected step ran to its end. `time_limit`: the time limit ended the run and no phase had failed before it. `unfinished`: a step failed, stopped (as at the spending cap) or never ran. `stopped`: the model provider refused a call for the account, or `nudi report` wrote the report for a run whose process ended without closing it out. `running`: the report so far, which the run rewrites after each confirmation; the final report replaces it |
| `outcome` | string | The Answer's first line: how the run ended, in plain words |
| `answer` | list of strings | In order: `outcome`; the verdict line; "An agent grouped the findings into causes; it can make mistakes." when a cause holds more than one finding or one judged to use it; one entry per cause with a level, highest first; then one line per interpretation without marks, saying what its check measured and why nudi makes no claim from it. A cause of one finding is one line: its id, its sentence and the finding's line. Any other cause gives its id, sentence and label, with each finding's line beneath it starting `  - ` and those with `read_as` true last; such an Attacker finding's line ends "judged to use this cause". A finding's line gives its id, reward, the marks its check measured, the help its Attacker had, its level's words and how many assessed attempts with its help were exploits (for `rejected_valid`, how many reproduced the work the grader failed). When findings have a level, the verdict line says whether the grader can be cheated, only in a copy of the task package when no cheat was evidenced in a native episode or reproduced by an Attacker, and whether it misjudges work |
| `unfinished` | object | Each step that did not run to its end, mapped to its status |
| `unresolved` | list of strings | Each step that ran to its end with evidence left unresolved |
| `elapsed` | number or null | The run's duration in seconds, from its start to the end of its analyses. Null when the record lacks either time, as after a killed process |
| `stop` | object or null | Why the run stopped before its end; null for a run that ended on its own. `kind` is `cancelled` (Ctrl-C), `terminated` (SIGTERM), `time_limit`, `spending_cap`, `provider_refused` (the model provider refused a call for the account) or `stopped` (`nudi report` for a run that did not close out). `phase` is the step it stopped, or the steps joined by `and`. `minutes` is the time limit. `reason` is the text `nudi report` gives or the provider's refusal. Each of `phase`, `minutes` and `reason` is null when not recorded |
| `phase_errors` | object | Each step that raised an error, mapped to that error |
| `ungrouped` | list of strings | Inspector findings no stored cause holds, as `grader-INDEX` or `hack-INDEX`; all of them when the attack was not selected |
| `analyses` | object | Each selected step (`simulation`, `grader`, `hack` or `attack`) mapped to its status: `complete`, `unresolved` (ran to its end with evidence left unresolved), `unfinished` (the simulation has an episode without a reward, or an inspection raised), `cancelled`, `spending_exhausted`, `running` or `not run`. In a report so far, a step with no record yet is `not started` |
| `attack` | object or null | The attack's candidates, attempts, exploits and interpretations; null when the attack was not selected |
| `causes` | list | One entry per cause, described below. A cause is one thing the grader trusts, with the findings that use it. Which findings share a cause is a model's judgment: a judge compared each new finding's cause sentence with the known ones when both existed, and the attack inspector judged which cause each no-hint exploit used. Older reports and records without causes give one cause per stored finding group. nudi still reads stored attack records that list causes under `holes`, with ids `H1` and so on |
| `attack.attempts[].sources` | list of strings | The findings whose guidance the attempt ran: first the one it used, the latest interpretation of its check when the attempt started, then the others of its check |
| `attack.attempts[].cause` | string or null | The cause its target finding had when the attempt started, which its help was written for. For a no-hint attempt, the cause its attack inspector judged the exploit to use, a known one or the new one it made. Null when it made no exploit |
| `attack.attempts[].failed` | string or null | The agent whose failure ended the attempt: `Attacker` (its `status` is then the Attacker's failure, such as `episode_failure` when the episode ended without a reward and without a model call) or `attack inspector` (the Attacker's `rewards` stay). Null otherwise and in older reports |
| `labels.counts` | object | Ordinary episodes per grader inspector label: `accepted_invalid`, `rejected_valid`, `legitimate`, `unknown`, `unavailable`, `ungrounded` or `unreviewed`. Only labels that occur appear. `labels` is null without a grader inspection |
| `configuration.known_cost` | number | Known inference cost in US dollars |
| `configuration.unknown_cost_calls`, `configuration.cancelled_calls` | integer | Calls whose cost is unknown, and calls cancelled in flight. The known cost excludes both |
| `configuration.unknown_reasons` | object | Each reason a call has no price, mapped to its count |
| `attack.attempts[].status` `no_reward` | string | The Attacker made model calls and the grader wrote no reward. There is nothing to judge and the attempt did not fail to run, so `failed` is null; `error` says why |
| `ordinary.no_reward` | object | Each Simulator episode without a finite reward, mapped to its `model_calls` and `phase`: `agent work`, `grading` (once nudi had copied its environment for grading), or null when it made no model call. Empty when every episode has a reward |
| `ordinary.retries` | object | Each fresh Simulator episode mapped to the one it replaced, an episode that ended without a reward and without a model call. The replaced one keeps its failures |
| `ordinary.groups[].episode_rewards` | object | Each ordinary episode of the group mapped to its rewards by key; null for a value that is not a finite number |
| `ordinary.groups[].rewards.<key>.flags` | list | Each reward pattern: `flag` (`identical_rewards`, `low_minority` or `high_minority`), its `episodes`, `text`, `quartiles` (Q1 and Q3 of a minority flag, else null), `fence` (the outer fence, Q1 - 3 IQR or Q3 + 3 IQR, else null), `minimum` (the usable rewards a flag needs) and `recorded`, which gives for each of its episodes `agent_timeout`, `verifier_timeout`, `errors` (error types) and `refusals` (refusal signals). A flag is not a finding and changes no rate or result |
| `inspections.<inspector>.open` | list | What kept a category, or a grader inspector's ordinary episode, unsettled when the inspection ended. Each entry has `id` (an experiment, episode or category), `category` (null for an ordinary episode), `reason` and `next` step. Empty when nothing was left open; absent in older reports |
| `inspections.<inspector>.findings.<result>[].claim.cause` | string or null | The inspector's one sentence on what the grader trusts that the finding uses. The judge compares it with the known causes when the finding is new. For an attack inspector's interpretation of a no-hint exploit, it is the `known_causes` id the exploit used or a new sentence. Null in older reports, where the mechanism stands for it; nudi still reads it from records that name it `hole` |
| `inspections.<inspector>.findings.<result>[].claim.marks` | list of strings | The observation names of its check that show the exploit. An interpretation without marks proves nothing: it stays in `open` until it names them, and it is a cause's finding without a level |
| `inspections.<inspector>.suspected` | list | Each suspected exploit, shown in `report.md` as "●○○○○ suspected exploit", with its `category` and `check`. It is a measured experiment, not replaced by a later one, whose latest interpretation ended unknown (unfinished included), in a category where no evidenced interpretation has the same case: the same case name, episode or package, location and capture point. Never a cause. Absent in older reports |
| `warnings` | list of strings | Everything that limits the results |

The exit code follows `status`: `0` for `complete`, `1` for every other status, `time_limit` included.

Each entry of `causes`:

| Field | Type | Values |
| --- | --- | --- |
| `id` | string | `C1`, `C2` and so on, numbered as the run found causes. A cause an older record lacks takes the next number |
| `cause` | string | One sentence on what the grader trusts: the first finding's cause sentence, else its mechanism |
| `level`, `label` | integer or null, string or null | The best level among its findings with `read_as` false, and that level's words. A finding judged to use the cause never raises it. Null for a cause whose one finding is an interpretation without marks, and for a cause whose every finding has `read_as` true, as when a later interpretation withdrew the finding that opened it. `report.md` then says "no level of its own, only findings judged to use it" |
| `attempts`, `reproduced`, `unrewarded` | integer or null | Counted over its findings with `read_as` false, each attempt once even when it had the help of two of them: assessed attempts given their help, how many reproduced the finding, and how many more got reward 0 and were not inspected. Null when no attempt was given the help of any of them |
| `findings` | list | Each finding of the cause, best level first, described below |

Each entry of `causes[].findings`:

| Field | Type | Values |
| --- | --- | --- |
| `id` | string | The finding, `hack-INDEX` or `grader-INDEX`, or an Attacker's episode |
| `source` | string | Who found it: `hack inspector`, `grader inspector` or `Attacker` |
| `outcome` | string | The measured outcome: `accepted_invalid` (incorrect work passed) or `rejected_valid` (correct work failed) |
| `attacked` | boolean | True when an Attacker attempt was given its help, assessed or not, and always for an Attacker's own finding |
| `read_as` | boolean | True for a finding that is under this cause because an agent judged it so. That is an inspector finding the judge matched to this known cause, or a no-hint Attacker exploit the attack inspector judged to use it, at its own level 5, whose line ends "judged to use this cause". It keeps its own level and sets neither the cause's level nor its counts. False for the findings of the cause's first finding group, and for a no-hint exploit of a new cause, which is a cause of its own |
| `mechanism` | string | What its interpretation says the work did, on one line |
| `text` | string | Only for an interpretation without marks: what its check measured |
| `type` | string or null | `hack`, `false_positive` (invalid work the grader inspector saw accepted in the simulations) or `false_negative` (correct work failed). Null for an interpretation without marks |
| `reason` | string | Only for an interpretation without marks: why nudi makes no claim from it |
| `level` | integer or null | 2 to 5, as in [Usage](usage.md#reports): the least help under which an Attacker given its help made an exploit, by any route, else 2. For an Attacker's finding, the help its own Attacker had, 5 with no extra information. Null only for an interpretation without marks |
| `label` | string or null | The level's words, such as `●●●○○ exploit executable by learner with full information`. For correct work failed, `Correct work failed`, then how an Attacker reproduced it |
| `conditions` | list of objects | For an inspector finding, each condition an Attacker tried it under, in order. Each has `condition` (`full`, `minimal` or `none`), `attempts` assessed, `exploited` (how many were exploits, counting only `accepted_invalid`, never `rejected_valid`), the Attacker `model` and the `status`. When there are any, it also has `unrewarded`, the attempts the grader paid nothing, which nudi did not inspect and does not count as assessed, and `not_assessed`, the attempts that did not run or were not judged, each with its `episode`, `status`, `reward` and `error` |
| `attempts`, `reproduced`, `unrewarded` | integer or null | Assessed attempts given its help, how many reproduced its outcome, and how many more got reward 0 and were not inspected. Null for an Attacker's finding and without the attack |
| `help`, `kind` | string or null | For an Attacker's finding, `help` is the help its Attacker had, such as `only a hint written for hack-3` or `no extra information`, and `kind` is `discovery` (no hint) or `reproduction` (of a finding no current interpretation holds). Null for an inspector finding |
| `scope`, `reward`, `check` | | `package` or `native`, its interpretation's reward and its check |
| `marks` | object | Each mark of its interpretation mapped to the value its check measured |
| `unresolved`, `family` | | `unresolved` is what its interpretation leaves open. `report.md` gives it in the finding's Attack entry, not in the Answer, and not for an inspector finding an Attacker reproduced. `family` is the hack family an `other` interpretation proposed. The novel-family line in `report.md` leaves out names in `HACK_CATEGORIES`, also with spaces or different case, and is absent when none remain |
| `also`, `location`, `capture_point` | | The other findings stored with it, such as an earlier interpretation of its check, and where its own case looked |
| `origin` | string or null | The earlier run a rerun took it from |

Older records keep their fields; a field they lack reads as unknown. These fields are gone: `exploited_with`, `exploited_by`, `evidenced_by_inspector`, `candidate`, the `elsewhere_` conditions, `claim.use`, the rerun fields `attack.attempts[].reproduced`, `rerun`, `rerun_check`, `noted`, `noted_reproduced`, `noted_rerun`, `counts_for` and `created`, the per-finding fields' `note`, the conditions' `written_for`, and each finding's `requirement`. A run whose `run.json` holds a `requirements` list still loads, and nudi ignores the list. Reports before version 4 listed findings under `problems` and `attack.problems`, with ids `P1`, `G1` and `A1`, and `attack.leads` had an `id`. An older attack record still loads. Its exploits are read again from its attack inspector interpretations, so an exploit made with a finding's help counts for that finding whatever its rerun measured.

`attack.exploits` keys each exploit by its kind: `reproduction`, made with a finding's full information or hint, or `discovery`, made with no extra information. Each names its `cause`. It holds only `accepted_invalid`: rejected-valid findings stay in the findings and attempts, with their reproduction counts, and never count as exploits.

`attack.leads` lists the stored finding groups that no shown finding confirms, each with its `findings`, `cause` and `origin`, and no level. A lead is an inspector finding a later interpretation withdrew, or one from an older record or an earlier run. An Attacker exploit of this run that no finding shows, such as a further interpretation of one attempt, is not a lead.

### Names of the inspectors

Each file spells the same inspector differently, by field:

| Where | Hack inspector | Grader inspector | Attack |
| --- | --- | --- | --- |
| `causes[].findings[].source` | `hack inspector` | `grader inspector` | `Attacker` |
| `attack.candidates[].source`, keys of `inspections` | `hack_inspector` | `grader_inspector` | |
| Keys of `analyses`, `unfinished`, `unresolved`; `phase` and `inspector` in `events.jsonl` | `hack` | `grader` | `attack` |

`--analysis hacking` selects the steps `hack` and `attack`, and `--analysis simulation` the steps `simulation` and `grader`.

## summary.json

A batch of several environments writes `summary.json` in the batch folder.

| Field | Type | Values |
| --- | --- | --- |
| `status` | string | `complete`, `time_limit`, `unfinished`, `cancelled` after Ctrl-C or `terminated` after SIGTERM. A batch in which no environment started is `unfinished` with `exit_code` `2` |
| `exit_code` | integer | The command's exit code |
| `environments` | list | One row per task, described below |

Each row of `environments`:

| Field | Type | Values |
| --- | --- | --- |
| `name`, `task_dir`, `run_dir` | string | The run folder's name, the task and the run folder |
| `status` | string | `complete`, `time_limit`, `unfinished`, `stopped`, `refused`, `not_started`, `cancelled` or `terminated`, as the table in [Usage](usage.md#several-environments) explains |
| `exit_code` | integer or null | The exit code the environment would have alone; null for `not_started` |
| `execution` | string or null | The run's `outcome`. Null when no report was written, as for a refused environment, whose reason is in `error` |
| `answer` | string or null | The run's verdict line |
| `known_cost` | number or null | From its `report.json` |
| `error` | string or null | Why it was refused or stopped |

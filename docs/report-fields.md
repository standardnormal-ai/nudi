# report.json and summary.json fields

The fields a script or coding agent reads. Both files hold more; [Usage](usage.md#reports) explains them. Keys not listed here can change without notice.

## report.json

| Field | Type | Values |
| --- | --- | --- |
| `schema_version` | integer | `4`; `3` before `causes` held each finding and the per-finding list went, `2` before the rerun fields went and levels came from the help given, `1` before levels by group were replaced. Raised when a listed field changes meaning or goes away; absent in reports written before it |
| `status` | string | `complete`: every selected step ran to its end. `time_limit`: the time limit ended the run with no phase failed before it. `partial`: a step failed, stopped, as at the spending cap, or never ran. `stopped`: the model provider refused a call for the account, or written by `nudi report` for a run whose process ended without closing it out. `running`: the report so far, which the run rewrites after each confirmation while it goes; the final report replaces it |
| `outcome` | string | The Answer's first line: how the run ended, in plain words |
| `answer` | list of strings | `outcome`, then the verdict line, then, when a cause holds more than one finding or one judged to use it, "An agent grouped the findings into causes; it can make mistakes.", then one entry per cause with a level, highest first: a cause of one finding is one line, its id, sentence and the finding's line; any other is its id, sentence and label, with each finding's line beneath it starting `  - `, those with `read_as` true last, an inspector's ending "not attacked on its own" and an Attacker's "judged to use this cause". A finding's line gives its id, reward, the marks its check measured, the help its Attacker had, its level's words and how many assessed attempts with its help were exploits, or reproduced work the grader failed for `rejected_valid`. Then one line per reading without marks: what its check measured and why nudi makes no claim from it. Without an approved list that confirms a finding, the verdict line counts the findings and those exploited by an Attacker given their help, or found by one, or that no Attacker ran, and says that nudi does not say which task rule each breaks |
| `unfinished` | object | Each step that did not run to its end, mapped to its status |
| `unresolved` | list of strings | Each step that ran to its end with evidence left unresolved |
| `elapsed` | number or null | The run's duration in seconds, from its start to the end of its analyses; null when the record lacks either time, as after a killed process |
| `stop` | object or null | Why the run stopped before its end; null for a run that ended on its own. `kind`: `cancelled` (Ctrl-C), `terminated` (SIGTERM), `time_limit`, `spending_cap`, `provider_refused` (the model provider refused a call for the account) or `stopped` (`nudi report` for a run that did not close out); `phase`, the step it stopped, or the steps joined by `and`, null when not recorded; `minutes`, the time limit, null when not recorded; `reason`, the words `nudi report` gives or the provider's refusal, otherwise null |
| `phase_errors` | object | Each step that raised an error, mapped to that error |
| `ungrouped` | list of strings | Inspector findings no stored cause holds, as `grader-INDEX` or `hack-INDEX`; all of them when the attack was not selected |
| `analyses` | object | Each selected step, `simulation`, `grader`, `hack` or `attack`, mapped to its status, such as `complete`, `partial`, `cancelled`, `spending_exhausted`, `running` or `not run`; in a report so far, `not started` for one with no record yet |
| `attack` | object or null | The attack's candidates, attempts, exploits and readings; null when the attack was not selected |
| `causes` | list | One entry per cause, below: each one thing the grader trusts, with the findings that use it. Which findings share a cause is a reading: a judge compared each new finding's cause sentence with the known ones when both existed, and the attack inspector read each no-hint exploit's cause. Older reports and records without causes give one cause per stored finding group; nudi still reads stored attack records that list causes under `holes`, with ids `H1` ... |
| `attack.attempts[].sources` | list of strings | The findings whose guidance the attempt ran: first the reading it used, the latest one of its check when the attempt started, then the others of its check |
| `attack.attempts[].cause` | string or null | The cause its target's finding had when it started, the one its help was written for; for a no-hint attempt, the cause its attack inspector judged its exploit to use, a known one, or the new one it made, and null when it made no exploit |
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
| `inspections.<inspector>.findings.<result>[].claim.cause` | string or null | The inspector's one sentence on what the grader trusts that the finding uses, which the judge compares with the known causes when the finding is new; for an attack inspector reading of a no-hint exploit, the `known_causes` id it used or a new sentence. Null in older reports, where the mechanism stands for it; nudi still reads it from records that name it `hole` |
| `inspections.<inspector>.findings.<result>[].claim.marks` | list of strings | The observation names of its check that show the exploit; a reading without marks proves none, stays in `open` until it names them, and is a cause's finding without a level |
| `inspections.<inspector>.suspected` | list | Each suspected exploit, `report.md`'s "●○○○○ suspected exploit": its `category` and `check`, a measured experiment, not replaced by a later one, whose latest reading ended unknown, unfinished included, in a category where no evidenced reading has the same case: the same case name, episode or package, location and capture point. Never a cause. Absent in older reports |
| `warnings` | list of strings | Everything that limits the results |

The exit code follows `status`: `0` for `complete`, `1` for the others, `time_limit` included.

Each entry of `causes`:

| Field | Type | Values |
| --- | --- | --- |
| `id` | string | `C1`, `C2` ..., as the run numbered causes while it went; a cause an older record lacks takes the next number |
| `cause` | string | One sentence on what the grader trusts: the first finding's cause sentence, else its mechanism |
| `level`, `label` | integer or null, string or null | The best level of its findings with `read_as` false and that level's words; a finding judged to use the cause never raises it. Null for a cause whose one finding is a reading without marks, and for one whose every finding has `read_as` true, as when a later reading withdrew the finding that opened it; `report.md` then says "no level of its own, only findings judged to use it" |
| `attempts`, `reproduced`, `unrewarded` | integer or null | Over its findings with `read_as` false, each attempt once, also one given the help of two of them: assessed attempts given their help, how many reproduced the finding, and how many more got reward 0 and were not inspected; null when no attempt was given the help of any of them |
| `findings` | list | Each finding of the cause, best level first, below |

Each entry of `causes[].findings`:

| Field | Type | Values |
| --- | --- | --- |
| `id` | string | The finding, `hack-INDEX` or `grader-INDEX`, or an Attacker's episode |
| `source` | string | Who found it: `hack inspector`, `grader inspector` or `Attacker` |
| `outcome` | string | The measured outcome: `accepted_invalid` (incorrect work passed) or `rejected_valid` (correct work failed) |
| `attacked` | boolean | True when an Attacker attempt was given its help, assessed or not, and always for an Attacker's own finding |
| `read_as` | boolean | True for a finding that is under this cause because an agent read it so: an inspector finding the judge read as this known cause, whose line ends "not attacked on its own", and a no-hint Attacker exploit the attack inspector judged to use it, at its own level 5, whose line ends "judged to use this cause". It keeps its own level and sets neither the cause's level nor its counts. False for the findings of the cause's first finding group, and for a no-hint exploit of a new cause, which is a cause of its own |
| `mechanism` | string | What its reading says the work did, on one line |
| `type` | string or null | `hack`, `false_positive` (invalid work the grader inspector saw accepted in the simulations) or `false_negative` (correct work failed), only when the approved requirement list confirms it: the reading reads an approved requirement violated, or for correct work failed every approved requirement supported, read with the other readings of its simulation episode for a grader inspector reading, as the metrics read it. Null otherwise, also for a finding with marks and a level |
| `text` | string | Only for a reading without marks: what its check measured |
| `reason` | string or null | For a reading without marks, why nudi makes no claim from it; for work the grader failed that the list does not confirm, why completeness is unknown; null otherwise |
| `level` | integer or null | 2 to 5, as in [Usage](usage.md#reports): the least help under which an Attacker given its help made an exploit, by any route, else 2; for an Attacker's finding, the help its own Attacker had, 5 with no extra information. Null only for a reading without marks |
| `label` | string or null | The level's words, such as `●●●○○ exploit executable by learner with full information`, or for work the grader failed `Correct work failed` when the list confirms the work correct, else `Work the grader failed`, then how an Attacker reproduced it |
| `conditions` | list of objects | For an inspector finding, each condition an Attacker tried it under, in order: `condition` (`full`, `minimal`, `none`), `attempts` assessed, how many were exploits (`exploited`, only `accepted_invalid`, never `rejected_valid`), the Attacker `model`, the `status`, and, when any, `unrewarded`, how many attempts the grader paid nothing, which nudi did not inspect and does not count as assessed, and `not_assessed`, the attempts that did not run or were not judged, each with its `episode`, `status`, `reward` and `error` |
| `attempts`, `reproduced`, `unrewarded` | integer or null | Assessed attempts given its help, how many reproduced its outcome, and how many more got reward 0 and were not inspected; null for an Attacker's finding and without the attack |
| `help`, `kind` | string or null | For an Attacker's finding, `help` is the help its Attacker had, such as `only a hint written for hack-3` or `no extra information`, and `kind` is `discovery` (no hint) or `reproduction` (of a finding no current reading holds). Null for an inspector finding |
| `scope`, `reward`, `check` | | `package` or `native`, its reading's reward and check |
| `marks` | object | Each mark of its reading mapped to the value its check measured |
| `requirement` | string or null | The approved requirement its reading reads violated; null without one or without an approved list |
| `unresolved`, `family` | | What its reading leaves open, which `report.md` gives in its Attack entry, not in the Answer, and not for an inspector finding an Attacker reproduced; and the hack family an `other` reading proposed. The novel-family line excludes names in `HACK_CATEGORIES`, also with spaces or different case, and is absent when none remain |
| `also`, `location`, `capture_point` | | The other findings stored with it, such as an earlier reading of its check, and where its own case looked |
| `origin` | string or null | The earlier run a rerun took it from |

Older records keep their fields; a field they lack reads unknown. `exploited_with`, `exploited_by`, `evidenced_by_inspector`, `candidate`, the `elsewhere_` conditions and `claim.use` are gone, and so are the rerun fields `attack.attempts[].reproduced`, `rerun`, `rerun_check`, `noted`, `noted_reproduced`, `noted_rerun`, `counts_for` and `created`, the per-finding fields' `note` and the conditions' `written_for`. `attack.exploits` includes only `accepted_invalid`; rejected-valid findings stay in the findings and attempts, with their reproduction counts, and never count as exploits. Reports before version 4 listed findings under `problems` and `attack.problems`, with ids `P1`, `G1` and `A1`; `attack.leads` had an `id`. An older attack record still loads: its exploits are read again from its attack inspector readings, so an exploit made with a finding's help counts for that finding whatever its rerun measured.

`attack.leads` lists the stored finding groups that no shown finding confirms, each with its `findings`, `cause` and `origin`, and no level: an inspector finding a later reading withdrew, or one of an older record or an earlier run. An Attacker exploit of this run that no finding shows, such as a further reading of one attempt, is no lead.

`attack.exploits` keys each exploit by its kind: `reproduction`, made with a finding's full information or hint, or `discovery`, made with no extra information; each names its `cause`.

### Names of the inspectors

Each file spells the same inspector by field:

| Where | Hack inspector | Grader inspector | Attack |
| --- | --- | --- | --- |
| `causes[].findings[].source` | `hack inspector` | `grader inspector` | `Attacker` |
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

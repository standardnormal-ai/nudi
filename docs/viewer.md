# Viewer contract

`nudi-view` is a terminal viewer for nudi runs, built from [`tui/`](../tui). It reads `RUN/report.json`, and with `--follow` also `RUN/events.jsonl`. It reads nothing else in the run folder and refuses a file that links outside the folder. nudi decides every word, status and number in those files. The viewer lays them out and never computes a result of its own. [Usage](usage.md#viewer) says how to build and run it.

## Accepted reports

| Report | Viewer |
| --- | --- |
| Schema 4 | Read in full: causes with their findings |
| nudi 0.0.1 to 0.4.0, schemas 1 to 3 | Read in full. Their problems are converted to causes on load, as [older reports](#older-reports) describes |
| nudi 0.0.0 | Read in full. The attack has no problems, so no cause is shown |
| Older, without `answer` | Refused: `RUN/report.json comes from a nudi older than 0.0.0, which wrote no answer; this viewer reads reports from nudi 0.0.0 on` |
| Incomplete: an empty `answer`, or a rate with a `value` but no `numerator` or `denominator` | Refused with a message naming the gap |

The viewer ignores fields it does not use. It shows as unavailable, never as zero: Python's nulls for statistics it cannot give, a missing `known_cost`, a reward statistic an older report lacks (such as `median`) and a missing `pass_rate`. An analysis status or category name the viewer has no words for is shown as written. Category states are not shown. Before anything is drawn, the viewer drops control characters and Unicode format characters, such as bidi overrides, from every string in the report (map keys included), from the folder name and from error messages.

## Fields read

| Field | Shown as |
| --- | --- |
| `answer` | The Results tab: the first line as how the run ended, the rest below it. A complete run whose first line starts `Finished, but` reads `Finished` with its elapsed time. A short yellow warning at the right names the phase whose work was lost and counts what that line names, such as `! Find Hacks: 1 search failed`. Each failed inspector session or failed experiment counts as a search, an inspector session that failed with its experiment's error counts once, and each failed Attacker try and each failed evidence copy (`copies` with an `error`) counts too; a failed copy belongs to no phase. The warning reads `! Some work was lost` when no record shows a failure. An `unfinished` run, in which a step failed or stopped, reads `Finished` the same way, with its elapsed time and the same warning. Only a stopped, failed, unstarted or still running run has a heading of its own. When the width is too narrow for both, the warning takes its own line. The plain report gives it as `Warning`, pointing to WORK LEFT |
| `status` | The exit code |
| `analyses` | The phase steps. A phase missing from it was not selected. `not run` and every other status are shown as given. A phase tab reads `unfinished` when a step of it failed or stopped. It reads `unresolved` when it ran to its end with evidence still open but `unresolved` and `unfinished` do not say so; when they do, such a phase shows a check and Work left lists its open questions |
| `warnings` | One Work left row each, naming where, what and why in Python's words. A warning that an attack candidate is unknown or unattempted is left out, since the row of its cause already says it. A coverage warning that a phase ended `unresolved` is replaced by that phase's open questions, when it has some, each named with its reference and its reason, or `Reason not recorded` |
| `configuration` | `task_dir`, `models.ROLE.model` and `reasoning_effort`, `spending_cap`, `known_cost`, `unknown_cost_calls`, `cancelled_calls`, `backend`, `modal_cost.at_requests` and `at_limits` |
| `ordinary` | `requested`, `attempted`, and per group `configuration.model` and `rewards.KEY` with `attempted`, `usable`, `mean`, `median`, `sd`, `skewness` and `distribution`, drawn as the rewards chart. Then, on the Simulation screen and in the plain report, each of its `flags` as a plain observation, with its `flag` and its `text` as written in the method panel that `?` opens, or `flags_not_evaluated` as written. Absent or null `flags`, a null flag, or a flag without its `flag` or `text` reads `Pattern details unavailable.` |
| `labels.counts` | The grader inspector's episode labels |
| `metrics.confusion` | Per group: `configuration.model`, `reward`, `status`, `reasons`, `rule`, `tp`, `fp`, `fn`, `tn`, and both rates with `value`, `numerator`, `denominator`, `lower_bound` and `unavailable`. Also `pass_rate`, the native pass rate, with the same fields and `interval`, its 95% Wilson interval, worded as in `report.md` on the Grade Simulations screen and in the plain report whatever the group's `status`. An older `pass_rate` without `interval` is shown without one |
| `inspections.grader_inspector`, `inspections.hack_inspector` | `status`, `open`, `categories`, `attempts`, `experiments`, `applicability`, `limits`, and `findings.evidenced`, `inconclusive` and `legitimate` |
| `causes` | Schema 4: `id`, `cause`, `level`, `label`, and `findings` (`id`, `source`, `mechanism`, `outcome`, `type`, `level`, `label`, `attacked`, `read_as`, `conditions`, `help`, `unrewarded`, `marks`, `assessment`, and `requirement` when an older report has it). Schema 3: `id`, `cause`, `level`, `label`, `problems`, `readings` and `not_attacked` |
| `attack` | `status`, `maximum_attempts`, `candidates` (`id`, `valid_work`, `conditions.LEVEL.status`), `attempts` (`level`, `candidate`, `sources`, `problem`, `episode`, `status`), `findings`, and `exploits.KIND` (`assessment`, `candidate`, `sources`, and for `other` the `problem` the judge named). In schemas 1 to 3 also `problems`: `cause`, `findings`, `candidate`, `reproduced`, `reproduced_findings`, and for problems formed during the run `id`, `source`, `members`, `exploited_with` (`help_needed` in older reports), `level`, `label`, `exploited_by` and `conditions` (`condition`, `exploited`) |
| `other_episodes.attacker` | Which attempts started |

The viewer also reads these facts for the screens that tabulate them: `copies` (`error`), `unfinished`, `unresolved`, `elapsed`, `stop`, `phase_errors` and `ungrouped`; `configuration.capacity.concurrency`, `unknown_reasons` and `modal_cost` (`sandboxes`, `without_limits`, `still_running`); per ordinary group `episodes` and `episode_rewards`, and per flag `episodes`, `quartiles`, `fence`, `minimum` and `recorded`; `labels.episodes` and `labels.review`; `metrics.episodes` and `metrics.coverage`; per inspection `open` and each experiment's `id`, `status`, `check` and `episode`; in `attack`, `discovery`, each attempt's `number`, `rewards` and `error`, each exploit's `attempt` and `problem`, each problem's `outcome`, `evidenced_by_inspector` and `exploited_by`, and each condition's `attempts` and `status`. [Report fields](report-fields.md) defines them. A report written before one of them existed lacks it, and the viewer reads it as not recorded, never as none or zero. A report without `phase_errors` also predates `stop`, so its null `stop` does not say that the run ended on its own.

Each finding is read for `index`, `superseded_by`, `execution_scope`, `category`, `claim` (`mechanism`, `episode`, `unresolved`, `limits`), `captured` (`native_reward`, `copied_grader_reward`, `check.id`, `check.requirement.excerpt` and `path`), `interpretation` (`interpretation`, `citations`) and `assessment` (`outcome`, `reasons`, `limits`).

## Layout rules

These rules arrange the report. None of them changes a result.

### Findings

The list holds every evidenced finding whose `superseded_by` is null: the grader inspector's, then the hack inspector's, then the attack's, each in report order, numbered from 1. A hack inspector finding is named `hack-INDEX` and a grader inspector finding `grader-INDEX`, as the attack names its candidates, so a candidate, an attempt or a cause names the finding it came from. An attack finding is named by its check id. An inspector finding without its `index` is named `grader index unavailable` or `hack index unavailable` and links to nothing.

### Types

A finding's type comes from who found it and its outcome. `accepted_invalid` is "False positive: incorrect work passed" from the grader inspector, and "Hack: the reward was earned without doing the task" from the hack inspector or the attack. `rejected_valid` is "False negative: correct work was rejected" from any of them.

A finding's screen is titled by the sentence of the cause that holds it, with the finding's own mechanism on a Mechanism line. When no cause holds it, the title is its mechanism. Under the title it names its type in full, then who found it and where its evidence comes from.

A timeline follows, on the finding screen and in a piped `nudi-view RUN N` or finding id. It has one step for each fact the report holds, in this order:

- `issue`: the inspector and where it found the issue
- `requires`: the requirement it violates
- `reward`: what the grader paid
- `nudi`: what its check measured against the deserved score
- `cause`: `associated to cause N`
- one step per Attacker try at `hint`, `full` or `no info`, with its result and try, or one `attacker` step, `not attacked on its own`
- `level`: such as `4 of 5`

A step whose data is missing is left out, and the rows above the timeline do not repeat what it says.

An attack finding adds what it confirmed of the findings the attempt tested, from its entry in `exploits` (the one whose `assessment` is its `index`): reproduced (`reproduction`), another mechanism while testing (`other`), not confirmed as (`unattributed`), or found with no information (`discovery`). Each tested finding is named by its id and its number, as in `hack-1 (finding 3)`. From schema 3, a `discovery` entry names no finding: a try given no information keeps the candidate of the slot it ran in without being told it. Its finding's Cause row then says which cause a judge matched it to, and the plain report's attempt list says the try was aimed at `none`.

An attack finding with no entry confirms no tested finding, with one exception. From 0.5.0, an Attacker finding of work the grader failed in a native run is no exploit and has no entry; as in the Markdown report, it reproduced the candidate of the evidenced try whose episode it was found in. When the finding lacks its `index`, or any entry is null or lacks its `assessment`, an unmatched finding reads `confirmation unavailable`, so nothing is attributed from missing data. A report without `exploits` shows nothing there.

The Limitations tab numbers `claim.unresolved` as open conditions, then the scope limits, each under a short heading. The References tab lists every id the finding names, with what it is.

### Attempts

An attempt started when its `episode` is listed in `other_episodes.attacker`. An attempt that never started is shown as not tested, whatever its status.

### Candidates

The attack selects only a cause's `candidate`, so only it is marked selected, then attempted or not tested. The cause's other findings get no selected, attempted or not tested mark. They can get a reproduced mark, since an attempt can test other findings of the cause along with the candidate. Every reproduced mark needs a started attempt that tested that finding: a finding is marked reproduced when `reproduced_findings` names it and a started attempt tested it. A report without `reproduced_findings` marks the candidate reproduced when `reproduced` is true and a started attempt tested the candidate. The hack panel counts the findings, under Findings.

### Causes

Results, the Attack screen and the plain report list `causes` in report order, which is by `level`, highest first, with a null `level` last. Results and the Attack screen group them under the heading of their type, as the [Attack screen](#attack-screen) rule says, keeping that order in each group. Results heads Hint and Full on each heading. Causes are numbered 1, 2 and so on in the order shown, and named `Cause 1`, `Cause 2` in titles, crumbs, the legend, the plain report and the Attack screen, for older reports too. The `id` appears only under References.

A cause shows its number, its `cause` sentence, its Hint and Full cells and its level as dots, ●●●●○ for 4. A cause with a null `level`, whose every finding is `read_as`, has no dots and reads `No level of its own, only findings associated to it`, dim under its sentence. A dim line under the sentence also counts its findings when it has several, and, in a run with Attacker tries, its findings `not attacked on its own`: inspector findings with `read_as` true whose `attacked` is not true. Nothing is derived from `attacked` false alone, since with no Attacker every first finding has it. The cause's `attempts`, `reproduced` and `unrewarded` are not shown.

Type is a heading, not a column, so the sentence takes the width left by the number, Hint, Full and level columns. On a folded row, on Results and the Attack screen, the sentence is one line, cut with `…` at that width. The cut falls at the last space when there is one in the line's second half or before a ref such as C4 or hack-17, else inside a word. Opening the cause shows it in full, as does the finding screen a cause of one finding opens. The plain report never cuts it.

### Cause rows

`enter` on a cause of one finding opens that finding. On a cause of several, it lists them, indented, each with its own cells and only a name: the label of the category its evidence record was found in (as the Find Hacks screen names categories), else its `mechanism` cut with `…`. A grader inspector category's label would repeat the heading, so such a finding shows its `mechanism`. A finding's id appears only under References, and who found it only on the finding's screen. A dim line under the name says `associated to this cause` for an Attacker finding judged to use it, or, in a run with Attacker tries, `not attacked on its own`. It also gives the finding's type when that differs from its cause's. A finding with `read_as` true that an Attacker found has its own level, ●●●●● for a no-hint exploit, and no cells. An inspector finding not attacked on its own is drawn dim, and its cause's line counts it.

`nudi-view RUN 1` opens cause 1 the same way, as do `cause 1`, `cause1`, `Cause 1` and its id, `nudi-view RUN C1`. `nudi-view RUN hack-6` or `RUN A2` opens a finding. A report without causes keeps `nudi-view RUN N` for finding N. In a pipe, a cause prints its block of the plain report. Attacker findings named after their episode show as A1, A2 and so on in report order, beside any A ids the report wrote. A try is named by its session's number, `Try 7` for `0007-attacker`, everywhere but the References tables, which keep the episode. The plain report's NEXT section opens the highest cause that has several findings or evidence that opens.

### Cause columns

Hint and Full are the best of a cause's findings attacked on their own, from their `conditions`:

- ✓ when an assessed attempt at that help was an exploit
- ✗ when attempts at that help were assessed and none was an exploit
- `?` when the only attempts got reward 0 (`unrewarded`), which nudi did not inspect
- `-` when none ran

An Attacker finding is ✓ at the help of its own attempt when that is a hint or full instructions. There is no No info column: a try given no information is aimed at no finding, and an Attacker finding's level says when an Attacker told nothing made it. The columns appear when the run has attempts or a finding has `conditions`.

A finding's type is the report's `type` in words (Hack, False positive, False negative) when it is set. Otherwise it comes from its `outcome`: `accepted_invalid` is Incorrect work passed and `rejected_valid` is Correct work failed, and an Attacker finding without an outcome is Incorrect work passed. A cause's type is the type of its findings other than those with `read_as` true, or its one finding's type. A cause with none, or with findings of several types, is under Type Unknown.

The `e` key, on the first heading, opens the legend. It gives the symbols, says the cells are for the findings attacked on their own, and adds the Answer's paragraph on how causes are grouped, the line before its first cause line. The Answer's cause lines are not repeated, since the rows hold them. The plain report gives the same under CAUSES: the paragraph, then each cause with its level and, for several findings, each finding's fields beneath.

### Attack screen

The causes are grouped by type: Hacks (Hack or False positive), Incorrect Work Passed, Correct Work Rejected (False negative), Correct Work Failed and, for a cause with none of these, Type Unknown. When no cause has a type, there is one group, Causes. Each row has the cause's number, its sentence, Hint and Full. It expands into the tries aimed at its findings attacked on their own, with a Finding column when it has several.

A try's Succeeded is ✓ for `evidenced_issue`, ✗ for an assessed `no_evidenced_issue` and `?` otherwise. Under it, a try the grader paid nothing reads `The grader paid nothing, so nudi did not inspect it.`, and one with status `unknown` reads `Result unclear:` and the first line of its `error`. The plain report says `not inspected` for such a try. Tries given no information are a block of their own, whose last column, `Same cause as`, names the cause the attack inspector judged the exploit to use, as `Cause 2`. Older reports without problems list their tries with `Succeeded`.

### Older reports

Schemas 1 to 3 are converted in one place on load, and the screens then read them as schema 4. Reports and events written before `unfinished` and `unresolved` existed gave both one status. Load reads it as `unfinished` for the run and the simulation, and as `unresolved` for the inspections and the attack, in `status`, `analyses`, `unfinished`, coverage warnings, `phase_end` and `run_end`.

A schema 3 `causes` row becomes a cause of its `problems`. Its `not_attacked` problems read as `read_as`, and each of its `readings` becomes an Attacker finding judged to use it, at level 5. Every other problem is a cause of its own, with the problem's id as its Ref and the problem's cause as its sentence, so an older report shows its problem ids, P1 or G1, where schema 4 shows C ids and finding ids.

What is lost in the conversion:

- A finding of an older report is named by its problem's id and cause sentence, not its own finding id and mechanism.
- A problem with several evidence records opens only the first from Results.
- A schema 3 cause level counts a no-hint Attacker finding judged to use it at 5, where schema 4 never lets such a finding raise its cause.
- Leads keep their dim count line.

Schema 2 reports get the same cells, except that a try given no information still counts for its candidate's problem. Their rerun, noted and same-as fields are not shown.

### Abandoned findings

Under Abandoned Findings, evidenced findings that no cause holds read `Standalone evidence`. Their rows are selectable, and `enter` opens the finding. Each row is named by its own `mechanism` cut with `…`, or by its category's label when the mechanism only names a category, never by a bare category name. The Ref column appears only when a row cannot be opened, and then only that row shows its reference. A suspected exploit, a measured check whose result ended unknown, reads `Suspected exploit`, with its category as the finding and its check as the reference. It appears only when the report has one. When the same check is also an unresolved finding, that finding's row reads `Suspected exploit` instead, so one check is one row.

### Errors

Wherever an error is shown (Work left, the search list, a try's line or a phase), it is its first line, up to any ` - {` that starts a payload a provider appended. `report.json` keeps the whole error.

### Open questions

Work left and the panels' open questions name each question with its reference and why it is open, or `Reason not recorded`. A phase in `unresolved` adds its unresolved findings, with the reason each finding records. The Results banner of a run with no cause reads `No cause demonstrated in this run.`

### Help and models

`?` explains every symbol and defines F1, AUROC and the score ordering AUROC needs. `m` lists each model role with its model, reasoning effort and the jobs it runs. Find Hacks names Attackers beside the Hack Inspector only when the run selected the attack.

### Search

The grader and hack panels list the category names searched; findings appear separately. Search scope comes from retained attempts, experiments and findings. Exclusions, attempt summaries and the reasons work is incomplete stay visible. Older reports still load: their generated category warnings keep their concrete reasons without verdicts, and their safety disclaimer is left out.

## Output and exit codes

In a terminal, the viewer opens on the Results tab and prints the header and Results tab into the scrollback when it quits. In a pipe, it prints plain text 100 columns wide: the plain report, finding N with its Evidence, Limitations and References tabs, or a cause's block. The plain report has one section per part of the Results tab, in its order: RUN, RESULT, CAUSES, EVIDENCE, ABANDONED FINDINGS, SIMULATION, GRADER ACCURACY, ATTACK ATTEMPTS, WORK LEFT, COST and NEXT. Each section holds one labelled field per line, with every id in full, no colour and nothing cut. A long value wraps at spaces, and a word too long for its column, such as a path, moves whole to a line of its own.

| Exit code | Meaning |
| --- | --- |
| `0` | The run is complete, as nudi's own exit code |
| `1` | A step failed or stopped, also at the time limit. Evidence left unresolved by a step that ran to its end does not make a run `unfinished` |
| `2` | No `report.json`, one linked from outside the folder, a report older than nudi 0.0.0, an incomplete or unreadable report, or wrong arguments. With `--follow`, also the cases [follow mode](#follow-mode) lists |

## Event log

Every run also writes `RUN/events.jsonl`, so a reader can follow the run while it goes on. `nudi send-nudis`, `send_nudis` and `send_nudis_async` all write it, and the viewer reads it in [follow mode](#follow-mode). Each line is one event: a JSON object in UTF-8 that ends with a newline. The log is an added file and changes no other file or report field.

Every event has these fields:

| Field | Meaning |
| --- | --- |
| `v` | The format version, `1` |
| `time` | When nudi wrote the event, in UTC as ISO 8601 with microseconds, such as `2026-11-07T09:15:02.123456+00:00` |
| `kind` | What happened, one of the kinds below |
| `text` | The line `nudi send-nudis` prints on stderr for the event, without its newline: `nudi: `, `time` as `HH:MM:SS` in the host's time zone, and the message |
| `known_cost`, `unknown_cost_calls`, `cancelled_calls` | The run's cost so far, as `run.json` has it when nudi writes the event: the known inference cost in US dollars, the calls of unknown cost other than cancelled ones, and the calls cancelled in flight |

Each kind adds its own fields. Null means the field does not apply to that event.

| Kind | Written when | Fields |
| --- | --- | --- |
| `run_start` | The run's settings, credentials and backend are accepted and its folder exists. It is the first event | `run_id`; `backend`, `docker` or `modal`; `docker_cpus` and `docker_memory_mb`, null on Modal; `host_cpus` and `host_memory_mb`, the CPUs and memory of the host that runs nudi, on Modal only and null on Docker; `free_bytes`, the free space where records go; `docker_free_bytes`, the free space where Docker stores data, null on Modal and when nudi cannot measure it, as for Docker Desktop, another virtual machine or a remote daemon; `spending_cap`, in US dollars, null without one; `concurrency` and `concurrency_setting`; `reason`, why concurrency is below the setting, or the capacity warning; `pid`, nudi's process id, and `host`, the name of the host it runs on, so a reader on that host can tell whether the run still goes on; `analyses`, the selected analyses in run order, with the names `phase_start` uses; `models`, each role's model settings |
| `reused` | A rerun of the attack (`attack_from`) starts copying the earlier run, after `run_start` and before any analysis. A copy that fails ends the run, and `run_end` follows | `earlier`, the earlier run directory as nudi read it; `analyses`, the analyses taken from it in run order, with the names `analyses` uses in `report.json`; `episodes` and `sandboxes`, how many episode and sandbox folders it copies |
| `phase_start` | An analysis starts | `phase`: `simulation`, `grader`, `hack` or `attack`, the names `analyses` uses in `report.json`; `slots`, for `hack` only, how many of its inspector sessions and Attacker episodes run at once |
| `phase_end` | An analysis ends | `phase`; `elapsed`, its duration in whole seconds; `status`: the status the analysis returned, `stopped` when a task environment cannot start (which stops the other analyses), `cancelled` for an analysis that such a stop or a full disk ended, or `failed`; `error` with `stopped` and `failed`. A returned analysis adds its counts: `episodes` and `requested` for `simulation`; `experiments` and `assessments` for `grader` and `hack`; `attempts`, `findings`, and of those `exploits` (incorrect work passed) and `correct_work_failed` for `attack` |
| `session_start` | An inspector session starts | `inspector`: `grader`, `hack`, or `attack` for the attack inspector; `session`, the session's name in its inspection record; `category`, the one category a focused session inspects; `episode`, the one episode an episode session judges. For an attack inspector session, also `candidate`, the finding its attempt was given help for, and `problem`, that finding's record id in `attack.json` |
| `session_end` | That session ends, also after a failure or a cancellation | `inspector`, `session`, `elapsed`; `status`, the lifecycle status of the session's last attempt; `result`, what the session's own work came to: `evidenced_issue` when an assessment it completed evidenced an issue, `open` when `open` still names its work or its last attempt failed, otherwise `no_evidenced_issue`; `category`, the one category the session inspects (a focused session's, or the inspection's only one), null for a session over several; `category_status`, kept for compatibility as internal search state. Neither it nor category verdicts appear in the terminal line, which names the searched category and keeps operational outcomes. The viewer normalizes older generated lines the same way, in plain follow output and in the live recent lines |
| `evidenced` | An inspector's assessment is evidenced | `inspector`; `outcome`, `accepted_invalid` or `rejected_valid`; `category`, when it is an approved category; `id`, the assessment's check id, or its experiment id when it has no check; `index`, the assessment's position in that inspection's assessments, so a hack inspector finding is `hack-INDEX`; `episode`, the episode or package sandbox the assessment graded, for the attack inspector the Attacker episode of `attempt_start` |
| `attempt_start` | An Attacker episode starts | `episode`; `candidate`, null for discovery; `level`, `full`, `minimal` or `none`; `number`; `problem`, the record id in `attack.json` of the finding a hinted attempt was given help for |
| `attempt_end` | That episode returned, before its attack inspector | The same fields, `elapsed`, and `rewards`: the episode's reward values in order, with null for a value that is not a finite number |
| `attempt_result` | An attempt's status is saved, once per attempt. That happens after its attack inspector and the judge, and also after zero reward (which needs no attack inspector), an error, a cancellation or the spending cap, including one that stopped an attempt before its episode started, with no `attempt_start` | `episode`, null when the episode never started; `number`; `problem`, the record id of the finding it was given help for, or the one the attack inspector named for a no-hint exploit, null without one; `level`; `status`, the attempt's status as `report.json` saves it, such as `evidenced_issue` for an exploit of its finding, `other_exploit` for an exploit of another mechanism, `unattributed_exploit` for an exploit nudi could not attribute, or `no_evidenced_issue`. An attack inspector session's own status is not the attempt's |
| `judged` | A new finding is recorded, or the attack inspector judged a no-hint exploit to use a known cause. A rerun of the attack first repeats the earlier run's events | `inspector`, `hack`, `grader` or `attack`; `finding`, a hack inspector finding (`hack-INDEX`; `experiment-NNNN` in older runs), a grader inspector finding (`grader-INDEX`) or an Attacker episode; `problem`, its record id in `attack.json`, `P`, `G` or `A` and a number, the known finding's when not new; `new`; `cause`, the new finding's cause sentence, or its mechanism without one; `cause_id`, the id of its cause in `report.json`, `C` and a number; `replayed`, true when a rerun repeats the earlier run's event for this log. Older logs also have the judge's `reason`, `same_as` and `request` |
| `cause` | The judge matched a new finding's cause to a known cause, so no Attacker attacks it | `finding`; `problem`, the new finding's record id; `cause`, the known cause's id |
| `reproduced` | An inspector finding is evidenced that was not yet, or a rerun of the attack starts from the earlier run's evidenced findings | `problem`, the finding's record id; `result`, `evidenced` (older logs also have `not_reproduced`); `replayed`, true when a rerun repeats the earlier run's evidence. A later event for the same record id replaces the earlier one. This is inspector evidence; `causes[].findings[].reproduced` in `report.json` instead counts the Attacker exploits made with the finding's help |
| `provider_refused` | The model provider refused a call for the account, as at a spend limit, and the run stops all its work | `agent`, the agent whose call it was; `reason`, the provider's reason with keys removed; `running`, the inspector sessions and Attacker episodes it stopped |
| `revised` | An inspector looks again at a check it had evidenced, withdrawing or correcting that finding | `inspector`; `id`, the check id; `index`, the new assessment's index; `before` and `after`, the two outcomes |
| `withdrawn` | A finding its inspector later withdrew gets no Attacker. nudi checks this just before the Attacker would start | `candidate`, the finding; `problem`, its record id; `level` |
| `warning` | nudi records a run warning that no other kind reports; `run.json` lists it too | `message` |
| `retry` | An inspector model call or a Modal operation failed briefly and is tried again after a short wait, at most three times. A model call is retried after a timeout, a rate limit, a lost connection or a server error, never after an account refusal or another client error. A Modal file copy is retried after Modal refused its credential or lost the connection. A command in a nudi sandbox is retried only when Modal refused its start, since a later failure can follow the command's effects. The text names what failed, such as `hack-broad: a model call failed with BadGatewayError; trying again in 4 s` | `error`, the failure's type; `wait`, the seconds before the next try |
| `heartbeat` | 15 minutes passed with no other line on stderr, and again after each further 15 quiet minutes | `jobs`, the inspector sessions and Attacker episodes still open, counted by job: `Attacker`, `hack inspector session`, `grader inspector session` or `attack inspector session`. The text gives the time since the analyses began and names the findings the open jobs work on, such as `still running after 3:10:00: 1 hack inspector session; 2 Attackers on hack-1, grader-0` |
| `time_limit` | The run reaches its `time_limit` | `phases`, the analyses it stopped, and `minutes` |
| `run_end` | The run ends after attempting cleanup and report writing, also after Ctrl-C, the time limit or an error. It is the last event, when nudi can write it | `status`: the report's `status` (`complete`, `unfinished` or `time_limit`), or `cancelled`, or `stopped` with `error`; `report`, `report.json` when it was written. That is the report so far, with `status` `running`, when the final one could not be written |

How to read it:

- Lines are in the order nudi wrote them. Order events by line, not by `time`, since `time` follows the host's clock, which can be set back.
- nudi writes one event at a time and closes the file after each, so a reader sees each event as soon as nudi goes on. Sessions and attempts that run at once add whole lines, never pieces of one.
- While the run goes on, the last line can lack its newline because nudi is still writing it. Parse a line only once its newline is there.
- If nudi cannot write an event, for lack of space or another storage error, it writes no more events for that run. The log is then a whole prefix of the run's events, though the failed write can leave part of its event as a last line without a newline. A log without `run_end` is incomplete.
- `status` in `phase_end`, `session_end` and `attempt_result` is an open set. Later versions of nudi add values, so show a value you do not know as text.
- Ignore kinds and fields you do not know. Later versions of nudi add them and keep `v` at 1. A change to the meaning of a kind or field raises `v`, and a reader skips events whose `v` it does not know.
- Event strings can hold text that a model or a task wrote, and JSON decoding restores any control character in it. Before terminal or plain-text output, remove control and Unicode format characters, such as bidi overrides, from every decoded string and map key you show, `text`, `message`, `error` and every id included, as the viewer does for the report.

What the log leaves out:

- The command prints every event's `text` except that of `run_end`, since it then prints the report on stdout. After Ctrl-C or a full disk it prints one more line of its own, which says whether the report was written. When an event cannot be written, the log stops silently after that first failed write: the command prints no line about it and still prints that event's text.
- A program that starts nudi must read or discard its stderr while the run goes on. nudi writes each line there before it continues, so a full pipe pauses the run until it is read.
- Errors before the run starts, such as invalid configuration, an output folder that is not empty or an unavailable backend, are printed only; there is no log yet.
- Phase events, `reused` and `run_end` come from `send_nudis`, `send_nudis_async` and `nudi send-nudis`. A program that calls `start_run` and one analysis itself gets `run_start` and that analysis' own events only. `nudi cost` writes nothing to the log.
- An analysis stopped by Ctrl-C or the time limit has no `phase_end`, and an Attacker episode that ends with an error has no `attempt_end`. `run_end` still follows.
- The log misses every event nudi cannot write, `run_end` included, and those after it. The run goes on and ends as it would have without the log; a full disk still stops it, through its other records.
- Model calls are not events: `run.json` lists them, and every event has the cost so far. Simulator episodes are not events either, so the simulation shows only its `phase_start` and `phase_end`, and an attack finding is in `report.json` only.

## Follow mode

`nudi-view --follow RUN` shows a run that is still going, from its event log, and then the finished viewer once the run is over. The folder must exist. The log need not exist yet; until it does, the screen says that it waits for it. A folder whose log has not begun after 2 minutes stops the follow.

Once a second, the viewer reads what nudi added to `RUN/events.jsonl` since the last read. It parses whole lines only, so a last line that lacks its newline waits for the next read. Every string is cleaned as the report's strings are, before anything is drawn.

A line that is not a JSON object, a field of the wrong type, or a `v` other than `1` stops the follow with an error that names the file and line. This differs from the general reader rule above: the viewer does not skip an event of an unknown version, since a screen that skipped it would no longer match the run.

Once `report.json` reads in full with a `status` other than `running`, the viewer shows it as for a finished run. A report with `status` `running` is the report so far, which nudi rewrites after each confirmation, so the viewer keeps following. After `run_end` the report is final. A `run_end` without `report`, a `report.json` that does not read, or one still `running` (as when the final report could not be written) stops the follow with that error, naming `nudi report` for the last case. A log without `run_end`, whose `run_start` names this host and a `pid` that no longer runs, also stops the follow, naming `nudi report` to write the report. A run on another host, or a log whose `run_start` has no `pid`, is followed until it ends or the viewer is quit.

The viewer follows a folder on this machine. A run whose folder is on a Modal Volume is followed from a downloaded copy, which shows the run only as far as the copy goes.

The live screen shares the finished viewer's header and tab strip, and lays out what the events say without a status of its own:

| Part | From the events |
| --- | --- |
| Header | `following live`, `backend`, the time since `run_start` by this machine's clock, the latest event's `known_cost` against `spending_cap`, and `concurrency` of `concurrency_setting` |
| Tabs | One tab per analysis that `run_start` lists in `analyses`, then Results. Only the running phase's tab shows the findings so far, the related observations, the Attacker with no information and the logs. Another phase's tab shows its phase line, its error or the time limit, and its own agents: none for Simulation, grader inspector sessions for Grade Simulations, hack inspector sessions for Find Hacks, and Attackers and attack inspector sessions for Attack. A tab shows a spinner while its phase runs, and the Attack tab also while Attacker or attack inspector sessions run. It shows `waiting` before its `phase_start`, and a check, `unfinished`, `unresolved`, `stopped` or `Error` after its `phase_end`. An `unresolved` phase never shows a check, since the events do not say whether each of its attempts ran. A phase whose `phase_end` has an `error` shows that error and the time the run ended on its tab |
| Agents | One tile per hack inspector, grader inspector and attack inspector session between its `session_start` and `session_end`, and per Attacker episode between its `attempt_start` and `attempt_end`. A tile shows its job in title case and the time since it started in the top edge, then what it works on in words. A hack inspector session reads General search or Focused search with its `category`; a grader inspector session General review or Episode review with its episode; an Attacker its `problem`'s cause and how much it was told, or "No information, looking for any hack" for a `none` attempt; an attack inspector the try and level it checks. When the tiles do not fit, the row pages with Left and Right, as `Agents 1-3 of 5`. An analysis's `phase_end` removes its own tiles, so the other analyses' tiles stay; `run_end` removes the rest |
| Findings so far | One row per cause from `judged` events with `new`, by its `problem`'s cause: P rows, then G rows, then A rows judged new for an Attacker attempt aimed at another finding, in log order. The columns are `New?`, whether `novelty_judge` judged it new; `Inspector?`, the reproduction from `reproduced`, `-` for an A row and ✗ after a `withdrawn` event for the finding; `Full instr.?` and `Hint?`, ✓ when `novelty_judge` put an Attacker attempt at that level in the cause, else the latest Attacker attempt aimed at the cause with full instructions and with only a hint. A cell is ✓ or ✗, `-` for not tested, `?` for unresolved, and a spinner while its attempt runs. Help, behind `?`, explains each column and symbol. A replayed cause from an earlier run is drawn as it was, never as new |
| Related observations | `judged` events without `new`, collapsed under `o`: the finding's reference, who found it, whether it is new and the cause it is the same as |
| Can an Attacker succeed without any information? | A block of its own, never a row of the findings. One row per `none` attempt with its try, its status, whether it demonstrated a hack (any hack, so `other_exploit` is ✓), whether `novelty_judge` judged that hack new, and, under Cause once the attempt is settled, the cause `novelty_judge` put its episode in. A rerun's replayed A cause from a guided try is a row of the findings so far |
| Logs | The latest four events, or all kept with `l`, each labelled with its time and the job that wrote it: `novelty_judge` for `judged`, Attacker for `attempt_*` events, the inspector for inspector events, otherwise nudi. An event is put in words from its fields when they say more than nudi's text: what the job worked on, the cause's sentence rather than its id, how much the Attacker was told and how it ended. Examples: `New cause C1: CAUSE` or `Known cause C1: CAUSE` for `judged`, with the id from `cause_id` when the event has it; `Started: check of try 1 with only a hint, for CAUSE`; `Demonstrated: try 1 with full instructions, for CAUSE`; for `withdrawn`, `Not started, the inspector that found it later withdrew it: with full instructions, for CAUSE`. A `revised` event reads `Read a check again: its earlier finding is withdrawn or corrected`. A `judged` event without `new` from the attack inspector reads `Judged to use cause C1: CAUSE`, or `Judged to use a known cause: CAUSE` without `cause_id`. A `cause` event is a `novelty_judge` line in nudi's text. A replayed `judged` event keeps nudi's text, which says the finding was judged in the earlier run. Other events keep nudi's text, and `--follow` in a pipe prints nudi's text as written. Help, behind `?`, lists only the keys and symbols of the live screen, says what `unfinished` and `unresolved` mean, and lists the references |
| Results | `Run not finished` with the time it has run, then the sections of a finished run until the final report is written: Causes, one row per cause so far, with the Attacker with no information under them; Abandoned Findings, Simulation Rewards, Grader Accuracy and Work Left, each saying `Available when the run ends.`; and Cost. The cause count leaves out a withdrawn cause unless an Attacker exploited it |

When the window is short, the agent tiles take one row and the findings keep at least two rows with `+N more ↓`; `f` opens them all. When fewer than two rows fit, a single line reads `Findings So Far (N)   f open`. A table header never stands without rows.

The events do not carry everything the finished screens show. The live screen leaves out the models, a limit per session or attempt, the Simulator's episodes, a description of each related observation, how the findings are later settled or superseded, and the time limit before it is reached.

| Exit code with `--follow` | Meaning |
| --- | --- |
| As without `--follow` | The report was read in full and shown |
| `2` | The folder does not exist, its log did not begin within 2 minutes, a log line is refused, the run ended without a readable report, nudi's process ended without `run_end`, the viewer was quit before nudi wrote the report, or a finding number was given |

In a pipe, `--follow` prints the `text` of each event as the viewer reads it, then the plain report.

Return to [Usage](usage.md).

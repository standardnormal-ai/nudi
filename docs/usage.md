# Usage

See [Installation](installation.md) for Python, sandbox and inference setup. First create `nudi.toml` with your provider's settings as described under [Models](#models).

## Run an analysis

Pass a local Harbor task directory containing its task configuration, instructions, environment and grader:

```sh
nudi send-nudis /path/to/task --config nudi.toml --output runs/first
```

The output directory must be new or empty. nudi copies the task for its work and preserves the original task directory.

The default `full` analysis runs two pieces, one after the other. The first, the hack phase, is the hack inspector with the Attackers beside it. The no-hint Attacker attempts start together with the hack inspector. Problems form only after evidence. Each hack inspector reading that evidences an issue is judged as it is recorded: the judge, one call of the run's inspector model, compares the finding with the problems known so far. A problem is one cause, one flaw of the grader or environment; a finding with the cause of a known problem becomes a new case of it, also where its location differs, and matching paths alone do not make the same cause. The judge reads the finding's category, outcome, mechanism, the requirement and scoring text it cites (each excerpt cut at 600 characters), its location and capture point, and for each problem its cause and its cases, each with its check, outcome, mechanism, location and capture point. It reads no check program. The first finding needs no call, and a second reading of the same experiment joins its problem without one. The judge's call is not a turn of the hack inspector and is not in its transcript. A legitimate or unknown reading makes no problem, and neither does a control probe, one with `control` true, which checks the measurement itself. A new problem is named `P1`, `P2` and so on. Its first finding with full guidance gets a full-hint Attacker attempt as soon as a slot is free, and the single (minimal) hint when the full hint exploited it. A no-hint attempt that exploits the task is judged too, with the category, location and capture point of the attack inspector's experiment that evidenced it: the same as `P2` means `P2` was found with no hint, and a new one is the Attacker's own problem, `A1`, which is not attacked further. An exploit the attack inspector attributes to a different problem than its attempt's target (`other`) is judged the same way: its finding in `attack.json` names that problem as `problem`, and the attempt keeps its target's. The hack phase ends when the hack inspector, the no-hint attempts and every attack it started have ended. The hack inspector never measures an Attacker episode, so those attempts never become its evidence.

An inspector's check program has the bound grading uses for this task, as a setup program has; one that does not finish in it is stopped, measures nothing and reaches the inspector as a tool failure, not a finding. It must exit 0 and print one JSON object with `observations` and `results` objects and a finite `results.deserved`, the score the cited scoring rule gives the submission from what the check measures; a program that is not valid Python is refused with its line number before any sandbox starts. nudi tests this as soon as the check ends: a check that breaks it gets a reply that starts with `contract`, naming what broke and the repair, the same episode checked again without a setup program, which then runs although its case was measured. A reading that stays unknown gets a reply that starts with `repair`: what nudi still needs and the cheapest route, the same check interpreted again when only the claim lacks something, else the same episode checked again. A positive reward equal to the deserved score while a requirement is violated stays unknown as before; its repair names both readings that resolve it, a deserved score that applies the violated requirement or observations showing the requirement is supported, and prefers neither. A probe's reference excerpt matches its source whatever the whitespace between its words, and a refused probe names the requirement or scoring reference that failed; the probe schema marks the fields it requires. An attack inspector probe's category is its attempt's, `accepted_invalid` or, for valid work, `rejected_valid`; nudi sets it, and its probe schema has no category field. run_experiment returns, with the receipt, a draft reading of what nudi knows: the experiment, episode and check, the category, the native reward key and reward, the requirement and scoring references, the location and capture point, the observation keys the check measured, its deserved score, and the fields the inspector supplies. A session has one open draft at a time: a further run_experiment runs nothing and returns that draft. interpret_experiment completes it with a claim whose schema states its required fields. Neither the probe nor the claim schema admits a field it does not declare, at any depth, so a reference in an undeclared place, such as a hack inspector citation or a citation inside a derivation, is refused as an argument error. interpret_experiment takes the open draft when no experiment is named, and an experiment or check id to repair an earlier interpretation. A claim whose derivation, or any further reading in it, names an observation key the check did not measure is refused at once. An experiment's `revisions` records the reasons nudi refused its claims; it does not record failed submissions or claims the schema rejected as argument errors. A session that ends with its draft open leaves that experiment `unfinished`: its reading is unknown with that reason, and an inspector can still complete it by its experiment id.

The second piece is the Simulator, then the grader inspector, which reads the hack inspector's findings as places to look, then the attack phase. The attack phase judges each evidenced grader inspector finding against every problem so far, from its own claim, outcome, check and experiment. A known problem is not attacked again; a new one, `G1`, `G2` and so on, gets the full hint, then the single hint when the full hint exploited it. A failed judge call counts the finding as a new problem, with one warning. Select a subset with `--analysis`: `hacking` runs the first piece alone, `simulation` the Simulator and the grader inspector.

```sh
nudi send-nudis /path/to/task --config nudi.toml --analysis hacking --output runs/hacking
nudi send-nudis /path/to/task --config nudi.toml --analysis simulation --episodes 20 --output runs/simulation
```

To try the attack again without inspecting again, see [Rerun the attack](#rerun-the-attack). To analyze several tasks in one command, see [Several environments](#several-environments).

Progress goes to stderr, one line for most events of `RUN/events.jsonl`. After 15 minutes without a line, nudi prints one that gives the time since the analyses began and the inspector sessions and Attacker episodes still open, with the problems they work on, and again after each further 15 quiet minutes. Simulator episodes and judge calls are not counted, so during the simulation it says that no inspector session or Attacker is open.

## Options

| Option | Default | Meaning |
| --- | --- | --- |
| `--analysis` | `full` | `full`, `hacking` or `simulation` |
| `--episodes` | `12` | Ordinary Simulator episodes |
| `--focused-attempts` | `2` | Focused attempts per grader inspector or hack inspection category |
| `--attacker-tries` | `1` | Maximum Attacker attempts per candidate and hint level |
| `--discovery-attempts` | `1` | Attacker attempts without hints, which start with the hack inspector |
| `--minimal-hints`, `--no-minimal-hints` | On | Attempt each candidate the full hint exploited with the single (minimal) hint too |
| `--attack-from` | Unset | Earlier run directory of the same task; copy its inspections and run only the attack |
| `--isolated-inspections` | Off | Inspect each ordinary episode in a separate grader investigation |
| `--backend` | `docker` | `docker` or `modal` |
| `--concurrency` | `8` | Sandbox limit, also constrained by local Docker capacity |
| `--spending-cap` | Unset | Stop admitting model calls when known inference cost reaches this USD amount |
| `--time-limit` | Unset | Whole-run limit in minutes. At the limit the run stops, cleans up and reports, as Ctrl-C does |
| `--credentials-file` | Unset | Dotenv file of inference credentials |
| `--workspace-memory-mb` | On Docker the smaller of 512 and the task's memory, on Modal the task's | Memory limit in MiB of an Inspector workspace; experiments and native episodes keep the task's limits |
| `--config` | Unset | TOML configuration file |
| `--output` | Required, here or in TOML | New or empty run directory |

Phases run one after another; parallelism is only within a phase. During the hack phase its Attacker attempts and the hack inspector's sessions share one set of slots, first come first served; the hack phase's `phase_start` event gives their number as `slots`, and `run_start` lists the phases that will run as `analyses`, only `attack` in a rerun with `--attack-from`. Inspection sessions and Attacker attempts run at once, up to half of `--concurrency` and at least one, because each holds a workspace and an experiment sandbox. On Docker they run one at a time when a workspace needs more memory than an episode. Simulator episodes use the full limit. `--concurrency` limits sandboxes, so a task's helper containers can exceed it, and one workspace may still admit one experiment even at `--concurrency 1`. Attacker retries of the same candidate at the same hint level wait for each other. A hack inspection category stays open after a finding, and its focused session is asked again, up to its attempts, while `open` names a failed attempt of its category that no later attempt recovered, unless the measurement was unavailable; a grader inspector category stops at its first evidenced issue.

Calls already admitted can exceed the spending cap. Unknown inference costs remain unknown; the cap is not a strict billing limit. A call cancelled in flight has no usage, so the report counts it apart from calls with unknown prices. A call that has no response when its episode or session ends without an error, as after an agent timeout, counts among the calls with unknown prices. The report gives each reason a call has no price with its count, also under `configuration.unknown_reasons` in `report.json`: no response before its calls ended, a failed request, or LiteLLM's own pricing error. nudi never guesses a price. Each call in `run.json` has `started`, when nudi admitted it, and `ended`, when its response, failure or the end of its calls was recorded; older records have neither. The report also gives the known cost of each job: Simulator, grader inspector, hack inspector, judge, Attacker, attack inspector and persistence probe; a run from before the judge has a grouping job instead. Modal sandbox costs are separate from the inference cap.

Some tasks take hours, so the time limit has no default. A stop (Ctrl-C or the time limit) keeps what ended before it: the hack inspector's records, every finished Attacker attempt and every problem judged so far, with the conditions an Attacker tried it under. The grader inspector's problems are attacked last, so a stop can leave them untested. A run stopped after the hack phase reports its attack as `cancelled` and unfinished, since the attack phase did not run. The hack phase's attempts also spend before the Simulator and grader inspector do. So that a time limit leaves as few problems untested as it can, every problem's first full-hint attempt runs before discovery, valid work, any retry, the minimal hint and the no-hint attempt aimed at it. A valid-work attempt starts only when the task's agent timeout fits in the time left; otherwise its status is `insufficient_time` and the report says it did not start. On Modal, each sandbox of a time-limited run also gets a lifetime of the limit plus 15 minutes, at most 24 hours.

Once 20% or less of a bound is left, nudi tells the agent that works under it in one line, so it can finish first: at the end of each inspector tool reply, error replies included, for the session's model turns (the Deep Agents step limit of 9,999 graph steps, about 4,999 turns per request), the time limit and the spending cap; and at the end of the Attacker's terminal output, for the task's agent timeout, the time limit and the spending cap. run_experiment's description states the task's grading bound, which stops an experiment's setup and its check. Simulator episodes get no such line, so they run as in training. A Simulator episode that the spending cap ends early is graded as Harbor leaves it, and is not representative.

By default each problem gets one full-hint attempt, valid work included; when the full hint exploited it, one single-hint attempt; and when the single hint exploited it, one no-hint attempt aimed at it. The run also makes one independent no-hint attempt, which starts at once. The single hint says that it marks where one specific flaw is and that only an exploit of that flaw counts. The no-hint attempt aimed at a problem gets exactly the independent attempt's instruction; only its attack inspector is told which problem it aims at. A step counts as working only when the attack inspector confirmed a reproduction of its target: another exploit, an exploit it could not tie to the target, or an unclear result stops the cascade. A step after one that did not exploit the problem is not run: its condition is `not_needed`. A valid-work candidate gets neither a single-hint nor an aimed no-hint attempt: both conditions are `not_applicable`. No attempt is retried beyond `--attacker-tries`. With `--no-minimal-hints`, or `minimal_hints = false` in the configuration file, each candidate's minimal and aimed no-hint conditions are `not_requested`: they keep the attack neither partial nor unknown, `report.json` has `minimal_hints: false` and the Markdown report says minimal hints were not requested.

Use `nudi send-nudis --help` for the complete CLI options.

## Models

Configure your OpenAI-compatible provider for the `simulator`, `inspector` and `attacker` roles under `[models.<role>]`. Set all three roles so every model call uses your chosen provider. Each configured role replaces that role's default model settings in full.

Replace `your-model` with your provider's model ID and `https://api.your-provider.com/v1` with its OpenAI-compatible base URL. Keep the `openai/` prefix to select the OpenAI-compatible API:

```toml
output_dir = "runs/configured"
analysis = "full"

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

CLI options override TOML values. Relative `output_dir`, `credentials_file` and `attack_from` paths in TOML resolve against the configuration file's directory. `api_key_var` names an environment variable; keep credentials out of the TOML file.

## Reports

Each run writes `report.md` and `report.json` beside its retained records and evidence. The CLI also prints the Markdown report. Completion refers to the selected analyses. An incomplete investigation or missing evidence must not be read as evidence that a task has no flaws.

The attack's candidates are the hack inspector's findings, named `hack-INDEX`, and the grader inspector's evidenced findings, named `grader-INDEX`; `attack.candidates` in `report.json` names each one's `source` inspector. The judge forms the problems as findings arrive, and the attack tries one finding of each evidenced problem, the first with full guidance. `report.json` lists them under `attack.problems`, each with its `id`, its `source` (`hack inspector`, `grader inspector` or `Attacker`), its `members` (the hack or grader inspector findings or Attacker episodes the judge placed in it; older reports name hack inspector experiments), its `findings`, its `cases` (each finding or Attacker exploit as the judge reads it, with its check, outcome, mechanism, location and capture point) its `exploited_with`, the least information under which an Attacker exploit of it was observed: `none` (a no-hint attempt exploited it, whatever it was aimed at), `minimal`, `full`, or, without an exploit, `not_exploited` (the full hint failed), `no_guidance` (its findings gave the Attacker no guidance, so it was not attacked) or `unknown` (the run did not settle it, as after a stop). Older reports have `help_needed` in its place. Each problem has its `conditions`, one entry per condition an Attacker tried it under, by the stream of its attempts: `full`, `minimal` and `none` aimed at its findings, in the cascade's order; then `elsewhere_full`, `elsewhere_minimal` and `elsewhere_none`, attempts aimed at another problem, listed only when one of them exploited this one, as the judge named it; then `independent`, the no-hint search aimed at no problem, which a problem of correct work the grader fails has not. Each entry has its started `attempts`, how many `exploited` the problem, the Attacker `model` and the `status`. Each problem also has its `level`, 2 to 5, and `label`, its step on the exploit chart in `docs/diagrams/hacks.mmd`; its `cases` follow it in `report.md`, one line each, then one line per condition, such as "With only a hint: 0 of 1 attempts exploited it, MODEL, no_evidenced_issue." or "With only a hint: Not run, the previous step did not exploit it."

| `level` | `label` | When |
| --- | --- | --- |
| 2 | ●●○○○ reproduced exploit | an inspector finding evidenced it and no Attacker exploited it (`not_exploited`, `no_guidance`, `unknown`) |
| 3 | ●●●○○ exploit executable by learner with full information | an Attacker that received full instructions exploited it (`full`) |
| 4 | ●●●●○ exploit executable by learner with hint | an Attacker that received only a hint exploited it (`minimal`) |
| 5 | ●●●●● exploit executable by unaided learner | an Attacker with no extra information exploited it, whatever it was aimed at (`none`) |

`report.md` and the viewer show the label, and at level 2 where its findings were evidenced, `scope` ("evidenced in a package sandbox" or "evidenced in a native episode", native when any of its findings is; omitted when the report has no inspection that says where), then the reason, "Attackers did not exploit it", "not attacked: no guidance" or "no clear Attacker result". `report.md` lists the problems by level in its Answer and one line per problem in its Attack section, highest first, each naming its `source`, every other inspector whose finding is among its `members`, and the independent attacker when the no-hint search aimed at no problem exploited a problem an inspector found. A problem is formed only from evidence, so there is no level 1. Problems that neither an inspector's evidence nor an Attacker's exploit confirms are leads: an older record's problems judged before measurement, and a problem whose findings later readings of their checks withdrew, as legitimate or unknown, which loses its evidenced status but keeps its `cases` as receipts. `attack.leads` in `report.json` lists each one's `id` and `cause`, and `report.md` names them on one line, "Leads, which no evidence confirmed", with no level; so does a stored report's level-1 problem, or one whose `help_needed` is `not_reproduced`. Readings that evidenced nothing stay among the inspections' `experiments`; the Categories searched section names each category's `open` entries as its leads and counts each category's latest legitimate readings, a count and no verdict. When the problems have ids, the line after the problems by level, in the Answer and in the Attack section, says where each id's letter comes from: "P: found by the hack inspector's search. G: found by the grader inspector in the simulations. A: found by an Attacker, not among the inspectors' findings." `source` in `report.json` names it too. A problem whose findings are correct work the grader fails is no exploit: its `label` is "Correct work failed", the words of `docs/diagrams/simulation.mmd`, then how an Attacker reproduced it ("reproduced by an Attacker with full instructions", "with only a hint" or "with no extra information"); its `level` still orders it, and `report.md` names these problems on lines of their own after the problems by level. Reports written before `level` show the level from `help_needed`, in the words above. `report.json` keeps every problem. A problem's `reproduced` in `report.json` says that an Attacker exploit was confirmed for it: an attempt's exploit was judged a reproduction of the candidate it tested; the attack inspector compares the episode with that candidate's mechanism and guidance only, not with the problem's `cause`. It is not the `reproduced` event, which says whether the hack inspector's experiment, or a grader inspector finding, evidenced the problem; an evidenced problem that no Attacker exploited has `reproduced` false. `reproduced_findings` names the findings that reproduction tested. A problem's `exploited_by` lists each attempt that targeted another problem and exploited this one, as the judge named it, with its `episode` and `target`; its line in `report.md` says "exploited by Attacker EPISODE, which targeted TARGET", in place of any level 2 reason. Its other findings were not tested, and the report never calls them reproduced. Each experiment row keeps its probe's `location` and `capture_point`; in older reports a hack inspector experiment whose probe was judged before it ran may have the status `known_problem`. A member, like a `judged` event's `finding`, is a hack inspector finding (`hack-INDEX`), a grader inspector finding (`grader-INDEX`) or an Attacker episode (`NNNN-attacker`); older runs name a hack inspector experiment (`experiment-NNNN`). The `judged` event records each judgement, and `reproduced` that an inspector finding evidenced a problem that was not yet evidenced, or with the result `withdrawn` that later readings withdrew all its findings. `attempt_end` comes when an Attacker episode returns, before the attack inspector judges it; each attempt then ends with one `attempt_result` event, with its `episode`, `problem`, `level`, `number` and the `status` saved for it, whatever its outcome; `episode` is null when the attempt stopped before its episode started, as at the spending cap. A run from before the judge has problems without these fields, and its report still loads. The grader inspection in `report.json` names the hack findings it read under `hack_findings`, and under `hack_inspection` whether that hack inspection was `complete`, `partial` or `failed`; a hack inspection that failed gives the findings it saved before the error.

Each Attacker attempt gets its attack instruction first, then the task's own instruction between `<task>` and `</task>`, then a one-line reminder of its goal. That text is saved as `episodes/<episode>/nudi-evidence/extension.md`.

The report lists the categories searched and the cheats found. Category states stay inside nudi to control the search and remain in `report.json` for compatibility.

Every run_experiment, interpret_experiment and inspection_status reply, also a refusal of the call's arguments, starts with `open`: what keeps the session's categories unsettled, each entry with its `id` (an experiment, episode or category), `category`, `reason` and `next` step. Its sources are an open draft reading; an experiment whose latest reading is unknown, with its reasons and repair, or agrees with the reward but leaves an item unresolved; a failed check or a check that broke the output contract, until a later check of its episode keeps the contract; a failed attempt no later attempt of its category recovered; a requested category with no reading that agrees with its reward; and, for the grader inspector, an ordinary episode whose label is unknown. A session sees its own and inherited experiments and what names its categories or its episode. A category settles `no_evidenced_issue` once its sessions ended and no entry names it, and an inspection is `complete` only when `open` is empty. Tool errors, duplicate cases and refused out-of-scope probes are history: they appear in limits and attempts but keep nothing open. A reading of a retained check outside an experiment, such as the attack inspector's reading of the check nudi reran on its episode, is in `open` like an experiment's. An ordinary episode without a native reward cannot be labeled: it is listed in limits and keeps nothing open. interpret_experiment accepts only the session's own experiments and checks, a check staying its session's when its measurement failed, and, for a session that continues broad's conversation, those of broad; a session that started fresh, as when broad's conversation could not be continued, inherits nothing. Another session's experiment or check is refused, so the session measures its own case. `report.json` keeps what was left open as `inspections.<inspector>.open`, and `report.md` has one line per open category under Categories searched.

When Modal reports that an inspector session's workspace or experiment sandbox ran out of memory, that inspector attempt has the status `out_of_memory`; for an attack inspector session, so does its attack attempt. An Attacker episode that runs out of memory, or an attack attempt that fails outside its attack inspector session, keeps its usual failure status, such as `tool_failure`. Docker does not report this to nudi.

An inspector session that uses all its model turns without returning its summary has the status `step_limit`, with a cause such as "the attack inspector ran out of steps after 4999 turns"; for an attack inspector session, so does its attack attempt.

Grader classification rates require a supported binary reward contract. Unresolved cases are reported separately. `report.md` and the viewer name the counts and rates as `docs/diagrams/simulation.mmd` does: TP (Correct work passed), FP (Incorrect work passed), FN (Correct work failed), TN (Incorrect work failed), FDR (Of accepted work, how much was incorrect?) and FNR (Of correct work, how much was rejected?). Grading analysis for non-binary rubric totals is not supported. When a configuration's native decision rule is grounded in the grader's source, the report also gives its native pass rate over the usable rewards, with a 95% Wilson interval that assumes independent episodes. In `report.json` it is each `pass_rate` under `metrics.confusion`, with the interval as `interval`.

Under Ordinary rewards, each reward of each configuration shows its median, minimum, maximum and skewness beside the mean and SD. When only two values occur, it also shows the share at the higher value with a 95% Wilson interval. From 10 usable rewards, the report can add flags, listed in each reward's `flags` in `report.json` and under Ordinary rewards in `report.md`. `identical_rewards` means every usable reward has the same value. `low_minority` and `high_minority` mean a few rewards lie more than three interquartile ranges below the first quartile or above the third (Tukey's outer fences); the flag names those episodes, their rewards and any timeout, error or refusal they recorded. A flag is a reward pattern that points to episodes worth reading, not a finding. It states no cause and changes no status, exit code, label or rate. With fewer than 10 usable rewards the flags are not evaluated, and the report says so.

`copies` in `run.json` and `report.json` lists nudi's state copies: filesystem copies of the grading environment, taken when grading starts and after the grader returns. `seconds` is the whole copy operation. In `size_bytes` and `pause_seconds`, null means unknown, not zero. On Docker, `size_bytes` is the source container's writable-layer size as `docker inspect --size` reports it, sampled before the commit; it is null when Docker reports no size or cannot compute one. On Modal it is not recorded and stays null, because Modal reports no snapshot size. `pause_seconds` is the elapsed call duration of the `docker commit` or Modal snapshot call, timed by nudi around the call; it is not a measured freeze. Docker pauses the container's processes during the commit, so they were paused for at most that long. Modal does not document whether a snapshot pauses the sandbox's processes. `pause_seconds` is null when the commit or snapshot failed, timed out or was cancelled. A Modal snapshot that fails with `NotFoundError` fails that copy and its experiment; nudi does not retry it.

| Exit code | Meaning |
| --- | --- |
| `0` | Every selected step ran to its end, also when it left evidence unresolved |
| `1` | A step failed or stopped, as at the spending cap or the time limit, or records storage was exhausted |
| `2` | Invalid configuration or startup failure |
| `130` | Interrupted with Ctrl-C; the written report is printed too |
| `143` | Stopped by SIGTERM, as `kill PID` sends; the written report is printed too |

The exit code and `status` in `report.json` say whether the steps ran, not what they found. `status` is `complete` when every selected step ran to its end, `time_limit` when the limit ended the run with no phase failed before it, `partial` when a step failed, stopped, as at the spending cap, or never ran, and `stopped` in a report that `nudi report` wrote for a run whose process ended without closing it out (see [Report a stopped run](#report-a-stopped-run)). A step that returned `partial` with an attempt that failed to execute, such as an inference or tool failure, an Attacker episode that raised, or a native timeout without a reward or an interpretation, is unfinished unless a later attempt of the same work ended without a failure: the same candidate at the same hint level, or the same inspector category or episode, and every unrestricted category after a failed broad session. The Answer then says it "had an attempt that failed to run". A recovered failure stays in Warnings, and a step that ends `complete` is never counted failed. `unfinished` names each step that did not run to its end, with its status, and `unresolved` names each step that ran to its end with evidence left unresolved, such as a category or an Attacker attempt the inspectors did not settle; its status in `analyses` is then `partial`, or `not run` for an attack whose findings gave no guidance. The Answer's first line says the same in plain words, also as `outcome` in `report.json`:

- "Finished. Every step ran."
- "Finished with gaps: the hack inspector failed. Results below are what was found." names each step that did not run to its end.
- "Stopped by you after 0:42. Results below are what was found so far." after Ctrl-C.
- "Stopped by a termination signal after 0:42. Results below are what was found so far." after SIGTERM.
- "Stopped at your time limit after 1:30. Results below are what was found so far."
- "Could not start: ..." with the first reason, when no step ran.
- "Stopped: the nudi process ended without closing out the run. Results below are what was found so far." from `nudi report` after the process ended with no chance to save, as after `kill -9`.

A finished line adds "Evidence stayed unresolved in ..., so the run may miss more." when a step left evidence unresolved. The time is hours and minutes from the start of the run to its end; a run recorded before nudi kept those times has none. On stderr, each step's last line says what it did, for example `attack done after 0:00:11: 15 attempts, 1 exploit, 2 cases where correct work failed; some results unclear`, where "some results unclear" is a `partial` step and "stopped" a cancelled one. The attack's exploits are confirmed cases where incorrect work passed; a confirmed case where correct work failed is counted apart, and its `phase_end` event gives both as `exploits` and `correct_work_failed`, besides all of its `findings`. The attack continues the attack that ran beside the hack inspector, so its record and its `phase_end` event count those attempts too; its line counts the new ones, as "1 new attempt, 16 in all", or says "nothing new to attack", and the event adds `new_attempts`.

`kill PID` (SIGTERM) stops a run as Ctrl-C does, also a run started in the background, where the shell ignores Ctrl-C; the command then prints `nudi: stopped by a termination signal` and exits `143`. Ctrl-C prints `nudi: stopping: saving what was found` at once, and so does SIGTERM; a repeated Ctrl-C prints it again and changes nothing else. The stop waits at most 30 seconds for the cancelled step, such as a sandbox command that never returns, then saves the records and the report; it waits at most 30 seconds more for the deletion of state copies and 30 more for any other work before it exits, so a stop usually ends within about 2 minutes, except during the final deletion of state copies at the run's own end, which can take several minutes on Modal. Allow at least 3 minutes before a hard kill: a caller that force-kills sooner, as `timeout -k 10s` does, leaves Docker containers running. Work still running then is named in Warnings and left: a Modal sandbox it holds ends at its lifetime, and a Docker container stays until you remove it.

Warnings that libraries nudi uses log through Python logging, such as asyncio's, go to `library.log` in the output folder instead of stderr; with several tasks it is the batch folder's. LiteLLM also prints its own warnings to stderr, through its own handler, and so does a library that writes to stderr itself. Before the command ends, nudi closes LiteLLM's cached connections.

Every field an agent reads in `report.json` and `summary.json` is in the [field reference](report-fields.md).

## Run from an agent or script

A run takes hours, and stdout gets the report only at the end, so start nudi in the background and poll. Send stdout and stderr to files and keep the exit code:

```sh
mkdir -p runs
nohup sh -c 'nudi send-nudis /path/to/task --config nudi.toml --output runs/first > runs/first.md 2> runs/first.err; echo $? > runs/first.exit' > /dev/null 2>&1 &
```

Then check every few minutes:

1. `runs/first.exit` exists: the command ended. Its number is the exit code in the table above. It is the authority on a stop, also after `run_end`: a Ctrl-C or SIGTERM that comes while nudi writes its last report can leave `run_end` and `report.json` saying `complete` while the command exits `130` or `143`.
2. Otherwise `runs/first/events.jsonl` grows, one JSON line per event. The run is over at the line whose `kind` is `run_end`; its `status` says how it ended and its `report` is `report.json`, or null when no report was written. Long silences are normal: a heartbeat line comes after each 15 quiet minutes, and the simulation writes nothing else for about 90 minutes with the default 12 episodes. Silence is not a hang.
3. The command ended with exit code `2` and `events.jsonl` does not exist: nudi refused to start. `runs/first.err` has the one-line reason.

When it is over, read `runs/first/report.json`: `status`, `outcome` and `attack.problems`, as the [field reference](report-fields.md) lists them. The same report is in `runs/first.md`. Exit `0` means every step ran, `1` that a step could not finish or the run stopped, as at the time limit, `2` invalid input or a refused start. These say whether the steps ran, never whether the task can be cheated; that is in `outcome` and `attack.problems`.

To stop the run early, `kill` the `pid` of the first event, `run_start`, not the `sh` around it: nudi saves the records and the report, writes `run_end` and exits `143`. Allow at least 3 minutes before a hard kill, as [Reports](#reports) explains.

If the process ended without a `run_end` line, for example after `kill -9`, run `nudi report runs/first` to write the report from the records.

## Report a stopped run

```sh
nudi report runs/first
```

writes `report.json` and `report.md` again from the run's records, prints the report and exits as the run would have: `0` when every step ran, `1` when a step could not finish or the run stopped, as at the time limit, `2` for a folder without `run.json`. It makes no model call and starts no sandbox. A run whose `events.jsonl` has no `run_end`, such as one whose process was killed, gets `status` `stopped`: its steps that were still going stay `running` under `unfinished`, and the Answer's first line says the process ended without closing out the run. A run whose `run_end` has `status` `stopped`, such as one whose records host filled at its last write, also gets `status` `stopped`, with that event's `error` in the Answer's first line, even when every step had saved its records. So does a run whose `run_end` has `status` `cancelled`, as after a Ctrl-C or SIGTERM during the final deletion of state copies; its Answer's first line says the run was interrupted. While the run's process still runs on this host, by the `pid` in `run_start`, it refuses with exit code `2`. Pass `--credentials-file` with the run's credentials file so its keys are redacted from the report as in the run's own; keys in the environment are redacted without it.

## Rerun the attack

To try the attack again without inspecting again, name an earlier run of the same task with `--attack-from`:

```sh
nudi send-nudis /path/to/task --config nudi.toml --attack-from runs/first --attacker-tries 3 --output runs/attack-again
```

The new run only reads the earlier run directory. It copies the earlier hack inspection record, the simulation and grader inspection record when that run has them, and every episode and sandbox the earlier run record lists, so the new directory is a whole run that `nudi-view` reads. It does not copy the earlier attack record, but it starts from the problems that record judged, and its event log repeats their `judged` and `reproduced` events, each with `replayed: true` and a text ending "in the earlier run", without calling the judge. A replayed event is not this run's finding: an Attacker member it names was found in the earlier run. A finding no recorded problem holds, as in a run from before the judge, is judged first. The new attack then tries every evidenced problem again from its first full-hint attempt, and makes its no-hint attempts again. It keeps only the earlier problems that were evidenced or that an Attacker found; an earlier problem nothing evidenced is dropped. Each kept problem has `origin`, the earlier run's directory, and `earlier_exploited_with`, the least information under which an Attacker exploited it there. A kept problem this run's Attackers do not exploit again keeps its earlier level, labelled "evidenced in run DIR at LABEL; not found again here" with LABEL its earlier label. `earlier_exploited_with` is read from the earlier run's own attempts, so a rerun of a rerun names only the run it read. It runs only the judge and the attack, with this run's models and settings; `--analysis`, `--episodes`, `--focused-attempts` and `--isolated-inspections` do not apply.

A partial or stopped earlier inspection is used as it is. The report keeps its status and names the earlier run in its Answer and in `configuration.attack_from`. An earlier analysis that failed before saving a record, or that stopped, is unfinished: the report is partial, and the Answer names that analysis. Its costs and warnings are this run's; the inspection's cost stays in the earlier run's report. The earlier attack is not copied, but its Attacker episodes are, so they are listed among the other episodes.

nudi refuses before any model call or sandbox when the earlier run has no usable hack inspection record, is a run of another task directory, holds the output directory, lists an episode or sandbox name that is not a single folder name or lists a name twice, or contains a link among the folders and files it would copy. It also refuses a task whose files changed since the earlier run, found by the task digest each earlier sandbox record stores, and an earlier run with no sandbox record to compare, because that run's inspection then may not describe this task; run a new analysis instead.

nudi uses the earlier `run.json` and inspection records as nudi wrote them; episode and sandbox folders hold task output, so their names and links are checked before copying. The earlier run directory may be a link, such as `runs/latest`; nudi then reads the directory it points to, and the report names that directory. The task path check compares the path the earlier run stored, so a relative task path needs the same working directory as the earlier run.

## Several environments

Give several task directories, for example a folder of tasks through a shell glob, to analyze each one in one command:

```sh
nudi send-nudis tasks/*/ --config nudi.toml --output runs/batch-1 --backend modal --spending-cap 10 --concurrency 8
```

With several tasks, `--output` names a new or empty batch folder. It holds one ordinary run folder for each environment, named after its task folder, plus `summary.json` and `summary.md`. Each run folder is what a run of that task alone writes, so `nudi-view`, `nudi cost` and the report read it as usual. With one task the command behaves as before and writes no summary. The CLI prints `summary.md`, not each report, and every progress line on stderr begins with its environment's name. In Python, `send_environments(task_dirs, config, **options)` and `send_environments_async` return the summary and write the batch layout even for one task.

Each summary row gives the environment's task and run folders, its `status`, the `exit_code` it would have alone, its `execution`, the Answer's first line, which says how the run ended, its `answer`, the Answer's verdict line, its `known_cost`, its Modal estimate, its share of the limits and its error, if any. The summary also gives the totals and how they were split. It has no combined verdict, and no finding is grouped across environments.

nudi refuses the whole command with exit code `2` before anything starts when two tasks have the same folder name, the batch folder is not new or empty, the batch folder or the credentials file is inside any task, `--attack-from` is given, or the configuration is invalid. A task that fails the task checks, such as a folder without `task.toml` or a task the backend does not support, is `refused` and the others still run.

The limits are totals for the command, split once at the start over the environments that pass the task checks:

- `--spending-cap`: each environment gets an equal share. An unspent share goes to no other environment.
- `--concurrency`: on Modal at most `concurrency // 2` environments run at once, each with `concurrency` divided by that number and at least 2 containers, so their sandboxes stay within the total; at `--concurrency 1` one environment runs, and its workspace may still admit one experiment, as in a single run. The rest wait in the given order. Each environment starts at least 30 seconds after the one before, also one that takes the place of an environment that ended early, so Modal's App creation rate limit is not met. On Docker environments run one at a time, each with the whole setting.
- `--time-limit`: one deadline for the command, split equally over the rounds in which environments run. An environment that would start after the deadline is `not_started`. Startup and cleanup run outside each share, so the command can end after the deadline.

| Status | Meaning | Exit code alone |
| --- | --- | --- |
| `complete` | Every selected step ran to its end | `0` |
| `time_limit` | Its share of the time ended with no failed phase | `1` |
| `partial` | A step failed or stopped | `1` |
| `stopped` | Records storage full or an unexpected error | `1` |
| `refused` | The task checks or the run start refused it, for example for capacity, backend or credentials | `2` |
| `not_started` | The deadline, Ctrl-C or SIGTERM came before its start | None |
| `cancelled` | Running at Ctrl-C; its report is written | `130` |
| `terminated` | Running at SIGTERM; its report is written | `143` |

The command exits `0` when every environment would exit `0` alone, `2` when no environment could start, `130` on Ctrl-C, `143` on SIGTERM and `1` otherwise. When no environment could start, `summary.md` reads "Could not start: no environment started." On Ctrl-C or SIGTERM the running environments write their reports, the waiting ones are `not_started`, and `summary.md` is written and printed.

## Modal cost

On Modal, the report and the viewer show two estimates of the sandbox cost: one at the CPU and memory the sandboxes requested, and one if all used their limits. Neither is a maximum: no recorded bound covers storage or sandboxes still running. Each run's sandboxes go in their own Modal App, `nudi-<run id>`, so the real bill can be read later:

```sh
nudi cost runs/first
```

It prints Modal's bill for that run's sandboxes and exits `0`, or prints one line saying why not. Exit `1` means try again later: the line says when, or the billing report failed or has no row for the run yet. Exit `2` means no bill will ever exist: the run used another backend or started no Modal sandbox, or the folder has no readable `run.json`. Modal reports whole hours, about 10 minutes after each hour ends, and only on Team and Enterprise plans. The bill is before credits and covers sandboxes only. nudi monitors this cost and never limits it.

## Viewer

`nudi-view` shows a finished run in the terminal: the answer and findings card, each phase with the findings beside it, and the evidence for each finding. It reads only the run's `report.json`, which nudi 0.0.0 or later must have written, and its `events.jsonl` when it follows a run that is still going. Build it from the repository root with Go 1.27.3 or later, as `tui/go.mod` requires:

```sh
(cd tui && go build -o nudi-view .)
```

Then, from the same directory, open a run folder, go straight to the evidence for its problem P2, or to its finding 3:

```sh
tui/nudi-view runs/first
tui/nudi-view runs/first P2
tui/nudi-view runs/first 3
```

A problem id, P, G or A with its number as the report names it, opens the finding that shows the problem: the one the attack tested, else its first finding, else for a problem an Attacker found the attack finding of its episode.

Use `←` and `→`, or `h` and `l`, to move between phases or findings, `↑` and `↓` to scroll, `enter` to open the evidence, `tab` to switch between evidence and limitations, `esc` or backspace to go back and `q` or Ctrl-C to quit. Pass `--no-intro` to skip the opening animation, which is also skipped when `CI` is set. In a pipe the viewer prints plain text, the card, or the finding a problem id or N names, for scripts and agents. It exits `0` for a complete run, whose steps all ran, `1` for any other run, such as one in which a step failed or stopped or one that reached its time limit, and `2` when the folder holds no readable report.

A run with `--backend modal` keeps its folder on the machine that ran nudi. If nudi itself ran on Modal and wrote to a Modal Volume, download the folder first:

```sh
modal volume get VOLUME RUN runs/RUN
tui/nudi-view runs/RUN
```

To watch a run that is still going, follow its folder. The viewer shows the running sessions and Attacker attempts, the attack and what was found so far, from the run's `events.jsonl`, and the card once nudi writes the report:

```sh
tui/nudi-view --follow runs/first
```

Press `q` to stop following; the viewer then exits `2`, since the run had no report yet. It also exits `2` when nudi's process on this host ended without closing out the run, or when no log began in the folder within 2 minutes. A run on Modal is followed from a copy of its folder downloaded as above, and shows the run as far as that copy goes.

[Viewer contract](viewer.md) lists the fields it reads.

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

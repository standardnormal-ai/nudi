# Usage

[Installation](installation.md) covers Python, tasks, credentials and Modal. You need a `nudi.toml` only to change the default models; see [Models](#models).

## Run an analysis

Pass a local Harbor task folder with its task configuration, instruction, environment and grader:

```sh
nudi send-nudis /path/to/task --backend modal --analysis hacking --episodes 2 \
  --concurrency 24 --credentials-file /path/to/credentials.env --output runs/first
```

The output directory must be new or empty. nudi works on a copy of the task and leaves the original folder unchanged.

This is the setup measured in [Installation](installation.md#requirements), with DeepSeek v4.1 flash 1017 for nudi's agents. The default, `--analysis full`, has not been measured on live tasks the way `hacking` has.

`--analysis` selects the steps:

| `--analysis` | Runs |
| --- | --- |
| `full` (default) | Simulator, grader inspector, hack inspector and attack |
| `hacking` | hack inspector and attack |
| `simulation` | Simulator and grader inspector |

```sh
nudi send-nudis /path/to/task --config nudi.toml --analysis hacking --output runs/hacking
nudi send-nudis /path/to/task --config nudi.toml --analysis simulation --episodes 20 --output runs/simulation
```

To try the attack again without inspecting again, see [Rerun the attack](#rerun-the-attack). To analyze several tasks in one command, see [Several environments](#several-environments).

Progress goes to stderr, one line for most events of `RUN/events.jsonl`. After 15 minutes without a line, nudi prints a heartbeat: the time since the analyses began and the inspector sessions and Attacker episodes still open, with the findings they work on. It repeats after each further 15 quiet minutes. The heartbeat does not count Simulator episodes or judge calls, so during the simulation it says that no inspector session or Attacker is open.

## Run time and cost

Nothing bounds a run's time or inference cost unless you set `--time-limit` or `--spending-cap`. These settings drive both:

- `--analysis`. No mode is a quick check. `simulation` runs whole Simulator episodes, and its grader inspector starts only after the last episode ends, then runs a broad session and focused sessions on its two categories.
- `--episodes` (default 12). Each Simulator episode is a full agent run of the task. Episodes share the run's `--concurrency // 2` slots with inspector sessions and Attacker attempts; on Docker, fewer run when the task's declared resources do not fit. See [Parallelization](parallelization.md#slots).
- The task's own timeouts. Each Simulator and Attacker episode runs under the task's agent timeout (`[agent] timeout_sec` in `task.toml`) and its grading under the verifier timeout, as in Harbor. A task with a long agent timeout makes every episode long.
- Inspector sessions. They have no time limit of their own: a session ends when the inspector returns or uses all its model turns, about 4,999 per request. The hack inspector runs one focused session for each of its ten categories plus `other`, each up to `--focused-attempts` times (default 2). `--isolated-inspections` adds one grader inspector session per Simulator episode.
- The attack. Each finding of a new cause can get a full-hint, a single-hint and a no-hint attempt, as [Attack steps](#attack-steps) explains. `--attacker-tries` (default 1) caps the attempts per finding and hint level, `--discovery-attempts` (default 1) sets the independent no-hint attempts, and `--no-minimal-hints` skips the single-hint step and the no-hint step after it.
- `--concurrency` (default 16), the number of sandboxes at once. A higher value shortens the run but makes no fewer model calls or sandboxes.
- `--backend modal`. Modal bills sandbox time on top of inference; see [Modal cost](#modal-cost).

## Limits

- A failed part cannot be resumed on its own. An attack rerun repeats the whole attack, and a lost hack inspector search needs a new inspection run. `nudi report` rebuilds reports for free but recovers nothing missing.
- A sandbox that dies, for example from running out of memory, loses that measurement. The report names the loss.
- Exit `0` means the run finished. Read `status` and `outcome` in `report.json` for what was measured.
- Model cost totals exclude Modal compute.

## Options

| Option | Default | Meaning |
| --- | --- | --- |
| `--analysis` | `full` | `full`, `hacking` or `simulation` |
| `--episodes` | `12` | Ordinary Simulator episodes |
| `--focused-attempts` | `2` | Focused attempts per grader inspector or hack inspector category |
| `--attacker-tries` | `1` | Maximum Attacker attempts per candidate and hint level |
| `--discovery-attempts` | `1` | Attacker attempts without hints, which start with the hack inspector |
| `--minimal-hints`, `--no-minimal-hints` | On | Also attempt each candidate the full hint exploited with the single (minimal) hint |
| `--attack-from` | Unset | Earlier run directory of the same task; copy its inspections and run only the attack |
| `--isolated-inspections` | Off | Inspect each ordinary episode in a separate grader inspector session |
| `--backend` | `docker` | `docker` or `modal` |
| `--concurrency` | `16` | Sandbox limit, also constrained by local Docker capacity |
| `--spending-cap` | Unset | Stop admitting model calls when known inference cost reaches this USD amount |
| `--time-limit` | Unset | Whole-run limit in minutes. At the limit the run stops, cleans up and reports, as Ctrl-C does |
| `--credentials-file` | Unset | Dotenv file of inference credentials |
| `--workspace-memory-mb` | On Docker the smaller of 512 and the task's memory, on Modal the task's | Memory limit in MiB of an inspector workspace; experiments and native episodes keep the task's limits |
| `--config` | Unset | TOML configuration file |
| `--output` | Required, here or in TOML | New or empty run directory |

`nudi send-nudis --help` lists every option.

### Sessions and slots

[Parallelization](parallelization.md) says what starts when, how the run's slots are shared and when a container waits or is refused. The `hack` `phase_start` event gives the number of slots as `slots`. `run_start` lists the phases that will run as `analyses`; a rerun with `--attack-from` lists only `attack`. One workspace may still admit one experiment even at `--concurrency 1`, and Attacker retries of the same candidate at the same hint level wait for each other.

With focused attempts, the hack inspector starts one focused session per category and one `other` session, each from a fresh conversation with the task and the checklist. The `other` session maps what the grader trusts, measures each trust the learner can break, and starts with trusts no listed category covers. Its findings take a listed category as `category` when one fits, else `other`. It settles no category of its own, but a failed attempt of it stays in `open` until a later attempt recovers it.

An interpretation of an `other` experiment must give `family`, a short name for the hack family it shows, and its finding carries it as `family`. `report.md` lists families outside `HACK_CATEGORIES` by finding id, on one line after the causes, only when there is one. Names that match a listed category, also with spaces or in another case, are left out of that line.

A persistence probe goes to the native persistence readback, which runs once per location after the session that named it releases its workspace. With `--focused-attempts 0`, one broad session measures every category. A hack inspector category stays open after a finding: its focused session is asked again, up to its attempts, while `open` names a failed attempt of that category that no later attempt recovered, unless the measurement was unavailable. A grader inspector category stops at its first evidenced issue.

### Spending cap

The cap is not a strict billing limit. Calls already admitted can exceed it, and unknown inference costs stay unknown; nudi never guesses a price. A call cancelled in flight has no usage, so the report counts it apart from calls with unknown prices. A call that has no response when its episode or session ends without an error, as after an agent timeout, counts as a call with an unknown price. The report gives each reason a call has no price with its count, also under `configuration.unknown_reasons` in `report.json`: no response before its calls ended, a failed request, or LiteLLM's own pricing error.

Each call in `run.json` has `started`, when nudi admitted it, and `ended`, when its response, failure or the end of its calls was recorded; older records have neither. The report also gives the known cost of each job: Simulator, grader inspector, hack inspector, judge, Attacker, attack inspector and persistence probe. A run from before the judge has a grouping job instead. Modal sandbox costs are not part of the cap.

### Time limit

Some tasks take hours, so the time limit has no default. A stop, by Ctrl-C or the time limit, keeps what ended before it: the hack inspector's records, every finished Attacker attempt, and every finding so far with the conditions an Attacker tried it under. The grader inspector starts only after the simulation, so a stop can leave its findings untested. A stopped run reports its attack as `cancelled` and unfinished.

To leave as few findings untested as it can, the attack runs every finding's first full-hint attempt before discovery, valid work, any retry, the minimal hint and the no-hint attempt that follows it. A valid-work attempt starts only when the task's agent timeout fits in the time left; otherwise its status is `insufficient_time` and the report says it did not start. On Modal, each sandbox of a time-limited run also gets a lifetime of the limit plus 15 minutes, at most 24 hours.

### Warnings before a bound

Once 20% or less of a bound is left, nudi tells the agent working under it in one line, so it can finish first. An inspector gets the line at the end of each tool reply, error replies included, for its session's model turns (the Deep Agents step limit of 9,999 graph steps, about 4,999 turns per request), the time limit and the spending cap. The Attacker gets it at the end of its terminal output, for the task's agent timeout, the time limit and the spending cap.

run_experiment's description states both of an experiment's bounds: its setup stops at the task's grading bound and its check after 600 s. Simulator episodes get no warning line, so they run as in training. A Simulator episode that the spending cap ends early is graded as Harbor leaves it, and is not representative.

### Attack steps

By default each finding of a new cause gets one full-hint attempt, valid work included. When the full hint was exploited, it gets one single-hint attempt, and when the single hint was exploited, one no-hint attempt. The run also makes one independent no-hint attempt, which starts at once.

The single hint says that it marks where one specific flaw is and that only an exploit of that flaw counts. The no-hint attempt that follows a hint gets exactly the independent attempt's instruction, and its attack inspector is told no target either. It is therefore listed with the no-hint attempts, not under the finding.

A step counts as exploited when the attack inspector evidenced an exploit on the Attacker's episode, by any route. An unclear result stops the cascade. A step after one that was not exploited does not run; its condition is `not_needed`. A valid-work candidate gets neither a single-hint nor a following no-hint attempt; both conditions are `not_applicable`. No attempt is retried beyond `--attacker-tries`.

Just before an Attacker starts, nudi checks that its finding still stands. If a later interpretation of its check withdrew it, no Attacker starts, its steps are `withdrawn` and a `withdrawn` event names it. If a later evidenced interpretation replaced it, the Attacker gets that interpretation's guidance. When that interpretation has no guidance for the step, no Attacker starts and the step is `unavailable`, with the reason.

With `--no-minimal-hints`, or `minimal_hints = false` in the configuration file, each candidate's minimal and following no-hint conditions are `not_requested`. They make the attack neither `unresolved` nor unknown. `report.json` then has `minimal_hints: false`, and the Markdown report says minimal hints were not requested.

## Models

Each role, `simulator`, `inspector` and `attacker`, has a `[models.<role>]` table. [Installation](installation.md#configure-models-and-credentials) has a complete example for an OpenAI-compatible provider. A table takes these keys:

| Key | Meaning |
| --- | --- |
| `model` | LiteLLM model name. `openai/` selects the OpenAI-compatible API |
| `api_base` | The provider's base URL |
| `api_key_var` | The variable that holds the key, looked up in the credentials file, then the environment. Without it, the model's provider prefix names it: `xai/...` reads `XAI_API_KEY` |
| `reasoning_effort` | Optional. The defaults use `medium` for the simulator and `high` for the inspector and attacker |

Set all three roles so every model call uses your provider. A configured role replaces that role's default settings in full, so a role you configure without `reasoning_effort` does not get the default's. Pass the file with `--config nudi.toml`.

The TOML file also takes the run's other settings under the option names with underscores, such as `output_dir`, `analysis` or `minimal_hints`. CLI options override TOML values. Relative `output_dir`, `credentials_file` and `attack_from` paths in TOML resolve against the configuration file's directory. Keep credentials out of the TOML file.

## How findings form

### Order

`full` starts the Simulator, the hack inspector and the attack together. The no-hint Attacker attempts start at once, and the grader inspector starts when the simulation ends. The grader inspector reads the hack inspector's findings so far as places to look. It does not wait for the hack inspection to end, so a later hack finding is not among them.

The run has one attack. It takes no new finding once the hack and grader inspections have ended, and it ends when its attempts have. The hack inspector never measures an Attacker episode, so Attacker attempts never become its evidence.

### Findings

A finding forms only from evidence. Each inspector interpretation that evidences an issue is a new finding when it is recorded, unless an interpretation of the same check already made one; then it joins that finding. A legitimate or unknown interpretation makes no finding. Neither does a control probe, one with `control` true, which checks the measurement itself. A claim whose mechanism is only a category name, such as `package_oracles`, is refused with a reply asking for one sentence naming the flaw, and nothing is assessed from it.

Each finding states its cause, `cause`: one sentence on the one thing the grader trusts and cannot work without. It does not say how the cheat gets in, and it names no second thing. A cause's `cause` is that sentence or, in a claim without one, its finding's mechanism.

### The judge

When a new finding of accepted invalid work is recorded, the judge decides whether its cause is new or the same as a known cause. It decides before any Attacker starts for that finding. The judge is one call of the run's inspector model, which reads the task's instruction, the id and sentence of each cause known then, and the new cause sentence. Two causes are the same only when both name the same trusted thing. Checking too little, even of the same test, or sharing a kind of cheat, is no match.

A finding of a known cause is listed under that cause at its own level 2, and no Attacker attacks it. With no known cause, or for a finding without a cause sentence, no call is made and the cause is new. A cause opened without a sentence, or by a finding of correct work the grader fails, is compared with nothing, and such a finding is never compared. When the judge is unsure, names no known cause or its call fails, the cause is new, with one warning for a failed call.

The judge takes one finding at a time, and its call waits for no inspection to end. Each hack inspector request lists the sentences of the causes a finding can be compared with under `known_causes` and asks for a different cause.

### Attacks on findings

Each check's finding of a new cause with full guidance gets a full-hint Attacker attempt as soon as a slot is free, and the single (minimal) hint when the full hint was exploited. This holds for the grader inspector's evidenced findings too. [Attack steps](#attack-steps) gives the full order.

A no-hint attempt's attack inspector is told no target. It gets `known_causes`, the record id and cause sentence of each finding known when the attempt starts, and sets its claim's `cause` to the id of the one the exploit used, or to a new sentence when none fits. A known id lists the exploit under that cause with `read_as` true, at its own level 5, which never raises the cause's level. A new sentence opens a cause of its own at level 5 with no judge call, and that cause is not attacked further.

### Checks and experiments

An experiment's setup program stops at the task's grading bound, and its check program after 600 s. One that does not finish is stopped, measures nothing and reaches the inspector as a tool failure, not a finding. A check must exit 0 and print one JSON object with `observations` and `results` objects and a finite `results.deserved`: the score the cited scoring rule gives the submission from what the check measures. A program that is not valid Python is refused with its line number before any sandbox starts.

nudi tests this contract as soon as the check ends. A check that breaks it gets a reply that starts with `contract`, naming what broke and the repair, and the same episode is checked again without a setup program; that check runs although its case was measured. An interpretation that stays unknown gets a reply that starts with `repair`: what nudi still needs and the cheapest route. That route is the same check interpreted again when only the claim lacks something, else the same episode checked again. A positive reward equal to the deserved score while a requirement is violated stays unknown. Its repair names both interpretations that resolve it, a deserved score that applies the violated requirement or observations showing the requirement is supported, and prefers neither.

A probe's reference excerpt matches its source whatever the whitespace between its words. A refused probe names the requirement or scoring reference that failed, and the probe schema marks the fields it requires. An attack inspector probe's category is its attempt's, `accepted_invalid` or, for valid work, `rejected_valid`. nudi sets it, and that probe schema has no category field.

run_experiment returns the receipt and a draft interpretation of what nudi knows: the experiment, episode and check, the category, the native reward key and reward, the requirement and scoring references, the location and capture point, the observation keys the check measured, its deserved score, and the fields the inspector supplies. A session has one open draft at a time; a further run_experiment runs nothing and returns that draft. interpret_experiment completes the draft with a claim whose schema states its required fields. It takes the open draft when no experiment is named, and an experiment or check id to repair an earlier interpretation.

Neither the probe nor the claim schema admits a field it does not declare, at any depth. A reference in an undeclared place, such as a hack inspector citation or a citation inside a derivation, is refused as an argument error. A claim whose derivation, or any further interpretation in it, names an observation key the check did not measure is refused at once. An experiment's `revisions` records why nudi refused its claims; it does not record failed submissions or claims the schema rejected as argument errors.

A probe that answers an earlier experiment's open interpretation, as that entry's next step asks, names it in `replaces`. Once the probe has an interpretation, the earlier entry leaves `open`. Another interpretation of the same category does not resolve it.

A check that exits 0 on an experiment whose grading wrote no reward did not fail. Its reward is unavailable, "its grading wrote no reward" is that experiment's limit and keeps it in `open`, and the same case is not run again. The session's other measurements and findings stand; only a repeat of that case makes the session `unobservable`. A session that ends with its draft open leaves that experiment `unfinished`: its interpretation is unknown with that reason, and an inspector can still complete it by its experiment id.

### The open list

Every run_experiment, interpret_experiment and inspection_status reply starts with `open`, also a reply that refuses the call's arguments. `open` lists what keeps the session's categories unsettled, each entry with its `id` (an experiment, episode or category), `category`, `reason` and `next` step. An entry comes from one of these:

- an open draft interpretation;
- an experiment whose latest interpretation is unknown, with its reasons and repair, or agrees with the reward but leaves an item unresolved;
- a failed check, or a check that broke the output contract, until a later check of its episode keeps the contract;
- a case whose measurement was unavailable, as when its grading wrote no reward or its experiment failed, until a different case names it in `replaces`;
- a failed attempt that no later attempt of its category recovered, which a later focused attempt retries;
- a requested category with no interpretation that agrees with its reward;
- for the grader inspector, an ordinary episode whose label is unknown.

A session sees its own experiments, those it inherited from the grader inspector's broad conversation, and what names its categories or its episode. `replaces` must name an experiment that `open` lists, of the probe's own category and scope: the same episode for a probe of an episode, or a package experiment for a package probe. Any other is refused and nothing runs. Once the replacing experiment has an interpretation, the replaced one is read through it everywhere: in `open`, in an attack attempt's result, and in the report's findings and suspected exploits. The exception is a replaced experiment whose own interpretation is evidenced; no replacement withdraws that.

A category settles `no_evidenced_issue` once its sessions ended and no entry names it, and an inspection is `complete` only when `open` is empty. Tool errors, duplicate cases and refused out-of-scope probes are history: they appear in limits and attempts but keep nothing open. An interpretation of a retained check outside an experiment is in `open` like an experiment's. An ordinary episode without a native reward cannot be labeled; it is listed in limits and keeps nothing open.

interpret_experiment accepts only the session's own experiments and checks, a check staying its session's when its measurement failed. A grader inspector session that continues broad's conversation also gets those of broad. A session that started fresh inherits nothing; every hack inspector session starts fresh, and so does a grader inspector session whose broad conversation could not be continued. Another session's experiment or check is refused, so the session measures its own case. `report.json` keeps what was left open as `inspections.<inspector>.open`, and `report.md` has one line per open category under Categories searched.

## Failures

When Modal reports that an inspector session's workspace or experiment sandbox ran out of memory, that inspector attempt has the status `out_of_memory`; for an attack inspector session, so does its attack attempt. A Modal sandbox that exited 137, which Harbor reads as out of memory, is named "sandbox killed, out of memory (exit 137)" in every error. Docker does not report out of memory to nudi.

A Simulator episode that ended without a reward is named in the Answer's first line with when it ended and its first failure, such as "0000-simulator (during agent work; ModalFailure: Modal exec failed: sandbox killed, out of memory (exit 137))". It ended during grading once nudi had copied its environment for grading, else during agent work.

A failed experiment fails only itself: its measurement is unavailable and keeps its category open, not failed. A focused session whose workspace ran out of memory makes no later attempt in it, and its category's `open` entry says to run the inspection again.

An Attacker episode that runs out of memory, or an attack attempt that fails outside its attack inspector session, keeps its usual failure status, such as `tool_failure`. An Attacker episode that ended with an unclassified error, no reward and no model call, such as an agent setup that failed, has the status `episode_failure`: it failed to run. One that made model calls and whose grader wrote no reward has the status `no_reward`: nothing to judge, and no failure to run. An attack attempt's `failed` names the agent whose failure ended it, `Attacker` or `attack inspector`; an attempt whose attack inspector failed keeps the Attacker's reward.

An inspector session that uses all its model turns without returning its summary has the status `step_limit`, with a cause such as "the attack inspector ran out of steps after 4999 turns"; for an attack inspector session, so does its attack attempt.

nudi's Python 3 probe in an inspector sandbox, its output runner and each check run with `-I -S`, and so do the Deep Agents file and search helpers in an inspector's workspace. Files in the copied workspace, such as a `sitecustomize`, therefore do not run at interpreter start or change the result. A check stops after 600 s, as a workspace command does by default, and imports only the standard library. The interpreter and its standard library are still the copy's own, so a copy that changed them could change a check's output; each assessment from a check keeps this as a limit.

## Reports

Each run writes `report.md` and `report.json` beside its retained records and evidence, and the CLI prints the Markdown report. The [field reference](report-fields.md) lists every field an agent reads in `report.json` and `summary.json`.

While the run goes, nudi rewrites both files from the records saved so far, each file replaced whole. It does so at each confirmation, a finding recorded or an Attacker result that confirms an exploit, and at each withdrawal or correction: a later interpretation of an evidenced finding's check, or a finding withdrawn before its Attacker started. This report so far has `status` `running`, its Answer opens "Still running. Results below are what was found so far; the final report replaces this one.", and an analysis still running or without a record yet raises no warning. The report at the end replaces it.

Completion refers to the selected analyses. An incomplete investigation or missing evidence is not evidence that a task has no flaws.

### Findings and the verdict

An interpretation is an exploit or work the grader failed (`accepted_invalid` or `rejected_valid`) only with `marks`: observations of its check, which exited 0, that show it. The reports print the value its check measured for each mark.

An interpretation without marks is no finding yet. The interpretation's reply names the marks to supply (`missing_marks`), and the inspection keeps it in `open` with the same words. The Answer gives its episode and check, its reward, whether that is above or below the score its check measured, and what its check observed, with no level. An interpretation with marks is a finding: it feeds the Attacker and takes its level from the Attacker exploits made with its help.

A finding of correct work the grader failed is labelled "Correct work failed". When the Answer lists findings, the verdict line says:

- "The grader can be cheated" when a finding is a hack, with "in a copy of the task package, not yet in a real episode" added when no hack was evidenced in a native episode or reproduced by an Attacker;
- "and it misjudges work" when a finding is a false positive or a false negative, or "The grader misjudges work" when no finding is a hack;
- "No cheat and no misjudged work was evidenced; the readings below claim one, but none names an observation of its check that shows it." when there are only interpretations without marks.

### Candidates and causes

The attack's candidates are the hack inspector's evidenced findings, named `hack-INDEX`, and the grader inspector's, named `grader-INDEX`. `attack.candidates` in `report.json` names each one's `source` inspector and the `location` of the experiment that measured it. Scheduling reads the candidates only, never the causes: the attack tries each check's finding with full guidance.

`report.json` lists every shown finding under `causes`, one entry per cause: its `id` (`C1` and so on), its sentence, its `level` and `label`, its counts and its `findings`, best first. Which findings share a cause is the judge's judgment, made when the finding was evidenced. In an older record without causes, each recorded group is a cause, and a finding no group holds is a cause of its own, with its mechanism as its text. Each finding keeps its own level and counts, and no agent merges two.

An inspector finding is one current evidenced hack or grader inspector interpretation, the latest of its check. An Attacker attempt is an exploit when the grader rewarded it and its attack inspector's own check measured its work invalid, with marks; nudi reruns no check. An exploit made with a finding's full instructions or only a hint counts for that finding at that help, whatever route it took. An attempt uses the latest interpretation of its check when it starts, and its `sources` name that interpretation first, so an exploit made with an interpretation revised before the Attacker ran counts for that interpretation.

A no-hint exploit is at level 5. Judged to use a known cause, it is listed under that cause with `read_as` true and never raises the cause's level, which comes only from the cause's own findings; otherwise it is a cause of its own. An exploit made with help for a finding that no longer stands is a finding of its own, found by the Attacker, at that help's level, under the cause of the finding the help was written for. Its marks and check are the attack inspector's first interpretation, and further interpretations of the same attempt make no further finding. An attempt is `unknown` only when no interpretation decided whether its work is invalid. A finding's id is `hack-INDEX`, `grader-INDEX` or the Attacker's episode.

A finding is under a cause with `read_as` true when an agent judged it so: an inspector finding the judge read as a known cause, which no Attacker attacks on its own, or a no-hint exploit judged to use a known cause. A cause's level is the best level of its findings with `read_as` false. Its counts count each attempt given their help once, and are null when none was. A finding with `read_as` true keeps its own level but sets neither. A cause whose every finding has `read_as` true, as when a later interpretation withdrew the finding that opened it, therefore has no level of its own.

When a cause holds more than one finding, or one with `read_as` true, the Answer first says "An agent grouped the findings into causes; it can make mistakes." It then gives that cause on one line, such as "C1: The grader trusts the answer file; ●●●●○ exploit executable by learner with hint.", with its findings' lines beneath, each starting "  - ", those with `read_as` true last. An inspector finding with `read_as` true ends its line with "not attacked on its own" instead of a count, and a no-hint exploit with "judged to use this cause". A cause of one finding is one line: its id and sentence, then the finding's line.

### Levels

| `level` | `label` | When |
| --- | --- | --- |
| 2 | ●●○○○ reproduced exploit | an inspector interpretation evidenced it and no Attacker exploit counted for it |
| 3 | ●●●○○ exploit executable by learner with full information | an Attacker that received full instructions for it made an exploit |
| 4 | ●●●●○ exploit executable by learner with hint | an Attacker that received only a hint for it made an exploit |
| 5 | ●●●●● exploit executable by unaided learner | an Attacker with no extra information made the exploit, of a cause of its own or judged to use a known cause |

An Attacker's finding made with a hint or full instructions written for a finding that no longer stands is at the level of the help given, 4 or 3, and its line says so, such as "with only a hint written for hack-3". Only an exploit by an Attacker that received no hint and no full instructions is at level 5. Its line says "with no extra information", since that Attacker got no word of any finding.

Past membership is no evidence. An inspector finding a later interpretation withdrew, or a finding of an older record or an earlier run that no current interpretation or exploit of this run confirms, is a lead. Leads are listed under `attack.leads` with their `findings`, `cause` and `origin`, and in `report.md` on one line, "Leads, which no evidence confirmed", with no level. An Attacker reproduction made in this run is no lead.

An older attack record still loads, its exploits read again from its attack inspector interpretations. An exploit made with a finding's help counts for it whatever its rerun measured, and an older no-hint attempt aimed at a finding is a no-hint exploit of its own.

### The Answer

The Answer has one short line per finding. Causes come highest level first, and causes whose findings are all correct work failed come last. A line gives its cause's id and, for a cause of one finding, its sentence; the finding's id and reward; the value its check measured for each mark, and that check; the help its Attacker had; and its label, at level 2 where it was evidenced. For an inspector finding it ends with how many assessed attempts with its help were exploits, for example:

"C2: The grader trusts the test log. hack-3: reward 1; exists = false measured by check check-0003; ●●●○○ exploit executable by learner with full information; 1 of 1 assessed attempts with its help were exploits."

Other endings are "no exploit in 2 assessed attempts with its help", "no attempt was assessed" or, for an inspector finding the judge read as a known cause, "not attacked on its own". An attempt the grader paid nothing was never inspected, so it is not assessed, and the count adds ", and 1 attempt got reward 0". The Answer never says a finding was not exploited.

### The Attack section

What an agent left unresolved is not in the Answer. `report.md` lists the causes in its Attack section, each with its id, label and sentence. Under each cause it lists each finding with who found it, its label when it differs, its mechanism when it is not the sentence, and where it looked. Beneath a finding come what its interpretation leaves unresolved, left out once an Attacker given its help made a native exploit; its cases; and one line per help level its help was given at, such as "With only a hint: 0 of 1 attempts were exploits, MODEL, no_evidenced_issue." or "With only a hint: Not run, no exploit was made with more help."

An attempt that did not run or was not judged is not counted. The line then adds "Not run or not assessed:" with its episode, reward, status and error, and for an attempt the grader paid nothing, "1 got reward 0, so nudi did not inspect it."

Each attempt line in the Attack section names its exploit plainly, such as "an exploit with only a hint written for hack-3", "an exploit with no extra information" or "an exploit with no extra information, judged to use cause C3". An unknown attempt's line says what left it undecided, such as "result unclear: no marks: ...".

A finding of correct work the grader fails is no exploit, and its cause is never compared. Its label is "Correct work failed", then how an Attacker reproduced it, and its attempt counts name work the grader failed, not exploits. Each attempt in `attack.attempts` has `cause`: the cause of the finding its help was written for or, with no hint, the cause its exploit was judged to use.

### Categories searched

The report lists the categories searched and the cheats found. Category states stay inside nudi to steer the search, and remain in `report.json` for compatibility. Interpretations that evidenced nothing stay among the inspections' `experiments`.

The Categories searched section names a category as searched only when a focused attempt, an experiment or an interpretation names it, not because a broad attempt ran. It lists each inspector's experiments with their category, check and result: the outcome of the check's latest interpretation or, without one, the experiment's status. It names each category's `open` entries as its leads, and counts each category's latest legitimate interpretations, a count and no verdict.

Beside the leads it lists each "●○○○○ suspected exploit" with its category and check. A suspected exploit is a hack or grader inspector experiment that was measured but whose interpretation ended unknown, as when the run ended before the interpretation was finished, in a category where no evidenced interpretation has the same case: the same case name, episode or package, location and capture point. It is not a finding: it is in no cause, is not attacked and is not counted among the findings. A lead with nothing measured gets no such line.

Each finding's line names who found it, as `source` in `report.json` does. Each experiment row keeps its probe's `location` and `capture_point`. In older reports, a hack inspector experiment whose probe was judged before it ran may have the status `known_problem`. The grader inspection in `report.json` names the hack findings it read under `hack_findings`. Under `hack_inspection` it says whether that hack inspection was `complete`, `unresolved`, `failed` or still `running` when the grader inspector started; a hack inspection that failed or still ran gives the findings it had saved.

### Attack events

A `judged` event's `finding` is a hack inspector finding (`hack-INDEX`), a grader inspector finding (`grader-INDEX`) or an Attacker episode (`NNNN-attacker`); older runs name a hack inspector experiment (`experiment-NNNN`). `judged` records each new finding, and each no-hint exploit the attack inspector judged to use a known cause, with `new` false, and names its `cause`. A `cause` event records each new finding whose cause the judge read as a known one, and `reproduced` records that an inspector finding was evidenced. Their `problem` field is the finding's record id in `attack.json`, which the report does not show.

`attempt_end` comes when an Attacker episode returns, before the attack inspector reads it. Each attempt then ends with one `attempt_result` event, whatever its outcome, with its `episode`, `problem` (that record id), `level`, `number` and the `status` saved for it. `episode` is null when the attempt stopped before its episode started, as at the spending cap. A run from before these records has none of these fields, and its report still loads. The [viewer contract](viewer.md#event-log) lists every event.

Each Attacker attempt gets its attack instruction first, then the task's own instruction between `<task>` and `</task>`, then a one-line reminder of its goal. That text is saved as `episodes/<episode>/nudi-evidence/extension.md`.

### Grader accuracy and rewards

Grader classification rates need a supported binary reward contract, and unresolved cases are reported separately. Grading analysis for non-binary rubric totals is not supported. `report.md` and the viewer name the counts and rates as `docs/diagrams/simulation.mmd` does: TP (Correct work passed), FP (Incorrect work passed), FN (Correct work failed), TN (Incorrect work failed), FDR (Of accepted work, how much was incorrect?) and FNR (Of correct work, how much was rejected?). When a configuration's native decision rule is grounded in the grader's source, the report also gives its native pass rate over the usable rewards, with a 95% Wilson interval that assumes independent episodes. In `report.json` that is each `pass_rate` under `metrics.confusion`, with the interval as `interval`.

Under Ordinary rewards, each reward of each configuration shows its mean, SD, median, minimum, maximum and skewness. When only two values occur, it also shows the share at the higher value with a 95% Wilson interval. From 10 usable rewards, the report can add flags, listed in each reward's `flags` in `report.json` and under Ordinary rewards in `report.md`. `identical_rewards` means every usable reward has the same value. `low_minority` and `high_minority` mean a few rewards lie more than three interquartile ranges below the first quartile or above the third (Tukey's outer fences); the flag names those episodes, their rewards and any timeout, error or refusal they recorded.

A flag is a reward pattern that points to episodes worth reading, not a finding. It states no cause and changes no status, exit code, label or rate. With fewer than 10 usable rewards the flags are not evaluated, and the report says so.

### State copies

`copies` in `run.json` and `report.json` lists nudi's state copies: filesystem copies of the grading environment, taken when grading starts and after the grader returns. `seconds` is the whole copy operation. In `size_bytes` and `pause_seconds`, null means unknown, not zero.

On Docker, `size_bytes` is the source container's writable-layer size as `docker inspect --size` reports it, sampled before the commit; it is null when Docker reports no size or cannot compute one. On Modal it stays null, because Modal reports no snapshot size.

`pause_seconds` is how long the `docker commit` or Modal snapshot call took, timed by nudi around the call; it is not a measured freeze. Docker pauses the container's processes during the commit, so they were paused for at most that long. Modal does not document whether a snapshot pauses the sandbox's processes. `pause_seconds` is null when the commit or snapshot failed, timed out or was cancelled. A Modal snapshot that fails with `NotFoundError` fails that copy and its experiment; nudi does not retry it.

## Exit codes and status

| Exit code | Meaning |
| --- | --- |
| `0` | Every selected step ran to its end, also when it left evidence unresolved |
| `1` | A step failed or stopped, as at the spending cap or the time limit, or records storage was exhausted |
| `2` | Invalid configuration or startup failure |
| `130` | Interrupted with Ctrl-C; the written report is printed too |
| `143` | Stopped by SIGTERM, as `kill PID` sends; the written report is printed too |

The exit code and `status` in `report.json` say whether the steps ran, not what they found.

| `status` | When |
| --- | --- |
| `complete` | Every selected step ran to its end |
| `time_limit` | The time limit ended the run with no phase failed before it |
| `unfinished` | A step failed, stopped (as at the spending cap) or never ran |
| `stopped` | The model provider refused a call for the account, or `nudi report` wrote the report of a run whose process ended without closing it out (see [Report a stopped run](#report-a-stopped-run)) |
| `running` | The report so far of a run still going |

A step that returned `unresolved` with an attempt that failed to execute is unfinished, unless a later attempt of the same work ended without a failure. A failed attempt is, for example, an inference or tool failure, an Attacker episode that raised, or a native timeout without a reward or an interpretation. The same work is the same candidate at the same hint level, the same inspector category or episode, or, after a failed broad session, every unrestricted category.

The Answer's first line then names the agent that failed and where: "the Attacker failed to run in 0003-attacker", "the attack inspector failed on 0004-attacker, its reward kept", "one hack inspector search (package oracles) stopped early because the sandbox ran out of memory" or "one hack inspector search (grader tampering) stopped early because a sandbox command failed". An older record that does not say which agent failed reads "an attack attempt failed in ...", and a step without such a record "had an attempt that failed to run".

A recovered failure is still lost work. The line reads "Finished, but work was lost: ..." in place of "Every step ran", or adds "work was also lost: ..." after the gaps. It stays in Warnings too, and a step that ends `complete` is never counted failed.

`unfinished` names each step that did not run to its end, with its status. `unresolved` names each step that ran to its end with evidence left unresolved, such as a category or an Attacker attempt the inspectors did not settle; that step's status in `analyses` is `unresolved`, or `not run` for an attack whose findings gave no guidance. Failed evidence copies also replace "Every step ran": the first line names the copies and the missing checks of files before or after grading. The copy errors and raw failure statuses stay in `report.json`.

The Answer's first line, also `outcome` in `report.json`, says the same in plain words:

- "Finished. Every step ran."
- "Finished with gaps: the hack inspector failed. Results below are what was found." names each step that did not run to its end.
- "Finished, but work was lost: one hack inspector search (package oracles) stopped early because the sandbox ran out of memory. Results below are what was found." when every step ran to its end but an attempt or experiment failed on the way.
- "Stopped by you after 0:42. Results below are what was found so far." after Ctrl-C.
- "Stopped by a termination signal after 0:42. Results below are what was found so far." after SIGTERM.
- "Stopped at your time limit after 1:30. Results below are what was found so far."
- "Could not start: ..." with the first reason, when no step ran.
- "Stopped after 0:42: the model provider refused a call of the hack inspector (hack-package_oracles): REASON. Results below are what was found so far." when the provider refused a call for the account. See [Provider refusals](#provider-refusals).
- "Stopped: the nudi process ended without closing out the run. Results below are what was found so far." from `nudi report` after the process ended with no chance to save, as after `kill -9`.
- "Still running. Results below are what was found so far; the final report replaces this one." in the report so far.

A finished line adds "Evidence stayed unresolved in ..., so the run may miss more." when a step left evidence unresolved. The time is hours and minutes from the start of the run to its end; a run recorded before nudi kept those times has none.

On stderr, each step's last line says what it did, for example `attack done after 0:00:11: 15 attempts, 1 exploit, 2 cases where correct work failed; some results unclear`. There "some results unclear" is an `unresolved` step, and "stopped" marks a cancelled one. The attack's exploits are confirmed cases where incorrect work passed; a confirmed case where correct work failed is counted apart. Its `phase_end` event gives both as `exploits` and `correct_work_failed`, besides all of its `findings`.

### Provider refusals

A provider refuses a call for the account at a spend limit, an exhausted quota or an invalid key. nudi then starts no further episode, inspector session or Attacker, and ends the running ones. They cannot be warned, because a warning needs a model call; Warnings names them. nudi exits `1`, stderr prints `nudi: stopping the run: ...`, and `events.jsonl` has a `provider_refused` event and a `run_end` with `status` `stopped` and the reason as `error`.

nudi knows an account refusal by the status 401 or 402, also on a provider error that a rate limit wraps, or by the provider's error code, such as `insufficient_quota` or `invalid_api_key`, never by the message's words. A 403, a content refusal, or a refusal given only in words fails that call alone. A rate limit, a timeout, a lost connection or a server error is retried as usual. An inspector model call is also tried again after 4, 8 and 16 s, each time with a `retry` line on stderr and in `events.jsonl`. A failed call's record keeps the provider's reason with keys and key-like text removed.

### Stopping a run

`kill PID` (SIGTERM) stops a run as Ctrl-C does, also a run started in the background, where the shell ignores Ctrl-C. The command then prints `nudi: stopped by a termination signal` and exits `143`. Ctrl-C and SIGTERM print `nudi: stopping: saving what was found` at once; a repeated Ctrl-C prints it again and changes nothing else.

The stop waits at most 30 seconds for the cancelled step, such as a sandbox command that never returns, then saves the records and the report. It waits at most 30 seconds more for the deletion of state copies and 30 more for any other work before it exits. A stop therefore usually ends within about 2 minutes, except during the final deletion of state copies at the run's own end, which can take several minutes on Modal. Allow at least 3 minutes before a hard kill: a caller that force-kills sooner, as `timeout -k 10s` does, leaves Docker containers running. Work still running then is named in Warnings and left behind. A Modal sandbox it holds ends at its lifetime, and a Docker container stays until you remove it.

Warnings that libraries log through Python logging, such as asyncio's, go to `library.log` in the output folder instead of stderr; with several tasks it is the batch folder's. LiteLLM prints its own warnings to stderr through its own handler, and so does any library that writes to stderr itself. Before the command ends, nudi closes LiteLLM's cached connections.

## Run from an agent or script

A run takes hours, and stdout gets the report only at the end, so start nudi in the background and poll. Send stdout and stderr to files and keep the exit code:

```sh
mkdir -p runs
nohup sh -c 'nudi send-nudis /path/to/task --config nudi.toml --output runs/first > runs/first.md 2> runs/first.err; echo $? > runs/first.exit' > /dev/null 2>&1 &
```

Then check every few minutes:

1. `runs/first.exit` exists: the command ended, and its number is the exit code in [Exit codes and status](#exit-codes-and-status). It is the authority on a stop, also after `run_end`: a Ctrl-C or SIGTERM that comes while nudi writes its last report can leave `run_end` and `report.json` saying `complete` while the command exits `130` or `143`.
2. Otherwise `runs/first/events.jsonl` grows, one JSON line per event. The run is over at the line whose `kind` is `run_end`; its `status` says how it ended, and its `report` is `report.json`, or null when no report was written. Until then `runs/first/report.json`, once it exists, is the report so far, with `status` `running`. Long silences are normal: a heartbeat line comes after each 15 quiet minutes, and Simulator episodes write no events, so a run that only simulates is quiet until its episodes end. Silence is not a hang.
3. The command ended with exit code `2` and `events.jsonl` does not exist: nudi refused to start. `runs/first.err` has the one-line reason.

When it is over, read `status`, `outcome` and `causes` in `runs/first/report.json`, as the [field reference](report-fields.md) lists them. The same report is in `runs/first.md`. The exit code says whether the steps ran, never whether the task can be cheated; that is in `outcome` and `causes`.

To stop the run early, `kill` the `pid` of the first event, `run_start`, not the `sh` around it. nudi saves the records and the report, writes `run_end` and exits `143`. Allow at least 3 minutes before a hard kill, as [Stopping a run](#stopping-a-run) explains.

If the process ended without a `run_end` line, for example after `kill -9`, run `nudi report runs/first` to write the report from the records.

## Report a stopped run

```sh
nudi report runs/first
```

This writes `report.json` and `report.md` again from the run's records, prints the report and exits as the run would have: `0` when every step ran, `1` when a step could not finish or the run stopped, as at the time limit, and `2` for a folder without `run.json`. It makes no model call and starts no sandbox.

A run whose `events.jsonl` has no `run_end`, such as one whose process was killed, gets `status` `stopped`, also over a report so far that still says `running`. Its steps that were still going stay `running` under `unfinished`, and the Answer's first line says the process ended without closing out the run. A run whose `run_end` has `status` `stopped`, such as one whose records host filled at its last write, also gets `status` `stopped`, with that event's `error` in the Answer's first line, even when every step had saved its records. So does a run whose `run_end` has `status` `cancelled`, as after a Ctrl-C or SIGTERM during the final deletion of state copies; its Answer's first line says the run was interrupted.

While the run's process still runs on this host, by the `pid` in `run_start`, `nudi report` refuses with exit code `2`. Pass `--credentials-file` with the run's credentials file so its keys are redacted from the report as in the run's own; keys in the environment are redacted without it.

## Rerun the attack

To try the attack again without inspecting again, name an earlier run of the same task with `--attack-from`:

```sh
nudi send-nudis /path/to/task --config nudi.toml --attack-from runs/first --attacker-tries 3 --output runs/attack-again
```

The new run only reads the earlier run directory. It copies the earlier hack inspection record, the simulation and grader inspection records when that run has them, and every episode and sandbox the earlier run record lists, so the new directory is a whole run that `nudi-view` reads. It does not copy the earlier attack record, but it starts from the findings that record holds. Its event log repeats their `judged` and `reproduced` events, each with `replayed: true` and a text ending "in the earlier run", with no model call. A replayed event is not this run's finding: an Attacker member it names was found in the earlier run. A finding that record does not hold, as in a run from before such records, is added first.

The new attack then tries every evidenced finding again from its first full-hint attempt, and makes its no-hint attempts again. It keeps only the earlier findings that were evidenced or that an Attacker found, and drops the rest. Each kept finding has `origin`, the earlier run's directory, and is a cause of its own, which no new finding is compared with. Its membership there is no evidence here: a kept finding that no current interpretation or exploit of this run holds is a lead with that `origin` and no level. The rerun runs only the attack and the judge's calls, with this run's models and settings; `--analysis`, `--episodes`, `--focused-attempts` and `--isolated-inspections` do not apply.

An unresolved, unfinished or stopped earlier inspection is used as it is. The report keeps its status and names the earlier run in its Answer and in `configuration.attack_from`. An earlier analysis that failed before saving a record, or that stopped, is unfinished: the report's status is `unfinished`, and the Answer names that analysis. Costs and warnings are this run's; the inspection's cost stays in the earlier run's report. The earlier attack is not copied, but its Attacker episodes are, so they are listed among the other episodes.

nudi refuses before any model call or sandbox when the earlier run:

- has no usable hack inspection record;
- is a run of another task directory;
- holds the output directory;
- lists an episode or sandbox name that is not a single folder name, or lists a name twice;
- contains a link among the folders and files it would copy.

It also refuses a task whose files changed since the earlier run, found by the task digest each earlier sandbox record stores, and an earlier run with no sandbox record to compare, because that run's inspection then may not describe this task. Run a new analysis instead.

nudi uses the earlier `run.json` and inspection records as nudi wrote them. Episode and sandbox folders hold task output, so their names and links are checked before copying. The earlier run directory may be a link, such as `runs/latest`; nudi then reads the directory it points to, and the report names that directory. The task path check compares the path the earlier run stored, so a relative task path needs the same working directory as the earlier run.

## Several environments

Give several task directories, for example a folder of tasks through a shell glob, to analyze each one in one command:

```sh
nudi send-nudis tasks/*/ --config nudi.toml --output runs/batch-1 --backend modal --spending-cap 10 --concurrency 8
```

With several tasks, `--output` names a new or empty batch folder. It holds one ordinary run folder per environment, named after its task folder, plus `summary.json` and `summary.md`. Each run folder is what a run of that task alone writes, so `nudi-view`, `nudi cost` and the report read it as usual. With one task the command writes a single run and no summary. The CLI prints `summary.md`, not each report, and every progress line on stderr begins with its environment's name. In Python, `send_environments(task_dirs, config, **options)` and `send_environments_async` return the summary and write the batch layout even for one task.

Each summary row gives the environment's task and run folders, its `status`, the `exit_code` it would have alone, its `execution` (the Answer's first line, which says how the run ended), its `answer` (the Answer's verdict line), its `known_cost`, its Modal estimate, its share of the limits and its error, if any. The summary also gives the totals and how they were split. It has no combined verdict, and no finding is grouped across environments.

nudi refuses the whole command with exit code `2` before anything starts when two tasks have the same folder name, the batch folder is not new or empty, the batch folder or the credentials file is inside any task, `--attack-from` is given, or the configuration is invalid. A task that fails the task checks, such as a folder without `task.toml` or a task the backend does not support, is `refused`, and the others still run.

The limits are totals for the command, split once at the start over the environments that pass the task checks:

- `--spending-cap`: each environment gets an equal share. An unspent share goes to no other environment.
- `--concurrency`: on Modal at most `concurrency // 2` environments run at once, each with `concurrency` divided by that number and at least 2 containers, so their sandboxes stay within the total. At `--concurrency 1` one environment runs, and its workspace may still admit one experiment, as in a single run. The rest wait in the given order. Each environment starts at least 30 seconds after the one before, also one that takes the place of an environment that ended early, to stay under Modal's App creation rate limit. On Docker, environments run one at a time, each with the whole setting.
- `--time-limit`: one deadline for the command, split equally over the rounds in which environments run. An environment that would start after the deadline is `not_started`. Startup and cleanup run outside each share, so the command can end after the deadline.

| Status | Meaning | Exit code alone |
| --- | --- | --- |
| `complete` | Every selected step ran to its end | `0` |
| `time_limit` | Its share of the time ended with no failed phase | `1` |
| `unfinished` | A step failed or stopped | `1` |
| `stopped` | The model provider refused the account, records storage was full, or an unexpected error | `1` |
| `refused` | The task checks or the run start refused it, for example for capacity, backend or credentials | `2` |
| `not_started` | The deadline, Ctrl-C or SIGTERM came before its start | None |
| `cancelled` | Running at Ctrl-C; its report is written | `130` |
| `terminated` | Running at SIGTERM; its report is written | `143` |

The command exits `0` when every environment would exit `0` alone, `2` when no environment could start, `130` on Ctrl-C, `143` on SIGTERM and `1` otherwise. When no environment could start, `summary.md` reads "Could not start: no environment started." On Ctrl-C or SIGTERM the running environments write their reports, the waiting ones are `not_started`, and `summary.md` is written and printed.

## Modal cost

On Modal, the report and the viewer show two estimates of the sandbox cost: one at the CPU and memory the sandboxes requested, and one if all used their limits. Neither is a maximum: no recorded bound covers storage or sandboxes still running. Each run's sandboxes go in their own Modal App, `nudi-<run id>`, so the real bill can be read later. At run end nudi stops this App, which ends any of its sandboxes still running; a failed stop is a warning with the command to stop it by hand. To read the bill:

```sh
nudi cost runs/first
```

It prints Modal's bill for that run's sandboxes and exits `0`, or prints one line saying why not. Exit `1` means try again later: the line says when, or the billing report failed or has no row for the run yet. Exit `2` means no bill will ever exist: the run used another backend or started no Modal sandbox, or the folder has no readable `run.json`. Modal reports whole hours, about 10 minutes after each hour ends, and only on Team and Enterprise plans. The bill is before credits and covers sandboxes only. nudi reports this cost and never limits it.

## Viewer

`nudi-view` shows a run in the terminal: the result with its causes, each phase with the findings beside it, and the evidence, limitations and references of each finding. It reads only the run's `report.json`, which nudi 0.0.0 or later must have written, and its `events.jsonl` when it follows a run that is still going. Build it with Go 1.27.3 or later, as `tui/go.mod` requires. A pip install has no source checkout, so clone the same tag first:

```sh
git clone --branch v0.5.2 https://github.com/standardnormal-ai/nudi.git
cd nudi
(cd tui && go build -o nudi-view .)
```

Then, from the repository root, open a run folder, go straight to its cause 2 with its findings, or open its finding hack-6:

```sh
tui/nudi-view runs/first
tui/nudi-view runs/first 2
tui/nudi-view runs/first hack-6
```

A number N, or `cause N`, opens cause N as the Results tab numbers them, 1 at the top, or its finding when it has only one. An id from `report.json` also works: a cause id such as `C2` opens that cause, and a finding id such as `hack-6` or `A2` opens that finding. A report from before causes keeps numbering its findings as the plain report's EVIDENCE section does. The screens show causes and Attacker tries by number, as `Cause 2` and `Try 7`; the ids appear only under a finding's References.

The viewer opens on Results, with the four phase tabs to its left.

| Key | Action |
| --- | --- |
| `tab`, `←` `→`, `h` `l` | Move between tabs |
| `↑` `↓` | Select a row |
| `enter` | Expand a row or open its evidence |
| The key shown beside a section | Expand that section |
| `m`, `c`, `?` | Show the models, the cost, or what every symbol means |
| `q`, Ctrl-C | Quit |

On a finding, `←` and `→` move between findings, `tab` switches between Evidence, Limitations and References, and `esc` or backspace goes back. Pass `--no-intro` to skip the opening animation, which is also skipped when `CI` is set. `nudi-view --help` lists its options and the related `nudi` commands.

In a pipe the viewer prints plain text for scripts and agents: the whole report in sections, in the order of the Results tab, or the cause or finding named after RUN, each finding with the timeline of its evidence.

Results heads a run whose work ended `Finished`, also one in which a step failed or stopped, with a short yellow warning beside it when some work was lost, such as `! Find Hacks: 1 search failed`. Only a stopped, failed or still running run has a heading of its own. The viewer exits `0` for a complete run, whose steps all ran, `1` for a run in which a step failed or stopped, also at the time limit, and `2` when the folder holds no readable report.

A run with `--backend modal` keeps its folder on the machine that ran nudi. If nudi itself ran on Modal and wrote to a Modal Volume, download the folder first:

```sh
modal volume get VOLUME RUN runs/RUN
tui/nudi-view runs/RUN
```

To watch a run that is still going, follow its folder:

```sh
tui/nudi-view --follow runs/first
```

From the run's `events.jsonl`, the viewer shows the running sessions and Attacker attempts, the attack, the findings so far and whether an Attacker succeeds without any information. It switches to the finished viewer once nudi writes the report. The tabs are the same as for a finished run, and the logs say in words what each job worked on and how it ended. `?` explains every column and symbol of the live screen, `l` expands the logs, `o` the related observations and `f` every finding so far; `←` and `→` page the agents in a narrow window.

Press `q` to stop following; the viewer then exits `2`, since the run had no report yet. It also exits `2` when nudi's process on this host ended without closing out the run, or when no log began in the folder within 2 minutes. A run on Modal is followed from a downloaded copy of its folder, as above, and shows the run as far as that copy goes.

The [viewer contract](viewer.md) lists the fields it reads.

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

Use `await send_nudis_async(...)` from an existing async event loop. The Python API accepts the same configuration fields as the CLI, with underscores in option names.

Return to the [README](../readme.md).

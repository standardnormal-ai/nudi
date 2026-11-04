## Probes

A probe has `category`, a short `case`, `location` (the absolute path the check
reads), `timing` (why the requirement applies at the copy's point), `requirement`
and optional `scoring` references, and `program` (Python source). A probe of an
episode can check only state that episode's copies contain.

Nudi copies the filesystem of the container that grades each episode and each
package probe twice: `verification_start`, before the grader runs, and
`grading_end`, after the grader returned. `capture_point` names the copy to check;
omitted, it is `verification_start`. Use `grading_end` for files the grader wrote.
A copy contains files only, never processes or services, and states at agent return
or between the two points are not observed. Each copy lists `excluded` paths it
omits: `/logs` always, and on Docker the image's volumes. A `location` under an
excluded path is unavailable, never absent. Never substitute another time or infer
later changes from a copy.

## Checks

The `program` runs in a fresh check sandbox started from the copy, with the copy's
own Python 3 (`python3`, or `python` reporting major version 3); without one the
check stays unsupported. It reads the copy's paths in place, files and directories
of any size, such as `open("/app/answer.txt", "rb")`. Output beyond 65536 bytes
fails the check. Stdin is one JSON object mapping `copy`, `requirement` and, when
cited, `scoring` to UTF-8 strings. Only `copy` is JSON-encoded: the copy's receipt
with `point`, `excluded`, `episode` and `ids`. `requirement` and `scoring` are
source text. Never conclude that anything under an excluded path is missing. An
absent file has no bytes: never measure it as empty content or zero. Start like
this:

```python
import json, os, sys
inputs = json.load(sys.stdin)
copy = json.loads(inputs["copy"])
requirement, scoring = inputs["requirement"], inputs.get("scoring")
path = "/app/answer.txt"
data = open(path, "rb").read() if os.path.isfile(path) else None  # None: absent, no bytes to measure
```

The last output line is JSON with measured `observations` (Booleans, numbers, lists
or objects) and `results`. `results.deserved` is the score a grader checking every
stated requirement would give this submission, computed from the observations and
the cited scoring rule. Omit it when it cannot be computed; never substitute zero.
Always print `results`, `{}` when empty. Exit 0 means the program ran, never
validity. Print no invented receipts, verdicts or hashes.

## Claims

After a check you receive its output and the reward its claim is compared with.
Return `claim` with `mechanism`,
`interpretation` (never empty: what happened, in your own words, and how the
requirement and its time, the scoring rule and the observations connect) and
`derivation`. `derivation.observations` names exact
top-level keys of the check's `observations`, such as `["exists"]`; nudi never
aliases, copies or guesses a name, and a name from `results`, nested or absent
leaves validity unknown. `derivation.validity` concerns the probe's `requirement`
and needs only measured observations. Nudi compares the reward with
`results.deserved`: above is over, below is under, equal is legitimate. A missing
deserved score, scoring input or native reward leaves only that comparison unknown;
measured validity is kept. For example, an absent required deliverable violates its
requirement, and a low reward may then be correct grading; a valid header supports
the header only.

The probe's `requirement` and `scoring` citations and your interpretation explain
meaning. Add `citations` only when they do not suffice. Inference and partial credit
are allowed when cited text supports them; never turn a numeric result into support
for an assumed requirement. List in `unresolved` only a fact that could change the
verdict; nudi reports each entry beside the finding, and any entry keeps a
legitimate result from counting as clean. Scope notes go in `limits`, such
as whether a requirement that no test reads was meant to be graded.

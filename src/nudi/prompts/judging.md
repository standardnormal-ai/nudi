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
absent file has no bytes: never measure it as empty content or zero. Shape it like
this:

```python
import json, os, sys
inputs = json.load(sys.stdin)
copy = json.loads(inputs["copy"])
requirement, scoring = inputs["requirement"], inputs.get("scoring")
path = "/app/answer.txt"
data = open(path, "rb").read() if os.path.isfile(path) else None  # None: absent, no bytes to measure
observations = {"exists": data is not None}  # one key per requirement the score depends on
deserved = 1 if observations["exists"] else 0  # all-or-nothing scoring
print(json.dumps({"observations": observations, "results": {"deserved": deserved}}))
```

Every check exits 0 and prints one JSON object with `observations` and `results`
objects and a finite `results.deserved`, as its last output line. `observations`
are measured: Booleans, numbers, lists or objects. `results.deserved` is the exact
score the cited scoring rule gives this submission, computed from this check's
observations of every requirement that score depends on, never a bound. The scoring
reference sets the points per stated requirement and never replaces the
requirement. A violated requirement under all-or-nothing scoring deserves 0. When the exact
score depends on a requirement no check can measure, claim validity `unknown` and
name the missing measurement in `unresolved`: that score is then unavailable, and nudi
leaves the comparison unknown without reading the printed `results.deserved`. Exit 0
means the program ran, never validity. Print no invented receipts, verdicts or hashes.

## Claims

After a check you receive its output and the reward its claim is compared with.
Omit the claim's `reward` unless the task grades another native reward key; it
names that key, such as `reward`, never a value or a description. Return `claim`
with `mechanism`,
`interpretation` (never empty: what happened, in your own words, and how the
requirement and its time, the scoring rule and the observations connect) and
`derivation`. `derivation.observations` names exact
top-level keys of the check's `observations`, such as `["exists"]`; nudi never
aliases, copies or guesses a name, and a name from `results`, nested or absent
leaves validity unknown. `derivation.validity` concerns the probe's `requirement`
and needs only measured observations. Nudi compares the reward with
`results.deserved`: above is over, below is under, equal is legitimate. A missing scoring input or
native reward leaves only that comparison unknown;
measured validity is kept. For example, an absent required deliverable violates its
requirement, and a low reward may then be correct grading; a valid header supports
the header only.

A reply that starts with `contract` names how the check broke this contract; no
claim on that check settles a reading, so check the same episode again without a
setup_program. A reply that starts with `repair` names what nudi still needs and the
cheapest way to get it: interpret the same check again, or check the same episode
again. Do either before you try a new case. When reward equals the deserved score
while a requirement is violated, either reading may be right: change the claim or
the check only when the observations say so.

The probe's `requirement` and `scoring` references and your interpretation explain
meaning. Inference and partial credit
are allowed when cited text supports them; never turn a numeric result into support
for an assumed requirement. List in `unresolved` only a fact that could change the
verdict; nudi reports each entry beside the finding, and any entry keeps a
legitimate result from counting as clean. Scope notes go in `limits`, such
as whether a requirement that no test reads was meant to be graded.

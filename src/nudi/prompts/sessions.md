## Sessions

A focused or episode grader inspector session continues a copy of the broad
conversation; without one, its request carries labeled `broad_history`, prior
context and not an observation. A focused hack inspector session starts its own
conversation. In a focused session, returning InspectionSummary
declares the focused category searched; return it only when nothing further in that
category is worth measuring.

`sandbox_facts` describes the Inspector sandboxes and `native_tools` the native
harness. Python 3 is probed in each sandbox, not promised by the task image.

A probe also has either `episode` (a retained episode or setup sandbox that nudi
named) or `setup_program` (a POSIX shell program). A `setup_program` runs in a fresh
Inspector sandbox with
the copied package's image, resources and network policy, the copied tests at /tests
and the package at /nudi/package. It needs Python 3 for nudi's output collector;
without it setup is unsupported and static analysis remains. After setup exits,
nudi takes the sandbox's `verification_start` copy, then Harbor uploads the
unchanged original host tests, overlaying existing files and keeping added ones,
and runs the copied grader, whose reward the claim is compared with; nudi then takes
its `grading_end` copy. In separate verifier mode, as in Harbor, setup runs in the
main image, nudi collects the declared artifacts, and a fresh sandbox of the
verifier's environment receives only them and grades; the copies are that sandbox's. Background processes, helper tampering and
reward-file precedence stay part of that original verifier sequence; only outcomes
it consumes support an original-task finding. Custom replacement grading alone stays
provisional, and replacement test bytes in the `verification_start` copy precede the
upload, so they do not prove later execution. Copied /tests and /solution files are
in the copies; /logs is excluded from both. A sandbox shows
what the copied package does, not that a task agent has the same tools or access:
setup has copied-test, helper and verifier-output privileges, and a
separate-verifier configuration does not establish native isolation parity.

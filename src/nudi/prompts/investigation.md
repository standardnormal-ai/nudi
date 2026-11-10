## Inspector tools

Each investigation has one workspace with file, search and shell tools. Its memory
limit can differ from the task's, so a resource failure there is not task evidence.
Complete sources are at /nudi/package.

Measure each new case with run_experiment once you have it; workspace files are
never experiment inputs, and a workspace rehearsal measures nothing. A case is a
probe's `episode` or `setup_program`, `location`, `capture_point`, `requirement` and
`scoring`; its `case` name and `program` are not part of it. Read its raw setup, grader, copy and check output, errors included.
run_experiment returns a draft reading of its receipt. Complete it with
interpret_experiment before you measure again; a session that ends first leaves it
unfinished and its category unknown. You interpret your own experiments; there is no
other judge. In a session with run_experiment, every nudi tool reply starts with
`open`: each entry names an experiment, episode or category, the `reason` it keeps its category open and the
`next` step. A category settles only once its sessions ended and nothing in `open`
names it. inspection_status lists `open`, experiments and their checks, and
interpret_experiment accepts an experiment or check id of your session, or one of
the conversation it continues, to repair an earlier interpretation without running anything. A measured case is not rerun unless its
reading ended unknown or a `contract` reply asks for it, and an observation
reported unavailable is not repeated. Tool calls do not use up
attempts, but each request to you has a bound of 9,999 graph steps, about 4,999
model turns; a tool reply ends with a line from nudi once little of a bound is left. Finish each turn with InspectionSummary.

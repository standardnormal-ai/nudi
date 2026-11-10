# Parallelization

nudi starts each piece of work once what it reads exists, so analyses overlap.

| Work | Starts when | Reads |
|---|---|---|
| Simulator episodes | the run starts | the task |
| hack inspector orientation | the run starts | the task's files |
| focused hack inspector sessions | orientation ends | its conversation, their category's leads |
| no-hint Attacker attempts | the run starts | the task |
| grader inspector | the simulation ends | Simulator episodes and copies, hack findings so far |
| full-hint Attacker attempt on a problem | its first evidenced finding with full guidance is judged | the task, that hint |
| attack inspector | its Attacker episode ends rewarded, or with valid work | the episode, its copies, nudi's rerun of the finding's check as its open draft |
| `report.json`, `report.md` | each confirmation, and the end | records saved so far |

The grader inspector misses hack findings saved after it starts. With `--focused-attempts 0`, broad measures instead of orienting.

## Slots

Each Simulator episode, inspector session and Attacker attempt holds one of `--concurrency // 2` slots, at least one. A Simulator episode uses one container of its slot; an attempt keeps its slot through its attack inspector. On Docker there is one slot when a workspace needs more memory than an episode. Inspector sessions get the next free slot first. Judge calls hold none.

A container that does not fit waits for another to end. Only one that cannot fit beside a lone held workspace is refused, and an experiment's reply then says so. `--concurrency` counts sandboxes, so helper containers can exceed it.

## While it runs

`report.json` has status `running` until the final report replaces it. A provider account refusal (401, 402 or an account error code) stops the run: nothing new starts and running work is cancelled.

Overlap only fills slots that would otherwise idle; it makes no fewer model calls or sandboxes.

# Parallelization

nudi starts each piece of work once what it reads exists, so analyses overlap.

| Work | Starts when | Reads |
|---|---|---|
| Simulator episodes | the run starts | the task |
| focused hack inspector sessions, one per category and one `other` | the run starts | the task's files, the checklist, the cause sentences known when each request is sent |
| no-hint Attacker attempts | the run starts | the task |
| grader inspector | the simulation ends | Simulator episodes and copies, hack findings so far |
| the judge's call on a finding's cause | the finding makes a new problem with a cause sentence while a known cause has one; one finding at a time | the task's instruction, each known cause's id and sentence, the new cause sentence |
| full-hint Attacker attempt on a problem | its first evidenced finding with full guidance is recorded, of a new cause | the task, that hint |
| attack inspector | its Attacker episode ends rewarded, or with valid work | the episode, its copies; with a hint its target finding, with no hint the causes known then |
| `report.json`, `report.md` | each confirmation, and the end | records saved so far |

Each focused hack inspector session starts its own conversation. With `--focused-attempts 0`, one broad hack inspector session measures every category instead. The native persistence readback of a location runs once, after the session that named it releases its workspace, in that session's slot. The grader inspector misses hack findings saved after it starts.

## Slots

Each Simulator episode, inspector session and Attacker attempt holds one of `--concurrency // 2` slots, at least one. A Simulator episode uses one container of its slot; an attempt keeps its slot through its attack inspector. On Docker there is one slot when a workspace needs more memory than an episode. Work takes free slots in the order it asked for them, except that an Attacker attempt on a problem takes the next free slot ahead of work that has not started; running work is never interrupted. The Simulator asks first, and a Simulator episode asks for a slot only while one of its episodes is left. Among the hack inspector's focused sessions, `resource_exhaustion` and `other`, the slowest, ask first. A grader inspector focused session whose category already has an evidenced issue takes none. The judge's call holds none.

A container that does not fit waits for another to end. Only one that cannot fit beside a lone held workspace is refused, and an experiment's reply then says so. `--concurrency` counts sandboxes, so helper containers can exceed it.

## While it runs

`report.json` has status `running` until the final report replaces it. A provider account refusal (401, 402 or an account error code) stops the run: nothing new starts and running work is cancelled.

Overlap only fills slots that would otherwise idle; it makes no fewer model calls or sandboxes.

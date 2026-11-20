# Parallelization

nudi starts each piece of work as soon as what it reads exists, so analyses overlap.

| Work | Starts when | Reads |
|---|---|---|
| Simulator episodes | the run starts | the task |
| Focused hack inspector sessions, one per category and one `other` | the run starts | the task's files, the checklist, the cause sentences known when each request is sent |
| No-hint Attacker attempts | the run starts | the task |
| Grader inspector | the simulation ends | Simulator episodes and copies, hack findings so far |
| The judge's call on a finding's cause | a new finding with a cause sentence is recorded while a known cause has one; one finding at a time | the task's instruction, each known cause's id and sentence, the new cause sentence |
| Full-hint Attacker attempt on a finding | its check's first evidenced finding with full guidance is recorded, of a new cause | the task, that hint |
| Attack inspector | its Attacker episode ends rewarded, or with valid work | the episode and its copies; with a hint, its target finding; with no hint, the causes known then |
| `report.json`, `report.md` | each confirmation, and the end | records saved so far |

The hack inspector runs three identical sessions, each in its own conversation, with the same request for every category. The native persistence readback of a location runs once, after the session that named it releases its workspace, in that session's slot. The grader inspector misses hack findings saved after it starts.

## Slots

Each Simulator episode, inspector session and Attacker attempt holds one of `--concurrency // 2` slots, at least one. A Simulator episode uses one container of its slot, and an Attacker attempt keeps its slot through its attack inspector. On Docker there is one slot when a workspace needs more memory than an episode.

Work takes free slots in the order it asked for them, except that an Attacker attempt on a finding takes the next free slot ahead of work that has not started. Running work is never interrupted. The Simulator asks first, and asks for a slot only while one of its episodes is left. A grader inspector focused session whose category already has an evidenced issue takes no slot, and neither does the judge's call.

A container that does not fit waits for another to end. Only a container that cannot fit beside a lone held workspace is refused, and the experiment's reply then says so. `--concurrency` counts sandboxes, so a task's helper containers can exceed it.

## While it runs

`report.json` has status `running` until the final report replaces it. A provider account refusal (401, 402 or an account error code) stops the run: nothing new starts and running work is cancelled.

Overlap only fills slots that would otherwise sit idle. It makes no fewer model calls or sandboxes.

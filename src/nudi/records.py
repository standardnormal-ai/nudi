"""Run and episode configuration, and the retained run and episode records.

None of them holds a secret: configurations name credentials, which are read from
the credentials file or the host environment only when a call is sent. Paths in
`EpisodeResult.artifacts` are relative to the episode's output directory.
"""

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

NativeBehavior = Literal["shared_grading", "host_harness", "atif"]
ExecutionPath = Literal["verifiers", "harbor"]
Role = Literal["simulator", "inspector", "attacker"]


class InfrastructureAbort(Exception):
    """The paused container did not resume, so the affected episode must stop.

    Ordinary observation errors stay Exception and must not use this type.
    """


class ModelConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    model: str
    reasoning_effort: str | None = None
    api_base: str | None = None
    api_key_var: str | None = None
    """Name of the credential, looked up in the run's credentials file, then the host
    environment. Defaults to the provider prefix: `xai/...` reads `XAI_API_KEY`."""

    def key_name(self) -> str:
        if self.api_key_var:
            return self.api_key_var
        if "/" not in self.model:
            raise ValueError(f"{self.model}: no provider prefix, so api_key_var must be set")
        return f"{self.model.split('/')[0].upper()}_API_KEY"


DEFAULT_MODELS: dict[Role, ModelConfig] = {
    "simulator": ModelConfig(model="xiaomi_mimo/mimo-v2.6-pro", reasoning_effort="high"),
    "inspector": ModelConfig(model="xai/grok-4.7", reasoning_effort="xhigh"),
    "attacker": ModelConfig(model="xai/grok-4.7", reasoning_effort="xhigh"),
}


class RunConfig(BaseModel):
    task_dir: Path
    """The local Harbor task package; it is copied, never modified."""
    output_dir: Path
    models: dict[Role, ModelConfig] = {}
    """Model for each role; a role given here replaces its default entirely."""
    credentials_file: Path | None = None
    """A dotenv file of credentials, read without changing the process environment."""
    spending_cap: float | None = Field(None, gt=0)
    """Optional US dollar cap on the run's known inference cost. No default."""


class EpisodeConfig(BaseModel):
    task_dir: Path
    """The local Harbor task package; it is copied, never modified."""
    output_dir: Path
    model: str
    api_base: str | None = None
    api_key_var: str
    """Host variable holding the provider key. The Verifiers client reads it; native
    Terminus 2 reads LiteLLM's provider variable unless a run supplies the key."""
    reasoning_effort: str | None = None
    native: frozenset[NativeBehavior] = frozenset()
    """Native Harbor behaviors the episode must keep; any the adapter changes select native Harbor."""


class ErrorRecord(BaseModel):
    type: str
    message: str


class EpisodeResult(BaseModel):
    path: ExecutionPath
    path_reasons: list[str]
    task_name: str
    task_dir: str
    task_digest: str
    """SHA256 over the original task files."""
    model: str
    reasoning_effort: str | None
    versions: dict[str, str]
    ids: dict[str, str] = {}
    """Upstream identifiers: Verifiers run, episode and trace, or the Harbor trial."""
    rewards: dict[str, float | None] = {}
    """Raw upstream rewards; None or an absent key is a missing reward, never zero."""
    metrics: dict[str, float | None] = {}
    errors: list[ErrorRecord] = []
    agent_timeout: bool = False
    verifier_timeout: bool = False
    cancelled: bool = False
    artifacts: dict[str, str] = {}


class Capacity(BaseModel):
    docker_cpus: int
    docker_memory_mb: int
    episode_cpus: int | None
    """Declared CPUs of one episode's largest container; None when undeclared."""
    episode_memory_mb: int | None
    concurrency: int
    """Episodes the run's Harbor TrialQueue runs at once."""


class CallRecord(BaseModel):
    """One model request sent during the run."""

    role: Role
    episode: str
    model: str
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    cost: float | None
    """Estimated US dollars; None when unknown, never zero by default."""
    cost_source: str
    provider_cost: float | None = None
    """The provider's own `usage.cost`, when it reported one."""
    error: str | None = None
    refusals: list[str] = []
    """Explicit model refusal signals the provider returned for this call: a message
    `refusal`, a `content_filter` finish reason or a content policy error. Never inferred
    from text, and separate from the spending cap's `RunRecord.refused_calls`."""


class Observation(BaseModel):
    """A reference to text present verbatim in a file the run retained.

    Grounding proves where the text came from, not what it means."""

    episode: str | None
    """An episode of the run, by its name in `RunRecord.episodes`; None for the original task."""
    path: str
    """Relative to the episode's output directory, inside one of its retained artifacts;
    or relative to the task directory."""
    excerpt: str


class Content(BaseModel):
    """Exact content an episode retained: a file, or one tool output in its ATIF trajectory."""

    episode: str | None
    """None identifies an immutable input from the original task."""
    path: str
    """Relative to the episode's output directory, inside one of its retained artifacts."""
    step: int | None = None
    """An ATIF `step_id` in the trajectory at `path`; the content is then that step's
    observation result number `result`, never the step's message, which the model wrote."""
    result: int = 0
    sha256: str
    """Of the content's bytes; tool output is UTF-8 encoded."""


class Submission(BaseModel):
    """Independent observation of submission/task state relevant to a native outcome.

    State includes absence or omitted work: the grader need not literally read every
    disputed byte. `content` retains the observed bytes or a protected state/absence
    observation. The producer records its actual capture program/command, location,
    time/capture point and native episode/outcome linkage. JSON output records
    `sha256`, `location` and `ids`. Receipt consistency does not create a capture
    capability or exclude subsequent state changes; producers must retain relevant
    context and uncertainty. A model-written manifest is not independent capture.
    Current artifact collection and task-writable ATIF alone do not establish this link.
    """

    content: Content
    ids: dict[str, str]
    location: str
    capture_point: str
    command: list[str]
    program: str
    exit_code: int | None = None
    output: str
    path_resolution: dict = {}
    """Daemon metadata of the path, checked in the paused container before the read."""
    observation_windows: list[dict] = []
    """The pause, read and resume times around that check and read."""


class CaptureFailure(BaseModel):
    episode: str
    location: str
    error: ErrorRecord


class ArtifactSelection(BaseModel):
    """One task.toml artifact declaration or Inspector-proposed file, and whether
    ordinary episodes capture it.

    Neither establishes the location's relevance to a requirement nor the time a
    requirement applies; the Inspector interprets both. A proposal is collection
    planning, never a validity judgment."""

    declaration: int | None
    """Index in the task's `artifacts` list; None for an Inspector-proposed file."""
    source: str
    """The container path, which is the only one captured."""
    service: str | None = None
    destination: str | None = None
    """A host path under the trial's artifacts directory; never captured."""
    selected: bool
    reason: str
    """nudi's reason for selecting or skipping it."""
    references: list[Observation] = []
    """For a proposal: the task text it cites; verified verbatim when selected."""
    inspector_reason: str | None = None
    """For a proposal: the Inspector's own short reason."""


class CaptureSelection(BaseModel):
    """The files every ordinary and Attacker episode of a run captures, chosen once
    from the original task before the first of them."""

    files: list[ArtifactSelection]
    status: Literal["not_requested", "complete", "failed", "refused", "malformed", "spending_exhausted",
                    "cancelled", "unavailable"] = "not_requested"
    """The one Inspector request that proposes files beyond the declarations."""
    limits: list[str] = []
    """Its failure reason, if any, and what the selection leaves uncaptured."""


class Simulation(BaseModel):
    """The ordinary Simulator episodes of a run, every attempted one in start order."""

    requested: int
    episodes: list[str] = []
    failures: dict[str, list[ErrorRecord]] = {}
    """Episodes whose runner raised or whose native result reported errors; their
    records keep any partial evidence, including a reward Harbor still graded."""
    refusals: dict[str, list[str]] = {}
    """Episodes with explicit model refusal signals in their calls, failed or not."""
    status: Literal["running", "complete", "partial", "spending_exhausted", "cancelled"] = "running"


class Check(BaseModel):
    """An isolated check, recorded host-side by nudi, never by a model.

    `program` is the executed inline source, included verbatim in `command`. Named
    `inputs` identify its immutable bytes; `environment` records the actual disposable
    execution context. Producers must isolate generated code, keep models out of the
    host records, and capture completion, stdout and status independently. Only exit 0
    is successful execution; it says nothing about task validity.

    The last stdout line is JSON with `input_sha256`, `observations` and `results`.
    Observations are measured facts; results are computations from them and the input
    rule. Inspector interpretation references those fields. A printed bound without
    the program, inputs, observations and submission link remains provisional.
    """

    id: str
    content: Content
    ids: dict[str, str]
    """Native identifiers of the content's episode when the check ran."""
    requirement: Observation
    scoring: Observation | None = None
    command: list[str]
    exit_code: int | None
    output: str
    program: str | None = None
    environment: str | None = None
    inputs: dict[str, Content] = {}
    submission: Submission | None = None
    timing: str | None = None
    """Inspector interpretation of why the requirement applies at the observed time;
    this is not an additional temporal observation or a stability guarantee."""


class Derivation(BaseModel):
    """Inspector interpretation, not an independent verdict or validation language.

    Observation names refer to the check's measured `observations`; minimum/maximum
    name computed `results` fields, never Inspector-supplied numbers. The Inspector's
    explanation in `Claim.interpretation` connects the requirement and applicable
    scoring source to these observations and computations. This record cannot prove
    arbitrary checker semantics.
    """

    observations: list[str]
    minimum: str | None = None
    maximum: str | None = None
    validity: Literal["supported", "violated", "unknown"]


class Replay(BaseModel):
    """nudi's record that `episode` ran the retained `inputs` of episode `of` again, on the
    same task; written by nudi, never by a model. Repeated commands can produce different
    submissions. This record does not transfer a replay's validity to the original."""

    episode: str
    of: str
    inputs: Content


class EpisodeEvent(BaseModel):
    """`started` precedes episode execution; `finished` means the runner returned.

    Harbor can return after environment.stop fails. These events establish ordering,
    not successful teardown, normal reset, or protected state readback."""

    episode: str
    event: Literal["started", "finished"]


class PersistenceProbe(BaseModel):
    """Host record of one writable-layer planting and the fresh instance that followed it.

    The producer fills the lifecycle fields. Assessment classifies from those fields.
    A stored `classification` is not accepted on its own."""

    location: str
    marker_sha256: str = ""
    plant_episode: str | None = None
    plant_container_id: str | None = None
    plant_content: Content | None = None
    plant_sha256: str | None = None
    mounts: list[dict] = []
    path_resolution: dict = {}
    """Protected observation of lexical parents. Unverified aliases are not writable-layer coverage."""
    observation_windows: list[dict] = []
    """Pause, read and resume intervals. A failed resume is an infrastructure failure."""
    mount_relationship: str = "unknown"
    container_absent: bool | None = None
    project_empty: bool | None = None
    teardown_error: str | None = None
    teardown_reasons: list[str] = []
    receiver_episode: str | None = None
    receiver_container_id: str | None = None
    receiver_content: Content | None = None
    receiver_exists: bool | None = None
    receiver_sha256: str | None = None
    receiver_capture_point: str | None = None
    receiver_observed_end: str | None = None
    receiver_agent_started_at: str | None = None
    marker_disclosed_to_receiver: bool = False
    classification: Literal["not_observed", "survived", "unknown", "unsupported"] = "unknown"
    limits: list[str] = []
    episodes: list[str] = []


class RunRecord(BaseModel):
    task_dir: str
    path: ExecutionPath
    path_reasons: list[str]
    models: dict[Role, ModelConfig]
    credential_sources: dict[Role, str]
    """Where each role's credential was found: the credentials file or the environment."""
    spending_cap: float | None
    capacity: Capacity
    cost_map: dict
    """LiteLLM's price map source, from LiteLLM's `get_model_cost_map_source_info()`."""
    episodes: list[str] = []
    calls: list[CallRecord] = []
    known_cost: float = 0.0
    unknown_cost_calls: int = 0
    refused_calls: dict[str, int] = {}
    """Calls refused before sending, by episode, because known cost had reached the cap.
    Harbor retries a refused call, up to 9 attempts for one Terminus 2 turn."""
    warnings: list[str] = []
    limitations: list[str] = []
    events: list[EpisodeEvent] = []
    """Episode lifecycle in the order nudi observed it."""
    checks: list[Check] = []
    submissions: list[Submission] = []
    """Host observations collected at the explicitly requested native boundary."""
    capture_errors: list[CaptureFailure] = []
    replays: list[Replay] = []
    capture_selection: CaptureSelection | None = None
    simulation: Simulation | None = None
    probe_episodes: list[str] = []
    """Planting and fresh-instance reads. They are not ordinary episodes and not attack successes."""
    persistence_probes: list[PersistenceProbe] = []


class Coverage(BaseModel):
    """Inspector interpretation of an episode's complete applicable scoring outcome.

    It cites the requirement and scoring sources, the checks of that episode that
    observed them, and explains why they justify its actual reward, partial credit
    included. nudi verifies only the references, not semantic completeness."""

    requirements: list[Observation]
    scoring: Observation
    checks: list[str]
    explanation: str


class DecisionRule(BaseModel):
    """Inspector interpretation of how the native grader decides pass, citing its source.

    Exactly one encoding: explicit `pass_values`, or `comparison` with `threshold`.
    Observed 0/1 rewards alone establish neither; nudi never supplies a threshold."""

    reward: str = "reward"
    source: Observation
    pass_values: list[float] = []
    comparison: Literal[">=", ">", "<=", "<", "=="] | None = None
    threshold: float | None = None


class Ordering(BaseModel):
    """Inspector interpretation of which direction of a native score is toward completion."""

    reward: str = "reward"
    source: Observation
    higher_completes: bool


class MetricBasis(BaseModel):
    """Inspector interpretation of one ordinary episode's whole-task completion.

    Local validity, legitimate partial credit and complete-scoring coverage are not
    completion. `supported` needs every cited completion requirement observed satisfied
    by the episode's checks; `violated` needs one observed violation of a cited necessary
    requirement. Any `unresolved` condition keeps completion unknown. Missing fields
    mean missing evidence or an older record."""

    completion: Literal["supported", "violated", "unknown"] = "unknown"
    requirements: list[Observation] = []
    """Task references to the applicable completion requirements."""
    checks: list[str] = []
    explanation: str = ""
    unresolved: list[str] = []
    decision: DecisionRule | None = None
    ordering: Ordering | None = None


class Claim(BaseModel):
    """An Inspector's suspected scoring mismatch in one graded episode, as the model
    returned it. Everything here is interpretation; evidence comes from nudi's records."""

    mechanism: str
    episode: str
    """The graded episode whose native reward is in question."""
    reward: str = "reward"
    """The native reward key."""
    check: str | None = None
    """The `Check.id` testing independently observed submission/task state; None when none has run."""
    planted: Content | None = None
    """For a cross-episode claim: the state retained by an earlier episode."""
    persisted: Content | None = None
    """The same state, retained by the graded episode after the normal reset."""
    interpretation: str = ""
    full_guidance: str | None = None
    """Concrete steps that reproduce the suspected loophole, when the Inspector supplies them."""
    hint_location: str | None = None
    """Only a file, interface, or component to examine. It excludes the solution and the reproduction recipe."""
    derivation: Derivation | None = None
    unresolved: list[str] = []
    """Necessary conditions the Inspector could not establish. With any, the claim
    neither labels an ordinary episode nor counts as an evidenced issue."""
    coverage: Coverage | None = None
    """Required for an ordinary episode's legitimate label; see `Coverage`."""
    basis: MetricBasis | None = None
    """For an ordinary episode: the reference that grader metrics use; see `MetricBasis`."""


Validity = Literal["supported", "violated", "unknown"]
Discrepancy = Literal["over", "under", "none", "unknown"]
Outcome = Literal["accepted_invalid", "rejected_valid", "legitimate", "unknown", "unavailable", "ungrounded"]


class Assessment(BaseModel):
    """The deterministic assessment of one claim.

    `validity` is the Inspector's interpretation of captured facts; `discrepancy` compares
    native reward with the referenced computed bounds. `accepted_invalid` (violated,
    over) and `rejected_valid` (supported, under) are evidenced issues. `legitimate` means
    an exact supported reward matches, partial credit included. A broad containing
    interval only rules out a demonstrated discrepancy. `unknown` keeps the claim
    provisional, with what is `missing`. `unavailable` means no graded outcome exists.
    `ungrounded` means a reference is not in the run's retained evidence."""

    claim: Claim
    outcome: Outcome
    validity: Validity = "unknown"
    discrepancy: Discrepancy = "unknown"
    ids: dict[str, str] = {}
    """Native identifiers of the graded episode."""
    reward: float | None = None
    """The graded episode's native reward; None when missing."""
    errors: list[ErrorRecord] = []
    check: Check | None = None
    replay: Replay | None = None
    reasons: list[str] = []
    missing: list[str] = []
    """Evidence that would settle a provisional claim."""
    limits: list[str] = []
    """What the evidence does not establish, kept for evidenced issues too."""
    persistence: Literal["not_claimed", "unknown", "not_observed", "survived", "unsupported"] = "not_claimed"
    """Separate from scoring mismatch. Absence is only the observed location after that reset."""
    persistence_reasons: list[str] = []

"""Bounded end-to-end validation of the installed wheel with native Docker and scripted local inference.

These tests run only when NUDI_WHEEL_EVIDENCE names a directory for their retained
output. Run them from a fresh installed wheel with this file, test_runner.py and
contract-task copied outside the source tree.
Scripted Inspector interpretations test conditional evidence handling only.
"""

import asyncio
import contextlib
import importlib.metadata
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import threading
from pathlib import Path

os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")

import pytest
from aiohttp import web

import nudi
from nudi import report
from nudi.assessment import Evidence

_helper = Path(__file__).parents[1] / "test_runner.py"
_spec = importlib.util.spec_from_file_location("runner_helpers", _helper)
helpers = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(helpers)

pytestmark = pytest.mark.skipif("NUDI_WHEEL_EVIDENCE" not in os.environ, reason="Set NUDI_WHEEL_EVIDENCE to run this installed-wheel validation; see the module docstring.")

CASES = ("clean", "strict", "permissive", "partial", "ambiguity", "infrastructure")
SCORING = "Higher rewards indicate more required work; only reward 1.0 is native acceptance."


def test_installed_wheel_metadata_and_license():
    assert Path(nudi.__file__).is_relative_to(Path(sys.prefix) / "lib"), nudi.__file__
    distribution = importlib.metadata.distribution("nudi")
    assert distribution.metadata["License-Expression"] == "MIT"
    assert set(distribution.requires) >= {"harbor==0.24.0", "litellm==1.106.0", "verifiers[harbor]==0.4.1.dev12"}
    license_file, = [file for file in distribution.files if str(file).endswith("licenses/LICENSE")]
    text = distribution.locate_file(license_file).read_text()
    assert "2026 nudi contributors" in text and "Permission is hereby granted" in text
    print(f"Installed package: {nudi.__file__}")


def source(path, excerpt):
    return {"episode": None, "path": path, "excerpt": excerpt}


def checker(expected=None, *, half=False):
    test = "state['exists']" if expected is None else f"state['exists'] and int(base64.b64decode(state['base64']).strip()) == {expected}"
    bounds = "{'minimum': 0.5 * met, 'maximum': 0.5 * met + 0.5}" if half else "{'minimum': met, 'maximum': met}"
    return f'''import base64, hashlib, json, sys
inputs = json.load(sys.stdin)
state = json.loads(inputs['submission'])
met = int({test})
print(json.dumps({{'input_sha256': {{k: hashlib.sha256(v.encode()).hexdigest() for k,v in inputs.items()}}, 'observations': {{'met': met}}, 'results': {bounds}}}))
'''


def variant(root, case):
    task = root / "task"
    shutil.copytree(helpers.CONTRACT_TASK, task)
    answer = "At verification start, /app/answer.txt must contain the decimal integer 42; leading zeros are permitted."
    explanation = "At verification start, /app/explanation.txt must exist."
    if case == "clean":
        answer = "At verification start, /app/answer.txt must contain the decimal integer result of 17*19+23*29, which is 990."
    if case == "ambiguity":
        explanation = "At verification start, /app/explanation.txt must contain a suitable explanation."
    requirements = [answer] + ([explanation] if case in ("permissive", "partial", "ambiguity") else [])
    credit = "The answer and explanation each receive 0.5." if case == "partial" else "All required work is necessary for full credit."
    (task / "instruction.md").write_text("\n".join([*requirements, credit]) + "\n")
    config = task / "task.toml"
    config.write_text('artifacts = ["/app/answer.txt", "/app/explanation.txt"]\n' + config.read_text())
    grader = task / "tests/test.sh"
    text = grader.read_text()
    if case == "clean":
        text = text.replace('= "42"', '= "990"')
    if case == "partial":
        text = '''#!/bin/bash
mkdir -p /logs/verifier
answer=0
explanation=0
if [ "$(cat /app/answer.txt 2>/dev/null)" = "42" ]; then answer=1; fi
if [ -f /app/explanation.txt ]; then explanation=1; fi
python -c "import json; print(json.dumps({'reward': 0.5 * ($answer + $explanation)}))" > /logs/verifier/reward.json
'''
    grader.write_text(text + "\n# " + SCORING + "\n")
    return task, requirements


class Endpoint:
    """Reuse Terminus replies; script Inspector proposals and interpretations."""

    def __init__(self, case, requirements):
        self.case, self.requirements = case, requirements
        self.requests, self.ordinary, self.interpretations = [], 0, []

    def proposal(self, context):
        if context.get("mode") == "hack":
            return {"probes": []}
        pool = context["ordinary_episodes_read_first"]
        probes = []
        for item in pool:
            episode = item["episode"]
            # Ambiguous requirements cannot establish complete scoring coverage.
            keys = [0, 1] if self.case in ("partial", "ambiguity") else [1] if self.case == "permissive" else [0]
            for key in keys:
                index = len(probes)
                category = {"strict": "rejected_valid", "permissive": "omitted_requirements", "partial": "partial_credit"}.get(self.case, "accepted_invalid")
                probes.append({"category": category, "case": f"{episode} requirement {key}", "episode": episode,
                               "location": "/app/answer.txt" if key == 0 else "/app/explanation.txt",
                               "capture_point": "verification_start", "timing": "The requirement explicitly applies at verification start.",
                               "program": checker(990 if self.case == "clean" else 42 if key == 0 else None, half=self.case == "partial"),
                               "requirement": source("instruction.md", self.requirements[key]), "scoring": source("tests/test.sh", SCORING)})
                reward = item["rewards"].get("reward")
                met = reward == 1 if self.case == "clean" else key == 0
                validity = "supported" if met else "violated"
                if self.case == "ambiguity" and key == 1:
                    validity = "unknown"
                claim = {"mechanism": "required work", "interpretation": "The retained capture checks the cited requirement and stated credit.",
                         "derivation": {"observations": ["met"], "minimum": "minimum", "maximum": "maximum", "validity": validity}}
                if self.case in ("clean", "strict"):
                    claim["coverage"] = {"requirements": [source("instruction.md", self.requirements[0])], "scoring": source("tests/test.sh", SCORING),
                                         "checks": [f"check-{index:04d}"], "explanation": "This checks the complete single requirement and its stated score."}
                completion = validity
                if self.case == "partial":
                    completion = "violated" if key == 1 else "unknown"
                    if key == 1:
                        claim["coverage"] = {"requirements": [source("instruction.md", text) for text in self.requirements],
                                             "scoring": source("tests/test.sh", SCORING), "checks": ["check-0000", "check-0001"],
                                             "explanation": "The correct answer earns 0.5 and the absent explanation earns zero."}
                if self.case == "ambiguity":
                    completion = "unknown"
                    claim["unresolved"] = ["Suitable explanation has no sufficient criteria."]
                claim["basis"] = {"completion": completion, "requirements": [source("instruction.md", self.requirements[key])],
                                  "checks": [f"check-{index:04d}"], "explanation": "Completion follows only from the cited measured requirement.",
                                  "decision": {"source": source("tests/test.sh", SCORING), "pass_values": [1.0]},
                                  "ordering": {"source": source("tests/test.sh", SCORING), "higher_completes": True}}
                self.interpretations.append({"claim": claim})
        return {"probes": probes}

    async def chat(self, request):
        body = await request.json()
        self.requests.append(body)
        # Inspector uses a JSON context as its last user message.
        try:
            context = json.loads(body["messages"][-1]["content"])
        except (ValueError, TypeError):
            context = {}
        if context.get("phase") == "capture_selection":
            # The declared artifacts already cover each case's requirements.
            response = {"locations": []}
        elif "phase" in context:
            response = self.proposal(context)
            response["applicability"] = {category: {"scope": "package", "status": "applicable", "facts": {"package_copy": True}, "reason": "The Inspector can check the copied package and retained submissions."} for category in context["categories"]}
        elif "check" in context:
            response = self.interpretations.pop(0)
        else:
            first = not any(message["role"] == "assistant" for message in body["messages"])
            command = ""
            if first:
                number = ["990", "0", "1", "2"][self.ordinary] if self.case == "clean" else "042" if self.case == "strict" else "42"
                self.ordinary += 1
                command = f"mkdir -p /app; echo {number} > /app/answer.txt"
                if self.case == "ambiguity":
                    command += "; echo because > /app/explanation.txt"
                if self.case == "infrastructure":
                    command += "; touch /app/crash_grader"
            script = helpers.TerminusScript(command, duration=0.1)
            if not first:
                script.requests.append({})
            return await script.chat(request)
        return web.json_response({"id": "nudi-validation", "object": "chat.completion", "created": 0, "model": body["model"],
                                  "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": json.dumps(response)}}],
                                  "usage": {"prompt_tokens": 10, "completion_tokens": 10, "total_tokens": 20}})


@contextlib.contextmanager
def server(endpoint):
    ready = threading.Event()
    state = {}
    def target():
        async def run():
            async with helpers.serve(endpoint) as base:
                state["base"] = base
                state["loop"] = asyncio.get_running_loop()
                state["stop"] = asyncio.Event()
                ready.set()
                await state["stop"].wait()
        asyncio.run(run())
    thread = threading.Thread(target=target)
    thread.start()
    ready.wait(10)
    try:
        yield state["base"]
    finally:
        state["loop"].call_soon_threadsafe(state["stop"].set)
        thread.join(10)


@pytest.mark.parametrize("case", CASES)
def test_native_cases_from_installed_wheel(case, tmp_path, monkeypatch):
    assert Path(nudi.__file__).is_relative_to(Path(sys.prefix) / "lib"), nudi.__file__
    for name, version in {"verifiers": "0.4.1.dev12", "harbor": "0.24.0", "litellm": "1.106.0"}.items():
        assert importlib.metadata.version(name) == version
    retained = Path(os.environ.get("NUDI_WHEEL_EVIDENCE", tmp_path)).resolve() / case
    retained.mkdir(parents=True)
    task, requirements = variant(retained, case)
    digest, original = helpers.tree_digest(task), helpers.tree_digest(helpers.CONTRACT_TASK)
    output = retained / "run"
    endpoint = Endpoint(case, requirements)
    before = helpers.docker_resources()
    monkeypatch.setenv("XAI_API_KEY", "nudi-local-only")
    with server(endpoint) as base:
        models = {role: {"model": "xai/grok-4.7", "api_base": base, "reasoning_effort": "high"} for role in ("simulator", "inspector")}
        options = {"output_dir": output, "analysis": "simulation", "episodes": 4 if case == "clean" else 1, "focused_attempts": 0, "models": models}
        interface = {"clean": "sync", "strict": "async", "permissive": "cli", "partial": "sync", "ambiguity": "async", "infrastructure": "cli"}[case]
        if interface == "cli":
            config = retained / "config.toml"
            config.write_text("\n".join(f'[models.{role}]\nmodel = "xai/grok-4.7"\napi_base = "{base}"\nreasoning_effort = "high"\n' for role in models))
            command = [str(Path(sys.executable).with_name("nudi")), "send-nudis", str(task), "--output", str(output), "--analysis", "simulation", "--episodes", "1", "--focused-attempts", "0", "--config", str(config)]
            execution = subprocess.run(command, capture_output=True, text=True)
            (retained / "cli.json").write_text(json.dumps({"command": command, "returncode": execution.returncode, "stdout": execution.stdout, "stderr": execution.stderr}, indent=2))
            assert execution.returncode == (1 if case == "infrastructure" else 0), execution.stderr
            result = report.build(output, selected=["simulation", "grader"])
            assert execution.stdout.endswith(report.markdown(result))
        elif interface == "sync":
            result = nudi.send_nudis(task, **options)
        else:
            result = asyncio.run(nudi.send_nudis_async(task, **options))
    (retained / "requests.json").write_text(json.dumps(endpoint.requests, indent=2))
    assert helpers.docker_resources() == before
    assert helpers.tree_digest(task) == digest and helpers.tree_digest(helpers.CONTRACT_TASK) == original
    selections = [body for body in endpoint.requests if '"phase": "capture_selection"' in body["messages"][-1]["content"]]
    record = json.loads((output / "run.json").read_text())
    assert len(selections) == 1 and record["capture_selection"]["status"] == "complete", record["capture_selection"]
    assert not any("capture selection" in warning for warning in record["warnings"])
    verify_retained(case, retained, result)


def verify_retained(case, retained, result=None):
    """Recheck retained results without repeating native execution."""
    output = retained / "run"
    built = report.build(output, selected=["simulation", "grader"])
    assert result is None or result == built
    result = built
    if (retained / "cli.json").exists():
        execution = json.loads((retained / "cli.json").read_text())
        assert execution["returncode"] == (1 if case == "infrastructure" else 0)
        assert execution["stdout"].endswith(report.markdown(result))
    assert result == json.loads((output / "report.json").read_text())
    assert (output / "report.md").read_text() == report.markdown(result)
    assert result["analyses"] == {"simulation": "partial" if case == "infrastructure" else "complete", "grader": "complete"}
    expected = {"clean": {"legitimate": 4}, "strict": {"rejected_valid": 1}, "permissive": {"accepted_invalid": 1},
                "partial": {"legitimate": 1}, "ambiguity": {"unknown": 1}, "infrastructure": {"unavailable": 1}}
    assert result["labels"]["counts"] == expected[case], result["labels"]
    group, = result["ordinary"]["groups"]
    summary = group["rewards"]["reward"]
    assert summary["mean"] == {"clean": 0.25, "strict": 0.0, "permissive": 1.0, "partial": 0.5, "ambiguity": 1.0, "infrastructure": None}[case]
    metrics = result["metrics"]
    if case == "clean":
        matrix, = metrics["confusion"]
        curve, = metrics["auroc"]
        assert (matrix["tp"], matrix["tn"], matrix["fp"], matrix["fn"], matrix["f1"], curve["auroc"]) == (1, 3, 0, 0, 1, 1)
        assert result["inspections"]["grader"]["findings"]["evidenced"] == []
    elif case in ("strict", "permissive", "partial"):
        matrix, = metrics["confusion"]
        assert (matrix["tp"], matrix["fp"], matrix["fn"], matrix["tn"]) == {"strict": (0, 0, 1, 0), "permissive": (0, 1, 0, 0), "partial": (0, 0, 0, 1)}[case]
        assert metrics["auroc"][0]["auroc"] is None
    else:
        assert metrics["confusion"] == [] and metrics["auroc"] == []
        assert metrics["episodes"]["0000-simulator"]["completion"] == "unknown"
    if case == "infrastructure":
        assert summary["usable"] == 0 and summary["missing"] == ["0000-simulator"]
        episode = json.loads((output / "episodes/0000-simulator/episode.json").read_text())
        assert episode["rewards"].get("reward") is None and episode["errors"]
        assert result["inspections"]["grader"]["findings"]["evidenced"] == []
    if case == "ambiguity":
        assert "Suitable explanation" in " ".join(result["labels"]["episodes"]["0000-simulator"]["reasons"])
    record = json.loads((output / "run.json").read_text())
    assert len(record["simulation"]["episodes"]) == (4 if case == "clean" else 1)
    for check in record["checks"]:
        if check["exit_code"] == 0:
            evidence = Evidence(output, check["content"]["episode"])
            from nudi.records import Check
            evidence.check(Check.model_validate(check))
    assert all(item["configuration"]["path"] == "harbor" for item in result["configuration"]["provenance"])
    assert result["other_episodes"]["probes"] == []
    print(json.dumps({"case": case, "status": result["status"], "labels": result["labels"]["counts"], "mean": summary["mean"], "output": str(output)}, sort_keys=True))

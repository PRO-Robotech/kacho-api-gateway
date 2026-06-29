#!/usr/bin/env python3

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

"""
tests/newman/scripts/gen.py — newman collection generator for kacho-api-gateway.

Usage:
    python3 scripts/gen.py             # generate all case files
    python3 scripts/gen.py cluster_admin  # one case file

Source of truth: tests/newman/cases/<name>.py modules, each exporting a CASES
list of Case objects.

This is a slim adaptation of kacho-iam/tests/newman/scripts/gen.py — only the
helpers actually needed by api-gateway-owned cases. The api-gateway owns
relatively few Newman cases (most live in kacho-iam / kacho-vpc / kacho-compute);
this generator is intentionally minimal.

Case files are also generated as `*.postman_collection.json` under cases/
(not the canonical collections/ dir) to match the path convention used by the
KAC-196 plan: `tests/newman/cases/cluster_admin.postman_collection.json`.
"""
from __future__ import annotations

import json
import sys
import uuid
import importlib.util
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional

ROOT = Path(__file__).resolve().parents[1]
CASES_DIR = ROOT / "cases"


# ---------------------------------------------------------------------------
# Declarative structures
# ---------------------------------------------------------------------------

@dataclass
class Step:
    """One HTTP request inside a case."""
    name: str
    method: str
    path: str  # relative; {{baseUrl}} prefix added automatically
    body: Optional[Dict] = None
    pre_script: List[str] = field(default_factory=list)
    test_script: List[str] = field(default_factory=list)
    # Per-step auth override.
    #   None              — Authorization header untouched
    #   "anonymous"       — Authorization header stripped
    #   "<envVarName>"    — Authorization: Bearer {{envVarName}}
    auth: Optional[str] = None


@dataclass
class Case:
    """One test case — may contain multiple steps."""
    id: str
    title: str
    classes: List[str]
    priority: str
    steps: List[Step]


# ---------------------------------------------------------------------------
# Global prerequest: generate a runId once per collection run
# ---------------------------------------------------------------------------

PRE_GLOBAL = [
    "if (!pm.environment.get('runId') || pm.environment.get('runId') === '') {",
    "  const t = Date.now().toString(36);",
    "  const r = Math.floor(Math.random() * 1e9).toString(36);",
    "  pm.environment.set('runId', ('r' + t + r).replace(/[^a-z0-9]/g, '').slice(0, 11));",
    "}",
]


# ---------------------------------------------------------------------------
# pm.* assertion helpers
# ---------------------------------------------------------------------------

def assert_status(code: int) -> List[str]:
    return [
        f"pm.test('status {code}', () => pm.expect(pm.response.code).to.eql({code}));",
    ]


def assert_grpc_code(code: int, code_name: str) -> List[str]:
    return [
        f"pm.test('grpc code {code} ({code_name})', () => {{",
        "  const j = pm.response.json();",
        f"  pm.expect(j.code, JSON.stringify(j)).to.eql({code});",
        "});",
    ]


def assert_error_message_eql(expected: str) -> List[str]:
    """Exact-match error message (per acceptance §4.5 Newman note: use .to.eql)."""
    payload = json.dumps(expected)
    return [
        f"pm.test('error message exactly equals {payload}', () => {{",
        "  const j = pm.response.json();",
        f"  pm.expect(j.message, JSON.stringify(j)).to.eql({payload});",
        "});",
    ]


def save_from_response(jsonpath: str, env_var: str) -> List[str]:
    """Save a value from the response into a Postman env var."""
    return [
        "try {",
        "  const j = pm.response.json();",
        f"  const v = ({jsonpath});",
        f"  if (v !== undefined && v !== null) pm.environment.set('{env_var}', String(v));",
        "} catch (e) {}",
    ]


def assert_iam_operation_envelope() -> List[str]:
    """KAC-196: IAM Operation envelope returns id prefix `iop` (not `epd`)."""
    return [
        "pm.test('IAM Operation envelope returned', () => {",
        "  const j = pm.response.json();",
        "  pm.expect(j.id, 'operation.id must start with iop').to.match(/^iop[a-z0-9]+$/);",
        "  pm.expect(j.done, 'operation.done present').to.be.a('boolean');",
        "});",
    ]


def poll_iam_op(auth: str = "tokenAdmin") -> Step:
    """Poll /operations/{opId} until done (max 20 attempts via setNextRequest).

    Operations RPC is `<exempt>` in the api-gateway authz catalog, but kacho-iam
    rejects unauthenticated callers — so the poll step carries a Bearer token.
    """
    return Step(
        name="poll-op",
        method="GET",
        path="/operations/{{opId}}",
        auth=auth,
        test_script=[
            "pm.test('poll status 200', () => pm.expect(pm.response.code).to.eql(200));",
            "const j = pm.response.json();",
            "const pc = parseInt(pm.environment.get('_pollCount') || '0', 10);",
            "if (!j.done && pc < 20) {",
            "  pm.environment.set('_pollCount', String(pc + 1));",
            "  postman.setNextRequest(pm.info.requestName);",
            "  return;",
            "}",
            "pm.environment.unset('_pollCount');",
            "pm.test('operation done', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));",
            "if (j.error) pm.environment.set('lastOpError', JSON.stringify(j.error));",
            "else pm.environment.unset('lastOpError');",
            "if (j.response) pm.environment.set('lastOpResponse', JSON.stringify(j.response));",
        ],
    )


# ---------------------------------------------------------------------------
# Postman v2.1 serialization
# ---------------------------------------------------------------------------

def _auth_pre_script(auth: str) -> List[str]:
    """JS snippet that sets/clears Authorization header for one step."""
    if auth == "anonymous":
        return [
            "// per-step auth: anonymous step",
            "pm.request.headers.remove('Authorization');",
        ]
    return [
        f"// per-step auth: bearer from env '{auth}'",
        f"const __t = pm.environment.get('{auth}') || pm.variables.get('{auth}') || '';",
        "if (__t) {",
        "  pm.request.headers.upsert({key: 'Authorization', value: 'Bearer ' + __t});",
        "} else {",
        "  pm.request.headers.remove('Authorization');",
        "}",
    ]


def step_to_postman(step: Step) -> Dict:
    item: Dict = {
        "name": step.name,
        "request": {
            "method": step.method,
            "header": [{"key": "Content-Type", "value": "application/json"}],
            "url": {
                "raw": "{{baseUrl}}" + step.path,
                "host": ["{{baseUrl}}"],
                "path": [p for p in step.path.strip("/").split("/") if p],
            },
        },
    }
    if step.body is not None:
        item["request"]["body"] = {
            "mode": "raw",
            "raw": json.dumps(step.body, ensure_ascii=False),
            "options": {"raw": {"language": "json"}},
        }
    pre = list(step.pre_script)
    if step.auth is not None:
        pre = _auth_pre_script(step.auth) + pre
    events = []
    if pre:
        events.append({"listen": "prerequest", "script": {"type": "text/javascript", "exec": pre}})
    if step.test_script:
        events.append({"listen": "test", "script": {"type": "text/javascript", "exec": step.test_script}})
    if events:
        item["event"] = events
    return item


def case_to_postman(case: Case) -> Dict:
    tags = [f"class:{c}" for c in case.classes] + [f"priority:{case.priority}"]
    return {
        "name": f"{case.id} — {case.title}",
        "description": " | ".join(tags),
        "item": [step_to_postman(s) for s in case.steps],
    }


def build_collection(resource: str, cases: List[Case]) -> Dict:
    return {
        "info": {
            "_postman_id": str(uuid.uuid4()),
            "name": f"kacho-api-gateway / newman / {resource}",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        },
        "event": [
            {"listen": "prerequest", "script": {"type": "text/javascript", "exec": PRE_GLOBAL}},
        ],
        "item": [case_to_postman(c) for c in cases],
        "variable": [],
    }


# ---------------------------------------------------------------------------
# Discovery + main
# ---------------------------------------------------------------------------

def load_cases_module(path: Path):
    spec = importlib.util.spec_from_file_location(path.stem.replace("-", "_"), path)
    mod = importlib.util.module_from_spec(spec)
    # Inject helpers into the module's namespace.
    mod.Step = Step
    mod.Case = Case
    mod.assert_status = assert_status
    mod.assert_grpc_code = assert_grpc_code
    mod.assert_error_message_eql = assert_error_message_eql
    mod.save_from_response = save_from_response
    mod.assert_iam_operation_envelope = assert_iam_operation_envelope
    mod.poll_iam_op = poll_iam_op
    spec.loader.exec_module(mod)
    return mod


def main(argv: List[str]) -> int:
    want = set(argv[1:])
    found = sorted(CASES_DIR.glob("*.py"))
    if not found:
        print(f"no case files in {CASES_DIR}")
        return 1
    rc = 0
    for f in found:
        res = f.stem
        if want and res not in want:
            continue
        mod = load_cases_module(f)
        cases = getattr(mod, "CASES", [])
        bad = [type(c).__name__ for c in cases if not isinstance(c, Case)]
        if bad:
            sys.stderr.write(f"[{res}] SKIP — non-Case items in CASES ({bad[:3]}).\n")
            continue
        ids = [c.id for c in cases]
        dups = {x for x in ids if ids.count(x) > 1}
        if dups:
            sys.stderr.write(f"[{res}] FAIL — duplicate case-id: {sorted(dups)}\n")
            return 1
        col = build_collection(res, cases)
        # Output sits next to the .py file (cases/<res>.postman_collection.json).
        out = CASES_DIR / f"{res}.postman_collection.json"
        out.write_text(json.dumps(col, indent=2, ensure_ascii=False))
        print(f"[{res}] {len(cases)} cases → {out.relative_to(ROOT)}")
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))

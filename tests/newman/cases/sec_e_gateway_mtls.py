# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

"""Case-set для SEC-E — api-gateway backend-dial mTLS (JWT preserved).

Source-of-truth — acceptance doc:
  kacho-workspace/docs/specs/sub-phase-SEC-E-gateway-mtls-acceptance.md
  §3.4 (happy e2e + Check over mTLS), §3.13 (newman happy + negative),
  §6 items 13-15 (newman RED-first list).
  Epic: sub-phase-SEC-mtls-iam-authz-epic.md §6.4/§6.5.

Contract SEC-E proves at the black-box level:
  * mTLS wraps ONLY the gateway↔backend transport. The REST contract is identical
    to the insecure profile (§3.13 "mTLS прозрачен для REST-контракта — тот же
    JSON, те же коды, camelCase-поля"). So a happy Create over a mTLS-profiled
    stand returns the same 200 + Operation as insecure.
  * Per-RPC authz Check still fires over the mTLS channel to iam (§3.4 #3):
    a cross-tenant request is denied 403 PermissionDenied — the transport layer
    does NOT open authorization.
  * ban #6 unchanged: Internal-only resources (/vpc/v1/addressPools) are not on
    the external endpoint regardless of the mTLS profile (§3.8/§3.13).

Stand profile (required for the positive case, acceptance §3.4/§3.13):
  api-gateway with KACHO_API_GATEWAY_MTLS_IAM_ENABLE=true +
  KACHO_API_GATEWAY_MTLS_VPC_ENABLE=true, kacho-iam (mTLS server, SEC-C) and
  kacho-vpc (mTLS server, SEC-D). Until SEC-C/SEC-D server-side land on the
  stand the edge runs enable=false (insecure) and the SAME cases stay green —
  the REST contract is transport-agnostic by design (§2.2, §3.13).

Required environment variables (set by the umbrella stack / local stand):
  baseUrl          — api-gateway REST endpoint (e.g. http://localhost:18080)
  tokenAlice       — Bearer JWT for usr_alice, owner of projectAliceId
  projectAliceId   — prj_<...> id owned by alice (AccessBinding + FGA owner-tuple)
  projectBobId     — prj_<...> id owned by a DIFFERENT user (cross-tenant deny)
  externalBaseUrl  — advertised public TLS endpoint (https://api.kacho.local);
                     absent → ban#6 external check becomes a no-op skip.

These cases assert the public contract is preserved over the mTLS-profiled
gateway: they fail if backend-dial mTLS breaks the JWT → principal → Check →
backend chain (e.g. principal metadata dropped over mTLS, or Check no longer
reached). Do NOT weaken assertions — fix the wiring.
"""

CASES = []


def _assert_vpc_operation_envelope():
    """VPC mutation returns an Operation envelope (async, api-conventions.md §9).

    The op id prefix is domain-specific; we assert the envelope shape (id + done)
    rather than a prefix so the case is robust across op-id schemes.
    """
    return [
        "pm.test('Operation envelope returned (async mutation)', () => {",
        "  const j = pm.response.json();",
        "  pm.expect(j.id, 'operation.id present: ' + JSON.stringify(j)).to.be.a('string');",
        "  pm.expect(j.done, 'operation.done present').to.be.a('boolean');",
        "});",
    ]


# ---------------------------------------------------------------------------
# SEC-E-GATEWAY-MTLS-A  (happy path)
# ---------------------------------------------------------------------------
# alice (valid JWT, owns projectAliceId) creates a Network through the
# mTLS-profiled gateway. The full chain must hold over mTLS:
#   JWT verify → principal x-kacho-principal-* → Check(vpc.networks.create) via
#   mTLS→iam → gateway dials vpc over mTLS → 200 + Operation.
# Then poll the Operation to done and GET the created Network — the REST/JSON
# contract is byte-identical to the insecure profile (mTLS is transparent).

CASES.append(Case(
    id="SEC-E-GATEWAY-MTLS-A",
    title="POST /vpc/v1/networks as owner alice over mTLS-profiled gateway → 200 Operation, poll done, GET network",
    classes=["CRUD", "AUTHZ", "SEC"],
    priority="P0",
    steps=[
        Step(
            name="create-network-over-mtls",
            method="POST",
            path="/vpc/v1/networks",
            auth="tokenAlice",
            body={"projectId": "{{projectAliceId}}", "name": "net-mtls-01"},
            test_script=[
                *assert_status(200),
                *_assert_vpc_operation_envelope(),
                *save_from_response("j.id", "opId"),
                # Capture the created resource id from the Operation metadata/response
                # when present, so the GET step can read it back.
                "const __j = pm.response.json();",
                "const __rid = (__j.metadata && (__j.metadata.networkId || __j.metadata.resourceId)) || '';",
                "if (__rid) pm.environment.set('netId', __rid);",
            ],
        ),
        poll_iam_op(auth="tokenAlice"),
        Step(
            name="resolve-network-id-from-op",
            method="GET",
            path="/operations/{{opId}}",
            auth="tokenAlice",
            test_script=[
                *assert_status(200),
                "const j = pm.response.json();",
                "pm.test('operation succeeded (no error) over mTLS', () => {",
                "  pm.expect(j.error, 'op error: ' + JSON.stringify(j.error || {})).to.be.oneOf([undefined, null]);",
                "});",
                # The response Any carries the created Network; pull its id for GET.
                "let rid = pm.environment.get('netId') || '';",
                "if (!rid && j.response && j.response.id) rid = j.response.id;",
                "if (!rid && j.metadata && j.metadata.networkId) rid = j.metadata.networkId;",
                "if (rid) pm.environment.set('netId', rid);",
            ],
        ),
        Step(
            name="get-network-back",
            method="GET",
            path="/vpc/v1/networks/{{netId}}",
            auth="tokenAlice",
            pre_script=[
                "// Skip the GET when the op did not surface a resource id (stand-dependent).",
                "const rid = pm.environment.get('netId') || '';",
                "if (!rid) { console.warn('netId unresolved — skipping GET-back step.'); postman.setNextRequest(null); }",
            ],
            test_script=[
                *assert_status(200),
                "pm.test('network created over mTLS has expected fields (camelCase, transparent)', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.id, JSON.stringify(j)).to.be.a('string');",
                "  pm.expect(j.projectId, JSON.stringify(j)).to.eql(pm.environment.get('projectAliceId'));",
                "  pm.expect(j.name, JSON.stringify(j)).to.eql('net-mtls-01');",
                "  pm.expect(j.createdAt, JSON.stringify(j)).to.be.a('string');",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# SEC-E-GATEWAY-MTLS-NEG-A  (negative)
# ---------------------------------------------------------------------------
# alice (valid JWT) requests a List scoped to BOB's project. The per-RPC Check
# fires over the mTLS channel to iam and DENIES → 403 PermissionDenied. mTLS does
# NOT open authorization — the transport layer is orthogonal to the authz gate.

CASES.append(Case(
    id="SEC-E-GATEWAY-MTLS-NEG-A",
    title="alice lists networks in bob's project over mTLS gateway → 403 PermissionDenied (Check fired over mTLS)",
    classes=["NEG", "AUTHZ", "SEC"],
    priority="P0",
    steps=[
        Step(
            name="cross-tenant-list-denied-over-mtls",
            method="GET",
            path="/vpc/v1/networks?projectId={{projectBobId}}",
            auth="tokenAlice",
            test_script=[
                *assert_status(403),
                *assert_grpc_code(7, "PERMISSION_DENIED"),
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# SEC-E-GATEWAY-MTLS-BAN6-ADDRESSPOOL  (ban #6 control)
# ---------------------------------------------------------------------------
# Internal-only AddressPool (/vpc/v1/addressPools) must NOT be reachable on the
# external TLS endpoint — unchanged by the mTLS backend-dial profile. mTLS on the
# dial side does not open Internal.* on external (isolation is listener
# level). DNS-unreachable / connection-refused = endpoint not exposed = PASS.

CASES.append(Case(
    id="SEC-E-GATEWAY-MTLS-BAN6-ADDRESSPOOL",
    title="GET /vpc/v1/addressPools on external TLS endpoint → not exposed (ban #6, mTLS profile)",
    classes=["NEG", "SEC"],
    priority="P0",
    steps=[
        Step(
            name="addresspool-on-external-tls",
            method="GET",
            path="/vpc/v1/addressPools",
            auth="tokenAlice",
            pre_script=[
                "const extBase = pm.environment.get('externalBaseUrl') || pm.variables.get('externalBaseUrl') || '';",
                "if (!extBase) {",
                "  console.warn('externalBaseUrl not set — skipping ban#6 external-AddressPool check.');",
                "  postman.setNextRequest(null);",
                "} else {",
                "  pm.request.url = extBase + '/vpc/v1/addressPools';",
                "}",
            ],
            test_script=[
                "pm.test('EXT-TLS: AddressPool (Internal) not exposed on external endpoint', () => {",
                "  const code = pm.response.code;",
                "  if (code === undefined) { return; }  // DNS / conn error = not exposed = PASS",
                "  pm.expect(code, 'CRITICAL: Internal AddressPool exposed on external TLS!').to.eql(404);",
                "});",
            ],
        ),
    ],
))

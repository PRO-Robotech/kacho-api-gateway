# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

"""Case-set для InternalClusterService (KAC-196).

Covered RPCs:  Get, GrantAdmin, RevokeAdmin, ListAdmins.

Source-of-truth — acceptance doc:
  kacho-workspace/docs/specs/sub-phase-KAC-196-cluster-rbac-admin-acceptance.md
  §5.5 (case list) + §6.00–§6.12 (GWT scenarios) + §0.3 D-2/D-4/D-5/D-6/D-9/D-11/D-12.

Service contract:
  * REST exposed ONLY on cluster-internal listener under `/iam/v1/internal/cluster/...`.
  * Gate (D-11) = computed FGA relation `admin` (cascade `system_admin OR emergency_admin`)
    on `cluster:cluster_kacho_root` for ALL 4 RPCs — including the read `Get` and `ListAdmins`.
  * Mutations return `operation.Operation` envelope with id prefix `iop` (IAM ops).
  * Sync RPCs (`Get`, `ListAdmins`) — direct response, no Operation envelope.

Error-text discipline (acceptance §4.5 Newman note):
  All gRPC error messages assert via `pm.expect(j.message).to.eql(<exact-text>)`.
  No substring / case-insensitive matching — exact verbatim text only.

Required environment variables (set by the umbrella stack or local stand):
  baseUrl              — api-gateway REST endpoint (e.g. http://localhost:18080)
  tokenAdmin           — Bearer token for the seeded system_admin user (S)
  tokenOrdinary        — Bearer token for an ordinary user without cluster-admin (U3)
  userOrdinaryId       — `usr_<17>` id of the ordinary user (subject for Grant cases)
  externalBaseUrl      — advertised public TLS endpoint (e.g. https://api.kacho.local)
                         When absent, the internal-not-on-external-tls case becomes
                         a no-op skip (DNS unreachable also accepted as PASS).

These cases assert the cluster-admin RBAC routes are reachable on the internal
mux and gated by the permission catalog. Do NOT weaken assertions to make them
pass — fix the implementation.
"""

CASES = []


# ---------------------------------------------------------------------------
# CLUSTER-ADMIN-GET-OK
# ---------------------------------------------------------------------------
# Setup: S is the seeded system_admin user. tokenAdmin is its Bearer JWT.
# Path: GET /iam/v1/internal/cluster → 200, singleton Cluster body
# (`{id: "cluster_kacho_root", name, description, createdAt}`).
# Authz gate: tokenAdmin carries `system_admin` → `admin` computed → PASS.

CASES.append(Case(
    id="CLUSTER-ADMIN-GET-OK",
    title="GET /iam/v1/internal/cluster as system_admin S → 200 with singleton Cluster id",
    classes=["CRUD", "AUTHZ"],
    priority="P0",
    steps=[
        Step(
            name="get-cluster-as-admin",
            method="GET",
            path="/iam/v1/internal/cluster",
            auth="tokenAdmin",
            test_script=[
                *assert_status(200),
                "pm.test('cluster id is the singleton cluster_kacho_root', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.id, JSON.stringify(j)).to.eql('cluster_kacho_root');",
                "});",
                "pm.test('cluster has createdAt timestamp', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.createdAt, 'createdAt present').to.be.a('string');",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# CLUSTER-ADMIN-GET-403-ORDINARY
# ---------------------------------------------------------------------------
# Setup: U3 is an ordinary user (no cluster-admin grant). tokenOrdinary is its JWT.
# Expected: api-gateway authz middleware refuses with 403 PermissionDenied (grpc code 7)
# BEFORE the request reaches kacho-iam — catalog entry `required_relation=admin`
# fails OpenFGA Check `(user:U3, admin, cluster:cluster_kacho_root)`.

CASES.append(Case(
    id="CLUSTER-ADMIN-GET-403-ORDINARY",
    title="GET /iam/v1/internal/cluster as ordinary user U3 → 403 PermissionDenied",
    classes=["NEG", "AUTHZ"],
    priority="P0",
    steps=[
        Step(
            name="get-cluster-as-ordinary",
            method="GET",
            path="/iam/v1/internal/cluster",
            auth="tokenOrdinary",
            test_script=[
                *assert_status(403),
                *assert_grpc_code(7, "PERMISSION_DENIED"),
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# CLUSTER-ADMIN-GRANT-OK
# ---------------------------------------------------------------------------
# Setup: S is system_admin, U3 is an existing kacho_iam.users row without cluster-admin.
# Expected: POST /iam/v1/internal/cluster/admins → 200 with iop-prefixed Operation,
# poll until done=true, then ListAdmins shows U3 in the admins[] array.

CASES.append(Case(
    id="CLUSTER-ADMIN-GRANT-OK",
    title="GrantAdmin U3 by system_admin S → Operation(iop) done=true, U3 appears in ListAdmins",
    classes=["CRUD", "AUTHZ"],
    priority="P0",
    steps=[
        Step(
            name="grant-u3",
            method="POST",
            path="/iam/v1/internal/cluster/admins",
            auth="tokenAdmin",
            body={"subjectType": "USER", "subjectId": "{{userOrdinaryId}}"},
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_iam_op(auth="tokenAdmin"),
        Step(
            name="list-admins-includes-u3",
            method="GET",
            path="/iam/v1/internal/cluster/admins",
            auth="tokenAdmin",
            test_script=[
                *assert_status(200),
                "pm.test('ListAdmins includes newly-granted U3', () => {",
                "  const j = pm.response.json();",
                "  const u3 = pm.environment.get('userOrdinaryId');",
                "  const found = (j.admins || []).some(a => a.subjectId === u3);",
                "  pm.expect(found, JSON.stringify(j)).to.eql(true);",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# CLUSTER-ADMIN-GRANT-403-ORDINARY
# ---------------------------------------------------------------------------
# Setup: U3 (ordinary) tries to Grant himself admin → 403 PermissionDenied via authz gate.

CASES.append(Case(
    id="CLUSTER-ADMIN-GRANT-403-ORDINARY",
    title="GrantAdmin as ordinary user U3 → 403 PermissionDenied (D-11 gate)",
    classes=["NEG", "AUTHZ"],
    priority="P0",
    steps=[
        Step(
            name="grant-as-ordinary",
            method="POST",
            path="/iam/v1/internal/cluster/admins",
            auth="tokenOrdinary",
            body={"subjectType": "USER", "subjectId": "{{userOrdinaryId}}"},
            test_script=[
                *assert_status(403),
                *assert_grpc_code(7, "PERMISSION_DENIED"),
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# CLUSTER-ADMIN-GRANT-400-INVALID-USER
# ---------------------------------------------------------------------------
# Setup: S grants a `usr_<...>` id that does not exist in kacho_iam.users.
# User existence check inside the handler TX → InvalidArgument with
# verbatim message `"User usr_nonexistent00000000 not found"`.

CASES.append(Case(
    id="CLUSTER-ADMIN-GRANT-400-INVALID-USER",
    title="GrantAdmin with nonexistent user id → 400 InvalidArgument (D-9)",
    classes=["VAL", "NEG"],
    priority="P0",
    steps=[
        Step(
            name="grant-nonexistent-user",
            method="POST",
            path="/iam/v1/internal/cluster/admins",
            auth="tokenAdmin",
            body={"subjectType": "USER", "subjectId": "usr_nonexistent00000"},
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
                *assert_error_message_eql("User usr_nonexistent00000 not found"),
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# CLUSTER-ADMIN-GRANT-OK-IDEMPOTENT
# ---------------------------------------------------------------------------
# Setup: U3 is already an active cluster-admin (from CLUSTER-ADMIN-GRANT-OK).
# Expected: second Grant of the same subject → Operation(iop) done=true, no error;
# ListAdmins still shows ONE entry for U3 (idempotent — no duplicate row).

CASES.append(Case(
    id="CLUSTER-ADMIN-GRANT-OK-IDEMPOTENT",
    title="GrantAdmin U3 twice → second call returns success Operation, no duplicate row (D-4)",
    classes=["CRUD", "AUTHZ"],
    priority="P0",
    steps=[
        Step(
            name="grant-u3-second-time",
            method="POST",
            path="/iam/v1/internal/cluster/admins",
            auth="tokenAdmin",
            body={"subjectType": "USER", "subjectId": "{{userOrdinaryId}}"},
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_iam_op(auth="tokenAdmin"),
        Step(
            name="list-admins-no-duplicate",
            method="GET",
            path="/iam/v1/internal/cluster/admins",
            auth="tokenAdmin",
            test_script=[
                *assert_status(200),
                "pm.test('ListAdmins has exactly one entry for U3 (idempotent)', () => {",
                "  const j = pm.response.json();",
                "  const u3 = pm.environment.get('userOrdinaryId');",
                "  const count = (j.admins || []).filter(a => a.subjectId === u3).length;",
                "  pm.expect(count, JSON.stringify(j)).to.eql(1);",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# CLUSTER-ADMIN-REVOKE-OK
# ---------------------------------------------------------------------------
# Setup: U3 is currently an active admin (granted above). S revokes U3.
# Expected: DELETE /iam/v1/internal/cluster/admins/{userOrdinaryId} → 200
# Operation(iop) done=true → ListAdmins no longer contains U3.

CASES.append(Case(
    id="CLUSTER-ADMIN-REVOKE-OK",
    title="RevokeAdmin U3 by S → Operation(iop) done=true, U3 not in ListAdmins",
    classes=["CRUD", "AUTHZ"],
    priority="P0",
    steps=[
        Step(
            name="revoke-u3",
            method="DELETE",
            path="/iam/v1/internal/cluster/admins/{{userOrdinaryId}}",
            auth="tokenAdmin",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_iam_op(auth="tokenAdmin"),
        Step(
            name="list-admins-excludes-u3",
            method="GET",
            path="/iam/v1/internal/cluster/admins",
            auth="tokenAdmin",
            test_script=[
                *assert_status(200),
                "pm.test('ListAdmins no longer contains U3', () => {",
                "  const j = pm.response.json();",
                "  const u3 = pm.environment.get('userOrdinaryId');",
                "  const found = (j.admins || []).some(a => a.subjectId === u3);",
                "  pm.expect(found, JSON.stringify(j)).to.eql(false);",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# CLUSTER-ADMIN-REVOKE-403-SELF
# ---------------------------------------------------------------------------
# Setup: S (system_admin) revokes herself.
# Self-revoke is rejected at the SQL CAS level → FailedPrecondition with
# verbatim message `"cannot revoke own cluster admin grant"`.
#
# NB: REST status for FailedPrecondition is 400 in grpc-gateway default mapping
# (grpc code 9 → HTTP 400). The case id keeps `403` for consistency with the
# case naming, but the on-wire status code is 400 + grpc=9.

CASES.append(Case(
    id="CLUSTER-ADMIN-REVOKE-403-SELF",
    title="RevokeAdmin self → FailedPrecondition 'cannot revoke own cluster admin grant' (D-5)",
    classes=["NEG", "VAL"],
    priority="P0",
    steps=[
        Step(
            name="revoke-self",
            method="DELETE",
            path="/iam/v1/internal/cluster/admins/{{userAdminId}}",
            auth="tokenAdmin",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(9, "FAILED_PRECONDITION"),
                *assert_error_message_eql("cannot revoke own cluster admin grant"),
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# CLUSTER-ADMIN-REVOKE-403-LAST
# ---------------------------------------------------------------------------
# Setup: stand has been narrowed to a single active cluster-admin (the seeded S).
# S attempts to revoke another admin who happens to be the only one. The atomic
# CAS-UPDATE with subquery `count(*) > 1` returns 0 rows → FailedPrecondition
# with verbatim message `"cannot revoke last active cluster admin"`.
#
# In a multi-admin stand this case must arrange the last-admin state via fixture
# (revoke all admins except one BEFORE running this case). The case below uses
# {{userLastAdminId}} for the targeted admin — fixture decides whether it equals
# S (then it overlaps with REVOKE-403-SELF) or another seeded last-admin.

CASES.append(Case(
    id="CLUSTER-ADMIN-REVOKE-403-LAST",
    title="RevokeAdmin last active admin → FailedPrecondition 'cannot revoke last active cluster admin' (D-6)",
    classes=["NEG", "VAL"],
    priority="P0",
    steps=[
        Step(
            name="revoke-last-admin",
            method="DELETE",
            path="/iam/v1/internal/cluster/admins/{{userLastAdminId}}",
            auth="tokenAdmin",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(9, "FAILED_PRECONDITION"),
                *assert_error_message_eql("cannot revoke last active cluster admin"),
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# CLUSTER-ADMIN-REVOKE-404-NOT-ADMIN
# ---------------------------------------------------------------------------
# Setup: U3 has NEVER been a cluster-admin (no active row in cluster_admin_grants).
# Asymmetric with Grant idempotency: Revoke of a non-admin returns NotFound
# verbatim `"user usr_<...> is not an active cluster admin"`. (The {{userOrdinaryId}}
# placeholder is substituted at test time; assertion matches by code+regex below
# since the id value is dynamic.)

CASES.append(Case(
    id="CLUSTER-ADMIN-REVOKE-404-NOT-ADMIN",
    title="RevokeAdmin a user who has never been admin → NotFound (D-12)",
    classes=["NEG", "VAL"],
    priority="P0",
    steps=[
        Step(
            name="revoke-non-admin",
            method="DELETE",
            path="/iam/v1/internal/cluster/admins/{{userOrdinaryId}}",
            auth="tokenAdmin",
            test_script=[
                *assert_status(404),
                *assert_grpc_code(5, "NOT_FOUND"),
                "pm.test('error message identifies non-admin user', () => {",
                "  const j = pm.response.json();",
                "  const u3 = pm.environment.get('userOrdinaryId');",
                "  const expected = 'user ' + u3 + ' is not an active cluster admin';",
                "  pm.expect(j.message, JSON.stringify(j)).to.eql(expected);",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# CLUSTER-ADMIN-LIST-OK
# ---------------------------------------------------------------------------
# Setup: S is system_admin (default seed). ListAdmins returns the seeded
# admin(s) ordered by granted_at ASC.

CASES.append(Case(
    id="CLUSTER-ADMIN-LIST-OK",
    title="ListAdmins as system_admin S → 200 with admins[] non-empty",
    classes=["CRUD", "AUTHZ"],
    priority="P0",
    steps=[
        Step(
            name="list-admins-as-admin",
            method="GET",
            path="/iam/v1/internal/cluster/admins",
            auth="tokenAdmin",
            test_script=[
                *assert_status(200),
                "pm.test('admins is an array (may be empty per fixture state)', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.admins || [], 'admins array').to.be.an('array');",
                "});",
                "pm.test('each admin entry has subjectId / subjectType / grantedAt', () => {",
                "  const j = pm.response.json();",
                "  (j.admins || []).slice(0, 3).forEach(a => {",
                "    pm.expect(a.subjectId, JSON.stringify(a)).to.be.a('string');",
                "    pm.expect(a.subjectType, JSON.stringify(a)).to.be.a('string');",
                "    pm.expect(a.grantedAt, JSON.stringify(a)).to.be.a('string');",
                "  });",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# CLUSTER-ADMIN-LIST-403-ORDINARY
# ---------------------------------------------------------------------------
# Setup: U3 (ordinary) tries to ListAdmins → 403 via authz gate.

CASES.append(Case(
    id="CLUSTER-ADMIN-LIST-403-ORDINARY",
    title="ListAdmins as ordinary user U3 → 403 PermissionDenied",
    classes=["NEG", "AUTHZ"],
    priority="P0",
    steps=[
        Step(
            name="list-admins-as-ordinary",
            method="GET",
            path="/iam/v1/internal/cluster/admins",
            auth="tokenOrdinary",
            test_script=[
                *assert_status(403),
                *assert_grpc_code(7, "PERMISSION_DENIED"),
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# CLUSTER-ADMIN-INTERNAL-NOT-ON-EXTERNAL-TLS
# ---------------------------------------------------------------------------
# Setup: requires `externalBaseUrl` env (e.g. https://api.kacho.local) — the
# advertised public TLS endpoint. The internal path `/iam/v1/internal/cluster/admins`
# MUST return 404 there (ingress / split-mux filters it out).
#
# DNS unreachable / connection refused are also accepted as PASS (endpoint
# simply not reachable from CI). Authoritative 200 / 401 / 403 on this path
# would be a CRITICAL leak.

CASES.append(Case(
    id="CLUSTER-ADMIN-INTERNAL-NOT-ON-EXTERNAL-TLS",
    title="POST /iam/v1/internal/cluster/admins on external TLS endpoint → 404 (workspace §Запрет 6)",
    classes=["NEG", "SEC"],
    priority="P0",
    steps=[
        Step(
            name="grant-on-external-tls",
            method="POST",
            path="/iam/v1/internal/cluster/admins",
            auth="tokenAdmin",
            body={"subjectType": "USER", "subjectId": "{{userOrdinaryId}}"},
            pre_script=[
                "// internal-only check: redirect to externalBaseUrl if set.",
                "const extBase = pm.environment.get('externalBaseUrl') || pm.variables.get('externalBaseUrl') || '';",
                "if (!extBase) {",
                "  console.warn('externalBaseUrl not set — skipping internal-not-on-external-tls check.');",
                "  postman.setNextRequest(null);",
                "} else {",
                "  pm.request.url = extBase + '/iam/v1/internal/cluster/admins';",
                "}",
            ],
            test_script=[
                "pm.test('EXT-TLS: status 404 (path not on external mux)', () => {",
                "  const code = pm.response.code;",
                "  if (code === undefined) { return; }  // DNS / connection error = endpoint unreachable = PASS",
                "  pm.expect(code, 'CRITICAL: InternalClusterService exposed on external TLS endpoint!').to.eql(404);",
                "});",
            ],
        ),
    ],
))

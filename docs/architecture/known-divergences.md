# Known divergences — kacho-api-gateway

Deliberate, reviewed deviations from a general rule or from an audit
recommendation. Each entry states the rule, why the gateway diverges, and why it
is not a defect. New entries are added when an audit flags something we
consciously choose not to "fix".

## 1. Configuration via envconfig struct-tags (not YAML/viper/koanf)

**Rule (evgeniy regime).** Service configuration should be loaded from a
hierarchical YAML file via viper/koanf with a typed nested schema and env-var
overlay, rather than flat environment variables bound through `envconfig` struct
tags.

**Gateway state.** `internal/config/config.go` is populated from ~60 environment
variables via `corelib corecfg.Load` with `envconfig:` struct tags.

**Why this is not a gateway defect.** This is a **workspace-wide platform
convention**, not a gateway-specific choice: every kacho-* service uses
`corelib corecfg.Load` with envconfig tags, and there is no YAML config
infrastructure anywhere in the workspace. Config shape is a horizontal,
cross-cutting concern owned by `kacho-corelib`, and 12-factor env-var config is
the deployment contract the Helm charts and the dev stack are built around.
Migrating a single service to YAML in isolation would fragment the platform and
break the shared `corecfg` loader. If the platform adopts the YAML regime, the
migration is a workspace-wide change to `kacho-corelib`'s config loader (all
services move together) — tracked at the platform level, not here.

**Mitigation for the "easy to mis-set a toggle" concern.** The loader is
fail-fast: mismatched/missing mTLS/authz env vars are caught at process start,
not at request time. The gateway does not silently run with a half-set security
toggle.

**Sub-concern: a misspelled env var is silently ignored, and the external-edge
relaxed-posture check is a WARN, not a fatal, outside prod-labelled envs.**
`envconfig` binds by exact name and ignores names it does not recognise, so a
fat-fingered `KACHO_API_GATEWAY_AUTHZ_ENABLE` (missing `D`) leaves
`AuthZEnabled` at its default. Two compensating controls already exist and are
deliberate:

- `validateProductionAuthzConfig` (main.go, keyed on `KACHO_APP_ENV`) **fatally**
  refuses to start a prod-class deploy with disabled/relaxed authz.
- For deploys that forget to set `KACHO_APP_ENV` (empty → dev-class) while
  exposing the **external advertised TLS edge**, main.go emits a loud startup
  `WARN` (SECURITY: external TLS edge enabled with a relaxed auth posture),
  independent of the env label. This is intentionally a WARN and not a fatal:
  the external listener can be legitimately fronted by a dev/local stack with a
  self-signed cert and relaxed auth for iteration, and hard-failing that case
  would break the documented dev workflow. The fatal guard is reserved for the
  explicit prod-class signal (`KACHO_APP_ENV`), which is the contract operators
  set for production. Making the external-edge case fatal regardless of env
  label is a deployment-policy change (would break dev stacks that expose TLS),
  not a gateway-code defect.

Rubric reference: envconfig-vs-YAML (evgeniy); CWE-1188. Contract impact: none.

## 2. One in-process cache intentionally NOT folded into `internal/lrucache`

The audit recommended consolidating the hand-rolled TTL+LRU caches into one
generic primitive. Five now share `internal/lrucache` (authz decision cache,
subject cache, DPoP replay cache, introspection cache, and — as of
sec-hardening-r9b — the `KratosClient` whoami cache). One is **deliberately left
separate** because forcing it onto the primitive would change its semantics, not
just its mechanics:

### 2a. `IdempotencyStore` (internal/middleware/idempotency.go)

- **Divergent semantics:** FIFO insertion-order eviction (NOT LRU — a replay
  read must not extend an idempotency record's lifetime) **plus** an atomic
  single-flight reservation (leader/follower flights) that has no analogue in a
  plain key/value cache. Its value type also carries HTTP status/body/headers
  and a body-size cap.
- **Why separate:** the single-flight admission path (`reserve` /
  `finishLeader` / `abortLeader`) and FIFO eviction are the whole point of this
  component; the generic LRU would either need to absorb single-flight (bloating
  a general primitive with a one-caller concern) or the store would lose its
  exactly-once guarantee. Kept as a focused component.

### Migrated (was 2b): `KratosClient` whoami cache

The whoami cache previously hand-rolled two maps (positive / negative) with
bespoke `evictLocked` / `enforceCapLocked` cap enforcement. It now uses a single
`lrucache.Cache[string, kratosCacheEntry]` where the positive/negative class is a
field on the value (`active`) and the dual TTL (positive 30s, negative 5s) is
expressed per entry via `PutWithTTL`. The attacker-controlled-cookie keyspace is
still bounded by the primitive's hard cap (`kratosCacheMaxEntries`). The earlier
"dual-TTL split-cache needs two primitives" rationale did not hold: one keyed
value + `PutWithTTL` covers it, so the eviction/cap path is now tested exactly
once in `internal/lrucache`.

Rubric reference: kacho-corelib reuse principle. Contract impact: none —
unexported, in-process, no wire/API/DB change.

## 3. Per-pod in-memory idempotency & DPoP-replay state under HPA (accepted residual)

**Rule (project-rule #10 spirit).** A within-domain invariant should be enforced
at a layer that spans the whole concurrency domain, not a per-process software
check. `IdempotencyStore.reserve()` (single-flight, exactly-once per
`Idempotency-Key`) and `DPoPReplayCache` (RFC 9449 §11.1 anti-replay on `jti`)
are both correct **within one process** (atomic reserve / `AddIfAbsent`), but the
concurrency domain is the whole gateway fleet — and the shipped chart enables HPA
(`autoscaling.enabled=true`, `maxReplicas: 10`), so the domain spans N pods.

**Why the gateway keeps per-pod state (for now).**

- **No shared store is provisioned.** Backing these with Postgres/Redis
  (`INSERT … ON CONFLICT DO NOTHING` for idempotency; `SET NX` with TTL for
  `jti`) is a genuinely correct fix but adds a hard runtime dependency and a
  per-request round-trip to the request-side bottleneck (~3500 RPS/pod). That is
  a deliberate infra decision, tracked separately — not something to bolt on
  silently under this hardening pass.
- **Capping `maxReplicas: 1` is worse.** api-gateway is the documented RPS
  bottleneck; forcing a single replica to "restore" the store's precondition
  trades a correctness edge case for a hard availability/capacity regression.

**Accepted residual + compensating controls.**

- *Idempotency:* two same-key double-submits that land on different pods each
  become a leader → duplicate downstream mutation. This is bounded to genuine
  concurrent double-submits of the **same** key racing across pods within the TTL
  window; the common single-client-retry case still hits one pod (keep-alive /
  L7 affinity) and dedups. The downstream resource services remain the real
  exactly-once authority via their own DB-level invariants (FK / partial-UNIQUE /
  atomic CAS, project-rule #10) — the gateway store is a latency/UX optimisation,
  not the integrity boundary.
- *DPoP replay:* a captured proof can be replayed at most once per replica that
  has not yet seen its `jti`, bounded by the 60s `iat`-freshness window (cache
  TTL = 2× that). Replay is capped at ~N (live replicas), not unbounded, and only
  within one freshness window.

**Path to full fix (when provisioned):** move both to a shared low-latency store
(idempotency: `INSERT … ON CONFLICT DO NOTHING` keyed on
`(principal,method,path,key)` with `RETURNING` to elect leader vs follower; DPoP:
`SET NX` with TTL = freshness window), or pin same-key/same-`jti` requests to one
pod via consistent-hash sticky routing.

Rubric reference: project-rule #10 (concurrency-domain enforcement); CWE-362 /
CWE-294. Contract impact: none — internal in-process state only; no wire/API/DB
change. The `deploy/values.yaml` autoscaling block documents this residual inline.

## 4. `main()` is a long composition root (single wiring site, by design)

**Rule (Go clean-code / McCabe).** A ~700-line function with dozens of
`if … { log.Fatalf }` startup branches is a high-cognitive-load signal; an audit
recommended extracting `buildBackends` / `buildExternalListener` /
`buildInternalListener` / `buildHTTPServer` helpers.

**Gateway state.** `cmd/api-gateway/main.go`'s `main()` wires the whole process
inline: backend dials, mTLS creds, IAM clients, JWT/DPoP/introspection setup,
authz middleware, REST mux, internal + external gRPC listeners, HTTP server and
graceful shutdown.

**Why this is not a gateway defect.** The workspace architecture rule
(`.claude/rules/architecture.md`) designates `cmd/<svc>/main.go` as the
**single composition root** — *"единственное место wiring"* — and explicitly
bans wiring/singletons leaking out of `cmd/`. Keeping the wiring literally in one
sequential `main()` is the intended shape: the security-critical **ordering** of
listener/interceptor registration (authz before/after DPoP, internal-vs-external
listener setup) is easiest to audit as one linear top-to-bottom read rather than
scattered across helper constructors that hide the sequence behind call sites.
The function is branch-heavy but not logic-heavy: nearly every branch is a
`log.Fatalf` fail-fast guard, not business logic. Splitting it would move code
without reducing the essential wiring complexity, and would risk exactly the
mis-ordering the audit worries about by making the order implicit. If the wiring
grows further, extraction is revisited — but a long *composition root* is a
deliberate, reviewed shape, not a defect.

Rubric reference: architecture.md (composition root); CWE-1121. Contract impact:
none — no behavior/wire/API/DB change.

## 5. `X-Forwarded-For` trusted by default (`client_ip` for FGA conditions)

**Rule (secure-by-default / CWE-348).** An audit noted that honouring
`X-Forwarded-For` / `X-Real-IP` by default (`KACHO_API_GATEWAY_AUTHZ_TRUSTED_XFF`
default `true`, `…_TRUSTED_PROXY_COUNT` default `1`) is a "less-trusted source"
if the gateway is ever reachable without a trusted L7 hop inserting the rightmost
XFF entry — a client could then forge `client_ip` and satisfy CIDR-scoped FGA
conditions (`source_ip_in_range`).

**Gateway state.** The parser reads the forwarded chain **from the right** with
`TRUSTED_PROXY_COUNT` hops, so a client-forged *leftmost* XFF cannot drive
`client_ip` in the intended ingress topology (an L7 LB appends the real peer as
the rightmost entry). The residual risk is only a topology change that removes
the trusted proxy (direct-to-Service / port-forward).

**Why the default stays `true` (not flipped here).** The deployed shape
(`kacho-deploy`) always fronts the gateway with an ingress that appends XFF;
FGA conditions such as `source_ip_in_range(client_ip, …)` depend on that derived
`client_ip`. Flipping the Go default to `false` would silently make `client_ip`
the TCP peer (the ingress pod IP) for the standard deploy, breaking those
conditions, unless the deploy chart is simultaneously changed to set
`…_TRUSTED_XFF=true` — a coordinated cross-repo change (`kacho-deploy`) outside
this repo's blast radius. The knob is first-class and documented on the config
field: operators running the gateway **directly on the wire** MUST set
`KACHO_API_GATEWAY_AUTHZ_TRUSTED_XFF=false` (or `…_TRUSTED_PROXY_COUNT=0`) so the
TCP peer is authoritative. Tightening the default to fail-closed is tracked for
the release that lands the matching `kacho-deploy` overlay change.

Rubric reference: CWE-348 / CWE-290; security.md. Contract impact: none — no
wire/API/DB change; behavior governed by existing env knobs.

## 6. Backend-dial transport mTLS is per-edge opt-in (not startup-enforced); mesh-terminated in the prod profile

**Rule (security.md #1).** Every service→service hop must be mTLS (verified client
cert); plaintext/insecure-gRPC in prod is banned. An audit noted that
`validateProductionAuthzConfig` fails closed on authz/authn posture but never
checks that any backend-dial mTLS edge (`KACHO_API_GATEWAY_MTLS_*_ENABLE`, all
default `false`) is enabled, nor that the external TLS listener is configured
(`KACHO_API_GATEWAY_TLS_LISTEN_ADDR` default empty) — so a prod-class deploy that
forgets the mTLS overlay boots and dials every backend (incl. `iam:9091` /
`AuthorizeService`) over insecure gRPC with no startup error.

**Identity-trust corollary (sec-hardening-r8b).** A follow-up audit sharpened the
concern: the gateway→backend hops carry the gateway-derived trusted identity
headers `x-kacho-principal-*` and `x-kacho-token-acr`
(`internal/restmux/mux.go buildPrincipalMetadata`), and iam trusts the forwarded
`acr` floor *only because* it arrives on the verified gateway edge. If that hop
runs plaintext, a workload on the pod network could sniff/inject those headers and
impersonate an arbitrary principal or forge a satisfied ACR floor. This does not
change the disposition: the trust assumption is discharged by the **transport
security of the hop**, which in the shipped profile is provided by the service
mesh (sidecar mTLS) — so header injection on the wire is not possible even with
app-level `MTLS_IAM_ENABLE=false`. A mesh-less deployment MUST enable the per-edge
flag (see Compensating controls) precisely so the identity headers are not
forwarded over an unauthenticated hop.

**Gateway state.** Backend-dial transport is a per-edge overlay
(`cmd/api-gateway/mtls_config.go`): each edge (vpc / compute / iam / nlb / geo /
registry) is independently enabled via its `MTLS_<EDGE>_ENABLE` flag. The build is
**fail-fast when an edge is enabled but its cert material is missing/partial**
(`buildBackendDialCreds` → `main.go log.Fatalf`), so the process never comes up
half-secured on a configured edge. With every edge disabled (the default), every
dial is insecure — identical to dev. The shipped prod profile
(`kacho-deploy values.prod.yaml`) does **not** set any
`KACHO_API_GATEWAY_MTLS_*_ENABLE`.

**Why a hard app-level startup guard is NOT added here.** The deployed prod
topology terminates inter-pod transport security at the **service mesh** (sidecar
mTLS), not in the application: the app legitimately dials plaintext to its local
sidecar and the mesh wraps the hop transparently. In that model app-level
`MTLS_*_ENABLE=false` is the correct, secure posture. A startup guard that fatally
required app-level backend mTLS in prod-class envs would break `values.prod.yaml`
(which does not enable it) and every mesh-based deployment — it would hard-code one
deployment-topology assumption (app-terminated mTLS) and reject the other
(mesh-terminated). This is the deliberate reason the **internal listener** guard
(`validateProductionInternalListener`) is asymmetric with backend dials: that
listener enforces an app-level **SPIFFE caller allow-list**, which requires the app
to see the verified client cert — a decision the mesh cannot make for it — so
app-level mTLS there is functionally required; backend dials need only transport
security, which the mesh provides.

**Compensating controls.** (a) fail-fast on any *enabled* edge with missing cert
material; (b) the internal listener hard-requires mTLS + SPIFFE allow-list in prod
(`validateProductionInternalListener`); (c) `main.go` emits a loud startup WARN when
the external advertised TLS edge runs with a relaxed auth posture. Operators who run
the gateway **without a mesh** (direct pod-to-pod) MUST enable the per-edge
`KACHO_API_GATEWAY_MTLS_*_ENABLE` flags + cert material; promoting this to a fatal
guard is tracked for the release that lands a mesh-vs-app transport-policy signal in
`kacho-deploy` (so the guard can distinguish "mesh handles it" from "misconfigured"
instead of over-constraining the prod profile).

Rubric reference: security.md #1; CWE-319 / CWE-1188. Contract impact: none — no
wire/API/DB change; behavior governed by existing per-edge env knobs.

## 7. Internal admin REST listener (`:8081`) has no app-level transport auth (mesh + NetworkPolicy isolated)

**Rule (security.md #1).** Internal listeners are not a trusted zone: every
listener — public AND internal — should enforce mTLS transport plus a per-RPC
authorization decision. An audit noted that the dedicated cluster-internal admin
REST listener (`KACHO_API_GATEWAY_INTERNAL_REST_ADDR`, default `:8081`) — the only
listener that serves `Internal*` REST (addressPools, `:internal` infra-sensitive
Network projections, InternalRegistry/Cluster/Operations,
`InternalUserService.UpsertFromIdentity`) — terminates plaintext HTTP: its origin
is marked purely by listener wrapping (`listenerorigin.InternalConnContext`) and
`<exempt>` Internal RPCs are admitted on it without authN. Unlike the internal
**gRPC** listener (`internal_grpc_security.go`: mandatory mTLS + SPIFFE allow-list
+ production guard), it has no app-level transport authentication.

**Why the internal gRPC listener enforces app-level mTLS but this REST listener
does not.** The asymmetry is deliberate and identical to the one in §6. The
internal gRPC listener makes an app-level **SPIFFE caller allow-list** decision
(only the iam push-drainer identity may flush the authz decision-cache) — that
requires the app itself to see the verified client cert, which a mesh cannot
decide for it, so app-terminated mTLS there is functionally required. The internal
REST listener makes **no such per-caller cert decision**: it is an admin-plane
surface reached by the UI / admin-tooling / `kubectl port-forward`, where
distributing and pinning client certs to browsers and operators is impractical.
Its transport security is therefore provided the same way as every other
backend hop in the shipped profile — by the **service mesh** (sidecar mTLS) — plus
**NetworkPolicy** restricting who can reach `:8081` at all.

**Compensating controls (defence-in-depth, not network-only).**

- The listener shares the one `httpSrv` handler chain, so every request on it
  still traverses `authInterceptor.HTTP` → DPoP → `authzMW.HTTP`. Non-exempt
  `Internal*` REST calls are subject to the same per-RPC authz `Check` as any
  other request; only the small `phaseInternalOriginExempt` set (identity
  bootstrap RPCs that necessarily run before a principal exists) is admitted
  without authN, and those are admitted *only* on the internal-origin-marked
  listener — never on the external edge (fail-closed origin default).
- The infra-sensitive Network `:internal` projections and admin `Internal*`
  surfaces are unreachable from the external listener regardless of NetworkPolicy
  (origin marker fail-closes to external → 404), so a NetworkPolicy miss exposes
  them only to in-cluster peers that can already reach `:8081`, not the internet.

**Why not add app-level mTLS termination here now.** Standing up a second
TLS-terminating `http.Server` (separate `tls.Config` with
`RequireAndVerifyClientCert`) for the admin REST surface hard-codes the
app-terminated-mTLS topology and breaks the mesh profile and the port-forward
admin workflow — the same over-constraint §6 documents for backend dials.
Promoting the internal admin surfaces to app-level mTLS is tracked for the release
that lands the mesh-vs-app transport-policy signal in `kacho-deploy` (so the guard
can tell "mesh handles it" from "misconfigured").

Rubric reference: security.md #1/#6; CWE-306. Contract impact: none — no
wire/API/DB change; posture governed by mesh + NetworkPolicy + the existing
origin-marker fail-closed default.

## 8. Resource-id extractor fails closed to the wildcard scope (no error channel)

**Rule (CWE-390 / observability).** An audit noted that `phaseResource`
(`internal/middleware/authz.go`) calls `Resources.ExtractFromHTTP(...)` /
`ExtractFromProto(...)` discarding the second return (`resourceID, _ = …`), so an
extraction miss is neither logged nor distinguished and could surface to operators
as an opaque `PermissionDenied`.

**Gateway state (why this is by design, not a dropped error).** The extractor's
second return is an `ok bool` documented as "no error", **not** an error value —
and it is `true` on every code path (`resource_extractor.go`). Extraction never
*fails*: a named field that is absent, empty, or on a non-proto request resolves
to the FGA wildcard `"*"` (List/Search scope), which is the intended fail-closed
result — a wildcard on a concrete-resource RPC is denied at the FGA `Check` (no
path), never silently allowed. There is deliberately no empty-id path: the only
branch that could once return `""` was the stdlib-reflect fallback for non-proto
requests, removed in sec-hardening-r8b (the production authz path always hands the
extractor a `proto.Message`), so `resourceID` is now always either a concrete id
or `"*"`.

**Why no extra logging is added.** A wildcard result is indistinguishable from a
legitimate List/Search RPC (which is *supposed* to scope to `"*"`), so logging
"extraction produced a wildcard" would fire on every List call — noise, not
signal. The one genuinely diagnosable input error — a syntactically **malformed**
concrete id — is already logged and surfaced as `InvalidArgument`/400 by the
malformed-id short-circuit (`authz.go`, `corevalidate.ResourceID`), before the FGA
`Check`. The remaining "wildcard → deny" path is a correct authz outcome, not a
maskable failure.

Rubric reference: CWE-390. Contract impact: none — no wire/API/DB change.

## 9. `authz.go` / `auth.go` are single large same-package files (not split by concern)

**Rule (Go clean-code / project-rule #11).** An audit flagged
`internal/middleware/authz.go` (~950 LOC) and `internal/middleware/auth.go`
(~780 LOC) as oversized multi-responsibility files (HTTP + gRPC unary/stream
interceptors, catalog lookup, subject resolution, resource scoping, caching and
Check dispatch each), on the highest-blast-radius security decision path.

**Why this is not treated as a defect.** The two files are already decomposed
*internally* into small, single-purpose phase functions
(`phaseCatalog` → `phaseSubject` → `phaseResource` → `phaseCheck`, plus the
HTTP/gRPC entry adapters), so the cognitive unit is the phase, not the file. The
audit's own proposed fix is a pure **file-move** (`authz_phases.go` /
`authz_http.go` / `authz_grpc.go`) with no behavior change and identical exported
`AuthzMiddleware` API. On the single most security-sensitive code path, a large
mechanical churn that touches every line's location — inflating the review diff
and colliding with other in-flight security branches — carries more regression
and review-miss risk than the maintainability signal it addresses, for zero
behavioral benefit. The decomposition that matters (per-phase functions, each unit
testable) is already present. A physical split is revisited if these files grow a
genuinely new concern rather than another phase of the existing pipeline.

Rubric reference: project-rule #11; CWE-1121. Contract impact: none — no
behavior/wire/API/DB change. (Confidence of the original finding: low.)

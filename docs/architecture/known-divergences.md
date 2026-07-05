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

## 2. Two in-process caches intentionally NOT folded into `internal/lrucache`

The audit recommended consolidating the six hand-rolled TTL+LRU caches into one
generic primitive. Four now share `internal/lrucache` (authz decision cache,
subject cache, DPoP replay cache, introspection cache). Two are **deliberately
left separate** because forcing them onto the single-TTL LRU primitive would
change their semantics, not just their mechanics:

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

### 2b. `KratosClient` whoami cache (internal/middleware/kratos_session.go)

- **Divergent semantics:** two separate maps (positive and negative results)
  with **different TTLs** (positive 30s, negative 5s) and a combined hard cap
  across both — a dual-TTL split-cache, not a single-TTL LRU. Keyed on the
  attacker-controlled full Cookie header, so the combined-cap eviction is a
  memory-safety control, not a recency optimisation.
- **Why separate:** the generic primitive is single-TTL; expressing "positive
  entries live 6× longer than negative entries, bounded by one shared cap" would
  require two primitives plus bespoke cross-cap coordination, which is more code
  and more surface than the current focused implementation.

Rubric reference: kacho-corelib reuse principle. Contract impact: none — both are
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

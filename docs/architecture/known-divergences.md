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

Rubric reference: envconfig-vs-YAML (evgeniy). Contract impact: none.

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

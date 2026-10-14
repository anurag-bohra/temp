# @rtk/provider-router

Deterministic provider registry and session router modelled on REA's `AnalysisProviderRegistry` / `SessionProviderRouter` / `BinarySession` (independent re-implementation, not a port of the source).

## What it does
- `AnalysisProvider` interface (id, name, version, kind `deep|auxiliary`, `supports`, `profile`, `open`, `close`, `call`, `operations`).
- `Registry`: candidates sorted by id (registration order is irrelevant). `auto` = first supporting deep provider by id. An explicit provider that is unknown, auxiliary, unsupported or unavailable is an error (`ProviderSelectionError`); there is **no fallback**. Auxiliary operations must be disjoint from each other and from every deep provider's operations (`RegistryConfigError`).
- `BinarySession`: one immutable (deep-frozen) binding per target sha256 + provider + profile digest, serialised open/close. Reopen of the same identity returns the same binding (`reused: true`); anything else throws until `close()`. Auxiliary providers that support the target are opened alongside and routed by operation name; they cannot override the deep binding.
- Evidence on bind: provider `rtk-provider-router`, operation `bind_provider`, predicate `analysis_provider_binding`, created with `createEvidence`.
- `capabilities()` inventory; `importSnapshot()` requires target sha256, concrete provider id and profile digest to match exactly (`SnapshotIdentityError`).
- Concurrency: register a factory (`() => provider`) to give each session its own instance. A plain instance can serve one session at a time (a second concurrent open throws).

## Verification
`npm test`: fake-provider tests for registration-order independence, deterministic auto selection, no-fallback on explicit failure, binding immutability, switching rules, reuse, auxiliary routing and conflicts, snapshot identity mismatch, evidence content, concurrent sessions on two targets, open-failure rollback.

## Not implemented
No lazy loading, no snapshot cache/persistence, no environment-default selector, no cancellation signals, no per-operation capability schemas (REA has these).

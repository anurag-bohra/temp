# @rtk/unknowns
Residual-Unknown registry: immutable revisions chained by digest, optimistic concurrency (`expected_revision`), evidence-qualified resolution.
`unknown_id` and `revision_digest` rules are byte-compatible with REA (verified on a real REA unknown). The rule for *which Evidence may close an Unknown* (authority equal, confidence ≥ required, environment/isolation ≥ required) is this package's implementation of the behaviour observed in REA, not a copy of REA's code.
**Verified (tests):** REA unknown parses and re-exports; tampering rejected; a `controlled-replay` + `virtual-machine` Unknown is refused static, process-isolation, and accepted only with VM-level replay evidence.

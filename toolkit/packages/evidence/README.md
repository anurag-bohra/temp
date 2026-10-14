# @rtk/evidence
REA-compatible Evidence envelope (zod), RFC 8785-style canonical JSON, deterministic `evidence_id`, in-memory deduplicating `EvidenceLedger`, and canonical Evidence bundles.
**Verified (tests):** all 26 Evidence IDs in a real REA bundle are reproduced; tampering is rejected; importing REA's exported bundle and exporting it again is **byte-identical**.
**Not done:** persistence (see `@rtk/triage` `CaseStore`), signing/attestation, streaming for very large bundles.

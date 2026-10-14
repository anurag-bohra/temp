# rea-toolkit (independent implementations of the 13 porting blueprints + triage layer)

Defensive malware-triage / vulnerability-research toolkit designed in `../docs/deep-dive/24-porting-blueprints.md`. TypeScript run directly by Node 22 (type stripping); `npm install && npm test`; `npx tsc --noEmit -p tsconfig.json` is clean at the last run.

## Status at last run: all 14 packages, 201 tests pass, 0 fail (1 skipped inside `sandbox` when a host capability is missing); `npx tsc --noEmit -p tsconfig.json` clean
| Package | Blueprint | Tests | Verification / state |
|---|---|---|---|
| `evidence` | 02 Evidence/ledger/bundle | 6 | Reproduces all 26 real REA Evidence IDs; REA's exported bundle round-trips byte-identically |
| `effects` | 01 ToolEffects + policy | 6 | Derived annotations = advertised for all 207 REA tools; policy profiles; verified audit-gap overlay |
| `unknowns` | 03 Unknown registry | 7 | REA-compatible ids/digests (real REA unknown validated); lifecycle + evidence-qualified resolution |
| `provider-router` | 05 registry/router | 13 | Deterministic selection, no fallback, immutable binding (no lazy load / snapshot cache / cancellation) |
| `ghidra-bridge` | 06 Ghidra bridge | 14 | Real Ghidra 12.1.4; matches REA's results on the same samples; x86-64 ELF/Linux only; `xrefs` = strings + direct calls |
| `hopper-bridge` | 07 Hopper bridge | 12 | **Skeleton, unverified against real Hopper** (fake-server tests only) |
| `prompts-skills` | 08 prompts + skills | 8 | REA's six prompts render byte-identically to real REA output; 4 toolkit prompts, 2 skills, installer |
| `js-analyzer` | 09 JS/Electron analyzer | 17 | Sinks, taint flows (IPC arg -> exec, network response -> eval), web preferences, IOCs; cross-checked with REA output. Not independently reviewed |
| `dotnet-analyzer` | 10 .NET analyzer | 8 | Metadata/IL/literals/P-Invoke, per-method literal diff (REA's blind spot). Not independently reviewed |
| `artifacts` | 11 archive inspector/extractor | 31 | Zip/tar/asar; zip-slip, symlink, bomb, quota tests. Not independently reviewed |
| `browser-observer` | 12 browser observer | 19 | Egress-allowlisted headless Chromium; runs with `--no-sandbox` as root (see its README). Not independently reviewed |
| `sandbox` | 13 sandboxed runner | 14 (+1 skip) | Process/namespace isolation, never a VM. Not independently reviewed |
| `mcp-gateway` | policy/untrusted-output gateway | 19 | Includes 5 live tests against the real REA server (tool hiding, path roots, injection envelope, audit chain) |
| `triage` | 14 triage layer | 27 | Full pipeline wired to js/dotnet/artifacts (recursive)/ghidra (opt-in)/sandbox (policy-gated, opt-in); STIX/MISP/CSV/MD; SQLite store |

## Remaining gaps
1. Hopper needs a real Hopper; Rizin/Cutter/IDA/JEB/Frida/adb bridges are not implemented.
2. Independent review of the five packages marked "not independently reviewed" (their implementers were stopped before a final pass).
3. Triage: no unpacking, no TI enrichment, indicative ATT&CK mapping, shallow PE/Mach-O depth; rules are indicator matches.
4. Nothing here has been tested on real malware or by a real LLM agent; samples are benign demos.

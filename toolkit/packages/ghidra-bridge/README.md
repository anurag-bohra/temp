# @rtk/ghidra-bridge

Real Ghidra headless integration. `analyzeBinary(path, opts)` runs Ghidra 12.1.4 `analyzeHeadless` with our own GhidraScript (`ghidra/RtkExport.java`) and returns a JSON `GhidraSnapshot`; `GhidraProvider` serves provider-router operations over that snapshot, each returning an `@rtk/evidence` record (provider `rtk-ghidra-bridge`).

## API
- `analyzeBinary(path, opts?) -> Promise<GhidraSnapshot>`. Options: `installDir` (default env `GHIDRA_INSTALL_DIR`, then `/opt/lab/ghidra_12.1.4_PUBLIC`), `timeoutMs` (whole run, default 600000), `maxHeap` (env `GHIDRA_HEADLESS_MAXMEM`, default 2G), `decompTimeoutSec`, `decompBudgetSec`, `maxFunctions`, `maxSymbols`, `maxStrings`, `tmpRoot`.
- Safety: the target is copied (mode 0600) into a fresh 0700 temp dir with a throwaway project; the original is hashed before/after and never opened by Ghidra. `analyzeHeadless` runs in its own detached process group; on timeout the group gets SIGKILL, and the group is killed and checked for survivors after every run (`GhidraCleanupError` if any remain). The temp dir is always removed and removal verified. Errors: `GhidraNotFoundError`, `GhidraTimeoutError`, `GhidraFailedError` (with log tail), `GhidraCleanupError`.
- `GhidraProvider` (`id: "ghidra"`, kind `deep`): operations `binary_overview, list_procedures, procedure_info, list_strings, search_strings (literal|regex), xrefs, procedure_callers, procedure_callees, procedure_pseudo_code, analyze_function, trace_call_path`. `procedure` accepts a name or an address (entry or any address inside the body).
- Snapshot content: program info, entry points, memory blocks, functions (body ranges, signature, callers, callees, call sites with indirect/unresolved flags, stack variables), defined strings with xref sources, externals, symbols, decompiler pseudocode per non-external function (per-function timeout + global budget; skipped/failed functions are marked `truncated` with `error`) and decompiler locals (e.g. `char[32]`).
- `trace_call_path`: BFS over resolved direct calls. `goal_status` is `reached`, `not-reached`, or `unknown` (when the search was depth-limited or unresolved indirect calls make absence unprovable: forward = in any visited function, backward = anywhere in the program).

## Verification (`npm test`, ~1-2 min; needs Ghidra and the lab samples, otherwise those tests skip)
Real Ghidra on `samples/c/t` and `samples/vuln/weak`: main/check found; `198.51.100.7` string with xref from main; `check` pseudocode contains `ptrace`; `trace_call_path main->check` reached; `greet` pseudocode contains `strcpy` and `char local_28 [32]`; unknown procedure error; tiny timeout -> `GhidraTimeoutError`, no group members, temp dir gone, copy was 0600; non-binary input -> failure and cleanup; original hash unchanged; works inside `BinarySession`. Cross-check against REA's own Ghidra results (`docs/deep-dive/manual-tests/mcp-transcripts/t2.json`, skipped if absent): main 0x10125b and its body range, check 0x101229, string 0x102004, xrefs 0x1012da and 0x104010, callers of check, sample sha256 all equal. Call-graph status semantics are tested on a synthetic snapshot (no Ghidra).

## Not done / limits
- `xrefs` covers references to defined strings and direct call targets only (the exporter does not dump the full reference table).
- Linux only for the process-group check (`/proc`). One snapshot per `open`; no caching/persistence; analysis uses Ghidra default analyzers (no custom options, no `.gdt` archives).
- Tested on x86-64 ELF only. PE/Mach-O/other architectures and large binaries are untested; decompile budget/timeouts are the only guard against slow functions.
- Unlike REA, we do not apply any annotations/renames to the program (no `set_address_name`); the bridge is read-only.

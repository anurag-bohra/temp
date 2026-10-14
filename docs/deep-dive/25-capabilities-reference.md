# 25 — Capabilities reference (every family and tool, with malware-analysis use)

Generated from the built catalogs (207 tools, 18 families, 47 providers) with family narrative hand-written from the REA README "What you can analyze" table and chapter findings. Tool descriptions are the **verbatim text advertised to the agent** (these are what steer LLM tool selection). Full input schemas: [catalog/](catalog/); full specs: [tool-specs/](tool-specs/). Architecture: [02](02-architecture-and-module-map.md), [03](03-mcp-server-runtime-and-contracts.md). Flow of prompts/skill: [12](12-ai-layer-prompts-and-skills.md). Defensive use: [23](23-defensive-malware-analysis-playbook.md).

**Reading the tier column:** A = no flagged effects (parse/inspect only; most also record session Evidence); B = writes files or launches helper processes; C = mutates the target database/session state; D = executes foreign code (detonation tier — VM only); E = mutates an attached Android device. Tier is derived from the audited `ToolEffects` flags; known audit gaps are noted per family.

## 1. Family `direct` — surface `official-proxy` (41 tools)

**What it does.** The low-level analyst vocabulary on an open native target: documents, procedures, segments, names, strings, bytes, disassembly, pseudocode, xrefs, callers/callees, bookmarks/comments/renames.

**Requirements.** One deep provider: Hopper, Ghidra or IDA (bring-your-own; setup can install Hopper only with approval). Provider ops are served through the official-proxy surface.

**Malware-analysis use.** Core of static malware reverse engineering: string hunting, API-call xrefs, decompilation of suspicious functions, renaming/commenting to build up an annotated database. Read tools are tier A. `set_*`, `comment`, `inline_comment`, bookmark tools edit the engine database only (Ghidra DB is ephemeral).

**Safety on hostile samples.** Static; the engine parses the sample (run engine in an analysis VM).

| Tool | Tier | Session | Providers | CLI | Needs |
|---|---|---|---|---|---|
| `address_name` | A | N | ghidra, hopper | — | mutatesSession |
| `address_to_file_offset` | A | N | ghidra, hopper | `rea address-to-file-offset` | mutatesSession |
| `annotate_native_function` | C | N | ghidra | `rea annotate-native-function` | launchesProcess, mayDiscardData, mutatesSession, mutatesTarget, writesFilesystem |
| `comment` | A | N | hopper | — | mutatesSession |
| `current_address` | A | N | hopper | — | mutatesSession |
| `current_document` | A | N | hopper | — | mutatesSession |
| `current_procedure` | A | N | hopper | — | mutatesSession |
| `goto_address` | A | N | hopper | — | changesUiState, mutatesSession |
| `inline_comment` | A | N | hopper | — | mutatesSession |
| `inspect_native_data_type` | A | N | ghidra | `rea inspect-native-data-type` | mutatesSession |
| `inspect_native_instruction` | A | N | ghidra | `rea inspect-native-instruction` | mutatesSession |
| `inspect_native_load_image` | A | N | ghidra | `rea inspect-native-load-image` | mutatesSession |
| `list_bookmarks` | A | N | hopper | — | mutatesSession |
| `list_documents` | A | N | ghidra, hopper, ida | — | mutatesSession |
| `list_names` | A | N | ghidra, hopper | — | mutatesSession |
| `list_procedures` | A | N | ghidra, hopper, ida | — | mutatesSession |
| `list_segments` | A | N | ghidra, hopper | — | mutatesSession |
| `list_strings` | A | N | ghidra, hopper, ida | — | mutatesSession |
| `next_address` | A | N | hopper | — | mutatesSession |
| `prev_address` | A | N | hopper | — | mutatesSession |
| `procedure_address` | A | N | ghidra, hopper, ida | — | mutatesSession |
| `procedure_assembly` | A | N | ghidra, hopper, ida | — | mutatesSession |
| `procedure_callees` | A | N | ghidra, hopper, ida | — | mutatesSession |
| `procedure_callers` | A | N | ghidra, hopper, ida | — | mutatesSession |
| `procedure_info` | A | N | ghidra, hopper | — | mutatesSession |
| `procedure_pseudo_code` | A | N | ghidra, hopper, ida | — | mutatesSession |
| `procedure_references` | A | N | ghidra, hopper | — | mutatesSession |
| `read_bytes` | A | N | ghidra, hopper | `rea read-bytes` | mutatesSession |
| `read_function_instructions` | A | N | ghidra, hopper, ida | — | mutatesSession |
| `resolve_containing_procedure` | A | N | ghidra, hopper, ida | — | mutatesSession |
| `resolve_native_call_targets` | A | N | ghidra | `rea resolve-native-call-targets` | mutatesSession |
| `search_bytes` | A | N | ghidra | `rea search-bytes` | mutatesSession |
| `search_procedures` | A | N | ghidra, hopper, ida | — | mutatesSession |
| `search_strings` | A | N | ghidra, hopper, ida | — | mutatesSession |
| `set_address_name` | C | N | ghidra, hopper | — | mayDiscardData, mutatesSession, mutatesTarget |
| `set_addresses_names` | C | N | ghidra, hopper | — | mayDiscardData, mutatesSession, mutatesTarget |
| `set_bookmark` | C | N | hopper | — | mayDiscardData, mutatesSession, mutatesTarget |
| `set_comment` | C | N | hopper | — | mayDiscardData, mutatesSession, mutatesTarget |
| `set_inline_comment` | C | N | hopper | — | mayDiscardData, mutatesSession, mutatesTarget |
| `unset_bookmark` | C | N | hopper | — | mayDiscardData, mutatesSession, mutatesTarget |
| `xrefs` | A | N | ghidra, hopper, ida | `rea xrefs` | mutatesSession |

### Tool descriptions (verbatim)

**`address_name`** — Address Name

> Resolve the primary analyzed name at a code or data address. Headless providers require an explicit address; GUI providers may default to their current cursor. Null means the provider has no primary name at that address.

**`address_to_file_offset`** — Address To File Offset

> Map one provider-normalized virtual address to its original nonnegative file offset. Hopper verifies the original bytes against the selected executable digest and translates FAT image-relative offsets using the loaded header. Results preserve the provider coordinate, image base, and source path. Unmapped addresses fail explicitly; changed or unavailable sources return typed errors retaining native mapping facts as partial evidence.

**`annotate_native_function`** — Annotate Native Function

> Atomically update one function name and/or entry comments, read them back, and return a refreshed complete function dossier. Ghidra changes its ephemeral session analysis database only; original executable bytes remain unchanged. Empty comment text clears that comment. Edits remain available to subsequent MCP calls until close; CLI returns the updated dossier before discarding its session. Invalid edits roll back the entire operation. Windows P0 and providers without this capability are unsupported.

**`comment`** — Comment

> Read the regular analysis comment at an address, defaulting to the current cursor. This is read-only and returns null when no comment exists; use set_comment to persist a finding.

**`current_address`** — Current Address

> Return Hopper's current cursor address for the selected document. Use only for interactive navigation state; prefer explicit addresses in reproducible investigations.

**`current_document`** — Current Document

> Return the document currently selected by REA's Hopper bridge.

**`current_procedure`** — Current Procedure

> Return the analyzed procedure containing Hopper's current cursor. This uses GUI cursor state and is not a procedure-name lookup.

**`goto_address`** — Goto Address

> Move Hopper's GUI cursor to a mapped address and return the observed cursor address. Interior coordinates snap to the containing analyzed object's start. Unmapped destinations fail without moving the cursor. This changes navigation state but not analysis data; use explicit-address tools for headless workflows.

**`inline_comment`** — Inline Comment

> Read the inline instruction comment at an address, defaulting to the current cursor. Returns null when absent; use set_inline_comment to write one.

**`inspect_native_data_type`** — Inspect Native Data Type

> Inspect one recovered type by exact database category path or defined typed data address. Returns observed size, alignment, packing, fields, bitfields, enum values, and child type identities; source-level authority and flexible-tail semantics remain unknown unless substantiated.

**`inspect_native_instruction`** — Inspect Native Instruction

> Inspect one exact code or data address: decoded bytes, mnemonic, ordered operand tokens, flow, outgoing instruction references and typed incoming references where available. Incoming references preserve source, access kind, operand index and analysis provenance even at data addresses; they do not prove runtime access. Memory addressing decomposition is unavailable when the provider supplies only tokens. Data, interior instruction addresses and undecodable bytes are distinct outcomes.

**`inspect_native_load_image`** — Inspect Native Load Image

> Verify the provider's loaded DOS MZ or explicitly selected COM image against its immutable target snapshot: complete original/modified source-byte digests, header/module file mappings and memory digests, relocations and external entry. Returns measured observations and independent checks with mismatch coordinates. COM verification includes its imposed entry register context and does not claim PSP/runtime coverage. Overlay and uninitialized coverage remain explicit; other formats return unsupported. Does not execute or modify the target.

**`list_bookmarks`** — List Bookmarks

> List every bookmark in the selected Hopper document as address and name pairs; unnamed bookmarks retain a null name. Use bookmarks as analyst-authored navigation aids; this does not discover code references.

**`list_documents`** — List Documents

> List provider program or document identities. Hopper may expose several documents; a Ghidra headless session contains exactly its one imported Program.

**`list_names`** — List Names

> List every analyzed memory and external symbol as address/value pairs. Provider metadata distinguishes Ghidra primary, dynamic, external, type, and source facts when available.

**`list_procedures`** — List Procedures

> List every analyzed procedure as address/value pairs after provider analysis. Ghidra metadata distinguishes thunks and external functions; use returned addresses in later function operations.

**`list_segments`** — List Segments

> List segments or memory blocks using exclusive end addresses. Ghidra reports block permissions, address space, image base, initialization, and overlay facts; Hopper marks unavailable permissions explicitly.

**`list_strings`** — List Strings

> List every provider-defined string object, or filter to one address, as address/value pairs with encoding, terminator status, and byte length when available. Hopper reads complete typed objects and retains its original display text as provider_value; long literals may span adjacent unterminated objects.

**`next_address`** — Next Address

> Return the next analyzed object address after an explicit address or current cursor. This is a navigation primitive, not instruction-flow or CFG analysis.

**`prev_address`** — Prev Address

> Return the previous analyzed object start before an explicit address or current cursor. This is a navigation primitive and may fail at document boundaries; data objects and instructions remain distinct from control flow.

**`procedure_address`** — Procedure Address

> Resolve an unambiguous procedure symbol name or provider-normalized address to its canonical entry address. External address spaces remain explicit.

**`procedure_assembly`** — Procedure Assembly

> Return assembly for one analyzed procedure identified by symbol or hexadecimal address. Use when pseudocode loses calling-convention or instruction-level detail; output is currently returned as one unpaginated string. Ghidra terminal-call assumptions that may cut the analyzed body are reported in Evidence limitations.

**`procedure_callees`** — Procedure Callees

> Return the provider's resolved direct callees for one procedure identified by symbol or address. Unresolved indirect calls may be absent; use analyze_function and typed references to preserve available edge uncertainty. Ghidra terminal-call assumptions that may cut the analyzed body are reported in Evidence limitations.

**`procedure_callers`** — Procedure Callers

> Return the provider's resolved direct callers for one procedure identified by symbol or address. Results reflect completed static analysis and may omit unresolved indirect references. Ghidra terminal-call assumptions that may cut the analyzed body are reported in Evidence limitations.

**`procedure_info`** — Procedure Info

> Return provider metadata for one procedure identified by symbol or address: entrypoint, signature, locals, size, block count, and complete inclusive body ranges when observed. Extents reflect the provider's analyzed body; Ghidra terminal-call assumptions that may cut it are reported in Evidence limitations. Hopper locals preserve observed names and signed stack displacements; source types remain unknown. Body byte count and enclosing span remain distinct; unavailable extent is explicit.

**`procedure_pseudo_code`** — Procedure Pseudo Code

> Decompile one analyzed procedure by symbol name or provider-normalized address. Ghidra also accepts file-offset:0x... selectors and falls back to a unique source-file mapping when a 0x-prefixed number resolves to no procedure; existing analysis addresses take precedence and ambiguous mappings fail explicitly. Returns provider-specific pseudocode, never original source or cross-provider text equivalence, and may return null; request procedure_assembly when instruction precision matters. Ghidra no-return assumptions may cut the analyzed body; Evidence limitations report observed terminal calls and available callee identities.

**`procedure_references`** — Procedure References

> Return every raw incoming or outgoing reference edge for one procedure. Endpoint procedures are resolved only from provider containment. Ghidra preserves detailed reference flags. Hopper preserves native CallReference classifications and exact endpoints while leaving unavailable detailed flags explicit.

**`read_bytes`** — Read Bytes

> Read analyzed bytes from one provider-normalized virtual address. The hexadecimal payload reports the exact returned length; incomplete reads remain explicit and unsupported provider APIs return typed capability unavailability.

**`read_function_instructions`** — Read Function Instructions

> Return every raw instruction for one analyzed procedure. Instruction text and body extent are provider-specific. Ghidra terminal-call assumptions that may cut the analyzed body are reported in limitations.

**`resolve_containing_procedure`** — Resolve Containing Procedure

> Resolve an arbitrary address, including an interior instruction or exact external entry, to its provider-analyzed containing procedure. A negative result distinguishes outside segments from not in a procedure and is never guessed from nearby symbols.

**`resolve_native_call_targets`** — Resolve Native Call Targets

> Resolve one explicit static call site using typed provider call references. Preserves ambiguous targets as candidates and unresolved computed calls as unknown; does not execute code or traverse a call graph.

**`search_bytes`** — Search Bytes

> Find masked byte signatures in initialized analyzed memory. Hex byte pairs and ?? wildcards are supported; an optional equal-length hex mask selects bits. Bounds are inclusive. Matches are ordered by provider address and never span blocks. Coverage describes this page; reuse the same query with next_cursor to continue. Uninitialized blocks are listed separately. Ghidra only; Hopper is unavailable.

**`search_procedures`** — Search Procedures

> Search every analyzed procedure name using literal matching by default or regex when requested. Results are deterministic and complete. Hopper regex mode uses ECMAScript Unicode syntax in a cancellable worker; a matching deadline leaves its API usable.

**`search_strings`** — Search Strings

> Search every provider-defined string object using literal matching by default or regex when requested. Results are deterministic and complete over those defined objects, not every text sequence in artifact bytes. Ghidra may omit packed or undefined literals, including Rust strings; an empty result does not prove text is absent. If an address is known, read_bytes and xrefs inspect its bytes and references. Hopper retains typed byte decoding, native display, and explicit decoding unknowns. Adjacent long-literal fragments match independently. Hopper regex mode uses ECMAScript Unicode syntax in a cancellable worker; a matching deadline leaves its API usable.

**`set_address_name`** — Set Address Name

> Assign an analyst name to one mapped hexadecimal address and report whether the native edit succeeded and exact readback matched. Hopper rejects symbol names exceeding 1024 UTF-16 code units before mutation, and rejects names owned by another address; use set_addresses_names to explicitly move or swap labels among selected addresses. This mutates analysis metadata.

**`set_addresses_names`** — Set Addresses Names

> Assign analyst names to multiple mapped addresses in one call and return per-address edit/readback success booleans. Hopper validates mapped destinations, native string representations, its 1024 UTF-16 code-unit symbol-name limit, and unique destinations/names before applying edits. Existing labels may move or swap only among explicitly selected addresses; unselected label owners remain unchanged. This mutates analysis metadata; verify failures individually.

**`set_bookmark`** — Set Bookmark

> Create or replace a bookmark at a mapped hexadecimal address and report success. This mutates navigation metadata; bookmarks are analyst-authored navigation aids, not binary evidence.

**`set_comment`** — Set Comment

> Write a regular analysis comment at a hexadecimal address and return whether readback matched. An empty comment clears it. This mutates the Hopper document; use comments to record evidence IDs or reasoning.

**`set_inline_comment`** — Set Inline Comment

> Write an inline instruction comment at a hexadecimal address and return whether readback matched. An empty comment clears it; Hopper may flatten newlines, producing false on exact readback. This mutates analysis metadata.

**`unset_bookmark`** — Unset Bookmark

> Remove the bookmark at a mapped hexadecimal address and return whether it is absent. Hopper also permits removing an existing legacy bookmark outside mapped memory. This mutates navigation metadata and does not alter binary bytes.

**`xrefs`** — Xrefs

> Return analyzed references to a code or data address. Hopper may default to its current cursor; headless providers such as Ghidra require an explicit address. Use to connect strings, globals, selectors, and functions; bare addresses are untyped and indirect references may be incomplete. Use inspect_native_instruction at the target address for typed incoming references where supported.

---

## 2. Family `enhanced` — surface `enhanced` (14 tools)

**What it does.** Composite investigations: function dossiers, batch decompile, binary overview, call graphs, call-path tracing, feature tracing, ObjC/Swift metadata, native API/dispatch inspection, value tracing.

**Requirements.** Same deep provider as `direct`; built on top of it.

**Malware-analysis use.** Fast triage: `binary_overview` then `analyze_function`/`batch_decompile` on imports of interest; `trace_call_path` from an entry/API to a sink (e.g. network or crypto call); `trace_native_values` for constants/keys.

**Safety on hostile samples.** Static.

| Tool | Tier | Session | Providers | CLI | Needs |
|---|---|---|---|---|---|
| `analyze_function` | A | N | ghidra, hopper, ida | — | mutatesSession |
| `analyze_swift_types` | A | N | built-in | — | mutatesSession |
| `batch_decompile` | A | N | built-in | — | mutatesSession |
| `binary_overview` | A | N | built-in | — | mutatesSession |
| `find_xrefs_to_name` | A | N | built-in | — | mutatesSession |
| `get_call_graph` | A | N | built-in | — | mutatesSession |
| `get_objc_classes` | A | N | built-in | — | mutatesSession |
| `get_objc_protocols` | A | N | built-in | — | mutatesSession |
| `inspect_native_api` | A | N | built-in | `rea inspect-native-api` | mutatesSession |
| `inspect_native_dispatch_metadata` | A | N | built-in | `rea inspect-native-dispatch-metadata` | mutatesSession |
| `trace_call_path` | A | N | built-in | — | mutatesSession |
| `trace_feature` | A | N | built-in | — | mutatesSession |
| `trace_native_ui_action` | A | N | built-in | `rea trace-native-ui-action` | mutatesSession |
| `trace_native_values` | A | N | built-in | `rea trace-native-values` | mutatesSession |

### Tool descriptions (verbatim)

**`analyze_function`** — Analyze Function

> Build a dossier for one native function identified by symbol or provider-returned address. Returns identity with complete inclusive analyzed body ranges or explicit unknown, provider-specific pseudocode and assembly, comments, calls, references, referenced strings/names, local CFG blocks, and available native API boundary observations. Ghidra terminal-call assumptions that may cut the analyzed body are reported in limitations with available callee identities.

**`analyze_swift_types`** — Analyze Swift Types

> Categorize analyzed Swift procedure names using their manglings or same-address Swift symbol aliases. Decodes legacy and literal modern nominal contexts into classes, structs, enums, protocols, and extensions. Preserves provider names and supporting mangled_names; unresolved categories appear in other and in unclassified, which remains inline even under category filters. Returns deduplicated procedure-name counts, not unique source types, plus identification limitations. Optionally select one category and/or apply a case-sensitive literal filter to provider names or supporting manglings; for example, use {category: "structs", pattern: "Pair"}.

**`batch_decompile`** — Batch Decompile

> Decompile each explicit procedure symbol or address concurrently. Preserves each input selector in address and reports the observed canonical entry and entry label in procedure; identity or label failures remain explicit without discarding usable pseudocode. Returns ordered per-item success or error results and aggregate counts.

**`binary_overview`** — Binary Overview

> Return the bound document and exhaustive procedure/string counts, plus every segment and segment_count when the provider supports segment enumeration. If segment fields are omitted, segment coverage is unavailable rather than empty. When every observed segment agrees on an analysis image base, return it as image_base so callers can relate provider addresses to their loader coordinates. Use search_procedures, list_procedures, or analyze_function directly when you already know which procedure to inspect.

**`find_xrefs_to_name`** — Find Xrefs To Name

> Resolve an exact name against the bound provider's name inventory and return a resolved or unresolved result. Unresolved names use the stable name_not_found reason; this xref workflow returns address-only projections.

**`get_call_graph`** — Get Call Graph

> Resolve one symbol or address to its canonical procedure entry, then traverse the bound provider's caller or callee relationships until the reachable graph is exhausted. Every node uses a canonical address and has an ok/error status; failures use safe typed projections. Unresolved indirect calls may be missing and results are not a whole-program CFG.

**`get_objc_classes`** — Get Objc Classes

> Discover and deduplicate Objective-C class labels, optionally filtering by literal substring.

**`get_objc_protocols`** — Get Objc Protocols

> Discover and deduplicate Objective-C and Swift protocol labels.

**`inspect_native_api`** — Inspect Native Api

> Analyze a native API boundary in one function identified by symbol or provider-returned address. Returns confidence, evidence, jump-table dispatch/data/case mappings, separately evidenced default targets, unsupported branches, and residual unknowns. Null case values mean unresolved cases, never a known default.

**`inspect_native_dispatch_metadata`** — Inspect Native Dispatch Metadata

> Inspect the bound provider's name inventory for Objective-C class/method symbols and Swift mangled symbols, returning at most max_records decoded names. Includes target SHA-256 when available, provider identity/version, analysis-profile digest, facet coverage, and per-record Evidence. This is symbol-level evidence, not runtime metadata: ivar layouts, protocol conformances, witness/class tables, and relative pointers are explicitly marked unsupported unless a provider supplies those decoders. The provider controls how its name inventory is acquired.

**`trace_call_path`** — Trace Call Path

> Resolve start and optional goal symbols or addresses to canonical procedure entries, then trace direct callers or callees until the graph is exhausted or the goal is reached. Results use canonical addresses; Evidence preserves supplied selectors. Returns visited nodes, direct-call edges, a shortest traversal path, provider failures, and residual unknowns. A requested goal is unknown when unresolved expansions prevent proving it absent; unresolved indirect calls remain unknown.

**`trace_feature`** — Trace Feature

> Trace the complete literal query, preserving spaces, through every matching string and procedure, their xrefs, and truthful containing-procedure resolution. Returns observations, operation count, and residual unknowns without inferring reference kinds.

**`trace_native_ui_action`** — Trace Native Ui Action

> Trace one unique compiled UI action, object ID, native symbol or exact function address through authored connections, encoded or symbolized Objective-C handlers, and bounded static call references. Typed direct and resolved indirect calls, ambiguous candidates, inferred untyped provider callees, and targetless sites remain distinct. Runtime reachability is unknown; use trace_native_values for recovered value dependencies.

**`trace_native_values`** — Trace Native Values

> Trace a bounded static dependency graph from one explicit native procedure. Includes high-p-code def-use, constants, operators, memory and branch operations, resolved call edges, and derived argument/parameter and return/output bindings. Missing bindings, alias semantics, persistent state and RNG roles remain unknown. Budgets bound depth, decompilations, graph size and payloads; nodes are paginated.

---

## 3. Family `native` — surface `native-provider` (23 tools)

**What it does.** Format inspectors and alternative engines (objdump, Rizin, Cutter, GDB sessions), offline ELF layout/mitigations, recorded core-file crash analysis, native call and UI observation.

**Requirements.** Per tool: built-in parsers (`inspect_macho`, `inspect_plist`, `inspect_pe_resources`, `inspect_signature`); caller-supplied pwntools (ELF layout, recorded crash), GNU objdump, Rizin, Cutter, GDB; macOS native UI/lldb tracing.

**Malware-analysis use.** `inspect_pe_resources` (icons/manifests/embedded payload resources), `inspect_signature` (code-signing facts), `inspect_binary_layout` (ELF mitigations/relocations), `inspect_recorded_crash` (post-mortem of a crashed sample core). Debugger/Rizin/Cutter command tools and `observe_native_calls`/`capture_native_ui_scenario` execute foreign code: detonation tier only.

**Safety on hostile samples.** Mixed: inspectors static; debugger/observer tools execute.

| Tool | Tier | Session | Providers | CLI | Needs |
|---|---|---|---|---|---|
| `capture_native_ui_scenario` | D | N | native-macos | `rea capture-native-ui-scenario` | accessesNetwork, changesUiState, executesForeignCode, launchesProcess, mayDiscardData, mutatesSession, mutatesTarget, writesFilesystem |
| `close_gdb_session` | D | N | gnu.gdb | — | executesForeignCode, launchesProcess, mutatesSession, mutatesTarget |
| `close_rizin_debug_session` | D | N | rizin.debugger | — | executesForeignCode, launchesProcess, mutatesSession, mutatesTarget |
| `cutter_command` | D | N | cutter.python-plugin | `rea cutter-command` | accessesNetwork, changesUiState, executesForeignCode, launchesProcess, mutatesSession, mutatesTarget, writesFilesystem |
| `demangle_swift` | B | N | native-macos | `rea demangle-swift` | launchesProcess, mutatesSession |
| `execute_rizin_command` | D | N | rizin | `rea execute-rizin-command` | accessesNetwork, executesForeignCode, launchesProcess, mayDiscardData, mutatesSession, mutatesTarget, writesFilesystem |
| `gdb_console` | D | N | gnu.gdb | — | accessesNetwork, executesForeignCode, launchesProcess, mutatesSession, mutatesTarget, writesFilesystem |
| `gdb_session_status` | A | N | gnu.gdb | — | — |
| `inspect_binary_layout` | B | N | pwntools-elf | `rea inspect-binary-layout` | launchesProcess, mutatesSession, writesFilesystem |
| `inspect_macho` | B | N | native-macos | `rea inspect-macho` | launchesProcess, mutatesSession |
| `inspect_pe_resources` | A | N | rea-pe-resources | `rea inspect-pe-resources` | mutatesSession |
| `inspect_plist` | B | N | native-macos | `rea inspect-plist` | launchesProcess, mutatesSession |
| `inspect_recorded_crash` | B | N | pwntools-elf | `rea inspect-recorded-crash` | launchesProcess, mutatesSession, writesFilesystem |
| `inspect_signature` | B | N | native-macos | `rea inspect-signature` | launchesProcess, mutatesSession |
| `inspect_with_objdump` | B | N | gnu.objdump | `rea inspect-with-objdump` | launchesProcess, mutatesSession |
| `list_architectures` | B | N | native-macos | `rea list-architectures` | launchesProcess, mutatesSession |
| `list_cutter_sessions` | B | N | cutter.python-plugin | `rea list-cutter-sessions` | accessesNetwork |
| `observe_native_calls` | D | N | native-macos | `rea observe-native-calls` | accessesNetwork, changesUiState, executesForeignCode, launchesProcess, mutatesSession, writesFilesystem |
| `observe_native_ui` | B | N | native-macos | `rea observe-native-ui` | launchesProcess, mutatesSession, writesFilesystem |
| `rizin_debug_command` | D | N | rizin.debugger | — | accessesNetwork, changesUiState, executesForeignCode, launchesProcess, mayDiscardData, mutatesSession, mutatesTarget, writesFilesystem |
| `rizin_debug_session_status` | A | N | rizin.debugger | — | mutatesSession |
| `start_gdb_session` | B | N | gnu.gdb | — | launchesProcess, mutatesSession |
| `start_rizin_debug_session` | D | N | rizin.debugger | — | executesForeignCode, launchesProcess, mutatesSession, mutatesTarget |

### Tool descriptions (verbatim)

**`capture_native_ui_scenario`** — Capture Native Ui Scenario

> Run selected-element press, increment/decrement scroll, AXValue text entry and bounded wait steps in one exact native app window. Returns ordered before/after captures and action/capture failures. Actions can change app data, network activity and persistent state; application state is left as-is and restoration is not attempted.

**`close_gdb_session`** — Close Gdb Session

> Close the owned GDB process after verifying the inferior state. When one live thread group has a verified durable output TTY, REA automatically detaches it, which may resume target execution; otherwise close reports that a disposition is required. REA never kills attached or remote targets as part of debugger cleanup. In a shared MCP server, this admitted close retires any active binary-analysis session; after target effects have settled, call open_binary before further analysis. Close an active Ghidra session explicitly first.

**`close_rizin_debug_session`** — Close Rizin Debug Session

> Close the REA-owned Rizin debugger only after verifying no inferior remains or detaching one with a verified caller-selected TTY output sink. A detached target may continue running and write to that TTY; target state is otherwise reported as unknown. REA never signals an inferior based on PID or path. In a shared MCP server, this admitted close retires any active binary-analysis session; after target effects have settled, call open_binary before further analysis. Close an active Ghidra session explicitly first.

**`cutter_command`** — Cutter Command

> Run one arbitrary Rizin command in a selected live Cutter session. Commands may edit and persist analysis state or execute plugin-provided effects; completion uncertainty is returned as Evidence and must not be retried automatically. In a shared MCP server, this admitted command closes any active binary-analysis session; after its effects have settled, call open_binary before further analysis. Close an active Ghidra session explicitly first.

**`demangle_swift`** — Demangle Swift

> Demangle an ordered list of single-line Swift symbols without requiring Hopper. Each input returns demangled, unchanged, or invalid status.

**`execute_rizin_command`** — Execute Rizin Command

> Execute one caller-selected Rizin command against a local artifact using the Rizin CLI profile that suppresses user settings and scripts while retaining plugins. Preserves decoded stdout and stderr inline with SHA-256 Evidence, up to a shared 16 MiB combined limit; invalid UTF-8 bytes are represented by replacement characters and flagged in Evidence limitations. output_truncated reports output beyond that limit and completion_status is unknown if buffer enforcement terminated the process. Rizin commands and retained plugins can execute foreign code, mutate files, access the network, and read files outside the selected artifact; identities and contents of those external inputs are not bound to Evidence. Command effects depend on the Rizin command and loaded plugins; JSON is command-specific and raw output remains authoritative. In a shared MCP server, this admitted command closes any active binary-analysis session; after its effects have settled, call open_binary before further analysis. Close an active Ghidra session explicitly first.

**`gdb_console`** — Gdb Console

> Run one unrestricted GDB CLI command through MI interpreter-exec console and return raw MI, console, target, and log records inline with Evidence. A command timeout preserves collected records with completion_status unknown and stops the owned debugger session. Commands can execute shell, alter target state, access files, and use network. Closing the debugger never implies target termination. In a shared MCP server, this admitted command closes any active binary-analysis session; after its effects have settled, call open_binary before further analysis. Close an active Ghidra session explicitly first.

**`gdb_session_status`** — Gdb Session Status

> Return the observed lifecycle state and bounded recent MI records and process diagnostics for one persistent REA GDB session; truncation and invalid-UTF-8 fields report discarded or lossy data.

**`inspect_binary_layout`** — Inspect Binary Layout

> Inspect an explicit local binary without launching it as a host process. Returns file-backed section/segment ranges, linked addresses, original symbol/REL/RELA table identities, complete encoded RELR tables and upstream-derived offsets with unknown per-word locations/addends, raw name bytes, dependency/interpreter names and static mitigation inferences inline with artifact SHA-256 Evidence. Initial profile: ELF64 x86-64 little-endian EXEC/DYN/REL on Linux x64 via caller-supplied Python with unchanged pwntools 4.15.0, pyelftools 0.33 and Unicorn 2.1.2. Runtime addresses/library paths, overall relocation inventory completeness and complete derived GOT/PLT coverage remain unknown. Zero executable entry values mean absence; relocatable entries are not applicable. Upstream can emulate PLT instructions with Unicorn for derived static maps. Uses bounded complete output and owned temporary files/processes; malformed, unsupported or oversized objects return no partial success. Select detail summary to retain the complete layout Evidence in this session and receive only its summary view, then inspect sections, symbols, mitigations or linkage with inspect_analysis_view.

**`inspect_macho`** — Inspect Macho

> Inspect Mach-O slices, load commands, imports, exports, dependencies, build metadata, segments, sections, permissions, and exact command provenance without launching Hopper. Large frameworks return megabytes of symbols; detail summary retains the complete Evidence and returns slice identity with per-collection counts, then page rows with inspect_analysis_view kind macho.

**`inspect_pe_resources`** — Inspect Pe Resources

> Inspect one explicit local PE32/PE32+ image's complete bounded type/name/language resource tree without executing it or opening a disassembler. Returns numeric IDs versus original UTF-16 names, directory/data-entry file locations, payload RVA/file ranges, complete SHA-256 hashes and static RT_GROUP_ICON image-resource candidates. Language fallback, image decoding and actual shell/window loading remain unobserved. Reads a stable regular file; malformed or ambiguous mappings, non-identical overlapping ranges and exhausted budgets return no partial success. Portable on supported Node hosts; no Windows SDK or engine installation required.

**`inspect_plist`** — Inspect Plist

> Parse Info.plist from the active artifact by default, or pass any local plist path. Returns normalized JSON rather than plutil text.

**`inspect_recorded_crash`** — Inspect Recorded Crash

> Inspect a supplied Linux ELF64 amd64 or AArch64 little-endian core without launching its target or attaching to any live PID. Returns all recorded segments, raw note owners/descriptors and source ranges, every Linux CORE PRSTATUS thread/register and SIGINFO fields inline with SHA-256 Evidence. Historical PID is recorded metadata; current process/file identity, note coverage and signal-thread associations stay unknown. Optionally add derived core-only GDB/pwndbg mapping candidates through explicit BYO configuration; zero map flags mean unknown permissions. Uses the same stable snapshot for both stages, bounded complete output and owned cleanup. Linux x64 host profile: unchanged pwntools 4.15.0/pyelftools 0.33/Unicorn 2.1.2; optional unchanged pwndbg 2026.09.15. No implicit executable/library pairing, GDB command language, host configuration changes or dependency installation.

**`inspect_signature`** — Inspect Signature

> Inspect the active Mach-O executable's code-signing identity, hashes, authorities, requirements, entitlements, hardened-runtime state, and exact command provenance.

**`inspect_with_objdump`** — Inspect With Objdump

> Run caller-selected GNU objdump inspection against a local artifact, or request operation=architectures without a path to list BFD targets advertised by the installed binary. Preserves decoded stdout and stderr inline with SHA-256 Evidence for artifact inspections, up to a shared 16 MiB combined limit; invalid UTF-8 bytes are represented by replacement characters and flagged in Evidence limitations. output_truncated reports output beyond that limit and completion_status is unknown if buffer enforcement terminated the process. The raw output is authoritative and REA does not claim a stable normalized format. DWARF does not follow local debug links by default. Set follow_debug_links to true to follow them; identities of external debug files are not bound to Evidence. REA clears DEBUGINFOD_URLS for objdump so DWARF processing does not make debuginfod network requests. Architecture output is subjectless and does not establish support for any artifact.

**`list_architectures`** — List Architectures

> List thin or universal Mach-O slices with offsets, sizes, alignment, explicit coverage, and native-tool provenance.

**`list_cutter_sessions`** — List Cutter Sessions

> List live REA bridge sessions hosted by upstream Cutter instances, including observed document identity and bridge-directory security status. Discovery admits at most 256 descriptor candidates (16 MiB at the descriptor byte limit), reads and probes at most eight concurrently, and reports bridge_directory_capacity_exceeded rather than claiming no sessions when that budget is exceeded.

**`observe_native_calls`** — Observe Native Calls

> Launch the active Mach-O as an owned process under LLDB and record each entry into caller-selected functions or Objective-C methods: thread, module, symbol, load and file address, raw argument registers, selector, receiver class and optional caller frames. Every hit auto-continues. No expression is evaluated and no other process is attached. The process is killed when max_events or duration_ms is reached; exit status, captured stdout/stderr, unresolved breakpoints and limitations are returned inline. The process runs with the current user's permissions and may change files, show UI or use the network. A hardened-runtime target needs the get-task-allow entitlement.

**`observe_native_ui`** — Observe Native Ui

> Observe an already-running native app by PID and window ID, bound to the active Mach-O target. Captures a bounded accessibility tree and selected-window screenshot; OS permission denial fails without broad capture or target launch.

**`rizin_debug_command`** — Rizin Debug Command

> Execute one unrestricted command in a persistent Rizin debugger session. Returns raw output inline with Evidence, including backend output interleaved before the completion marker. If the command exceeds the output or frame limit, `output_truncated` is true and `completion_status` is `unknown`; retained partial output is returned and the owned debugger session is stopped. Unsolicited frames already queued before the command make the session unavailable because correlation is ambiguous. Commands can access local files, shell, network, plugins, and target state; effects depend on the active backend and target. In a shared MCP server, this admitted command closes any active binary-analysis session; after its effects have settled, call open_binary before further analysis. Close an active Ghidra session explicitly first.

**`rizin_debug_session_status`** — Rizin Debug Session Status

> Return observed lifecycle state and bounded recent NUL-framed output and process diagnostics for one Rizin debugger session; truncation fields report discarded data, and output_invalid_utf8 reports whether invalid UTF-8 has been observed in session frame bytes; recent output may contain replacement characters.

**`start_gdb_session`** — Start Gdb Session

> Start a BYO GDB process in MI3 mode when available, suppress startup files, and disable auto-loading. Persistent GDB sessions are available only on Linux, where REA can verify live inferior output descriptors through /proc before detaching; macOS descriptor verification is not implemented, and Windows Job Object cleanup can terminate debugger inferiors. Optionally set inferior_tty to a caller-selected terminal for future inferior runs; REA verifies the setting through GDB/MI before the session becomes ready. The selected terminal must remain available after GDB exits. A live inferior can be detached during close only while this durable output sink remains verified. The session persists in this REA MCP server process and receives an explicit session ID.

**`start_rizin_debug_session`** — Start Rizin Debug Session

> Start a persistent Rizin debugger session using `-N` to suppress user settings and scripts while retaining plugins, `-0` for NUL framing, and `-d` with an optional caller-selected IO debugger backend. Requires a caller-selected Linux TTY for inferior stdout and stderr; the target may write directly to that terminal while running and after detach. REA verifies both destinations and `dbg.exitkills=false` before detaching. Backend and target capabilities depend on the installed build. The session lives in this REA MCP process. Persistent sessions require Linux `/proc` descriptor readback. In a shared MCP server, starting this session retires any active binary-analysis session; after target effects have settled, call open_binary before further analysis. Close an active Ghidra session explicitly first.

---

## 4. Family `artifact` — surface `artifact-provider` (16 tools)

**What it does.** Archive/package graph and extraction (ZIP/APK/IPA/MSIX/DMG), interface builder, asset catalogs, keyed archives, dylib resolution, WASM, EVM bytecode, Go build info, Rust cargo-auditable, SQLite snapshots, packet-field and signal-decoder discovery.

**Requirements.** Mostly built-in static parsers; WABT 1.0.42 for WASM; Node 24.15+/26 for SQLite; EVM/Go/Rust parsers built in; TShark/sigrok for packet/signal tools.

**Malware-analysis use.** Unpack droppers/installers (`inspect_artifact`, `extract_artifact` into a scratch dir), identify Go/Rust implants and their dependency sets (`inspect_go_binary`, `inspect_rust_binary`), triage smart-contract bytecode (`inspect_evm_interface`), review local SQLite stores (`inspect_sqlite_database`), WASM miners/loaders (`inspect_wasm_artifact`).

**Safety on hostile samples.** Static; `extract_artifact` writes files.

| Tool | Tier | Session | Providers | CLI | Needs |
|---|---|---|---|---|---|
| `compare_wasm_interfaces` | A | N | built-in | `rea compare-wasm-interfaces` | mutatesSession |
| `decode_interface_builder` | A | N | rea-artifact-graph | `rea decode-interface-builder` | mutatesSession |
| `decode_signal_recording` | B | N | sigrok-recording | `rea decode-signal-recording` | launchesProcess, mutatesSession, writesFilesystem |
| `extract_artifact` | B | N | rea-artifact-graph | `rea extract-artifact` | launchesProcess, mutatesSession, writesFilesystem |
| `inspect_artifact` | B | N | rea-artifact-graph | `rea inspect-artifact` | launchesProcess, mutatesSession, writesFilesystem |
| `inspect_asset_catalog` | B | N | rea-artifact-graph | `rea inspect-asset-catalog` | launchesProcess, mutatesSession |
| `inspect_evm_interface` | B | N | evmole-interface | `rea inspect-evm-interface` | launchesProcess, mutatesSession, writesFilesystem |
| `inspect_go_binary` | A | N | go-build-info | `rea inspect-go-binary` | mutatesSession |
| `inspect_keyed_archive` | A | N | rea-artifact-graph | `rea inspect-keyed-archive` | mutatesSession |
| `inspect_packet_capture` | B | N | tshark-capture | `rea inspect-packet-capture` | launchesProcess, mutatesSession, writesFilesystem |
| `inspect_packet_fields` | B | N | tshark-capture | `rea inspect-packet-fields` | launchesProcess, mutatesSession, writesFilesystem |
| `inspect_rust_binary` | A | N | rust-auditable | `rea inspect-rust-binary` | mutatesSession |
| `inspect_signal_decoders` | B | N | sigrok-recording | `rea inspect-signal-decoders` | launchesProcess, mutatesSession, writesFilesystem |
| `inspect_sqlite_database` | B | N | sqlite | `rea inspect-sqlite-database` | launchesProcess, mutatesSession, writesFilesystem |
| `inspect_wasm_artifact` | B | N | wabt-artifact | `rea inspect-wasm-artifact` | launchesProcess, mutatesSession, writesFilesystem |
| `trace_dylib_resolution` | A | N | rea-artifact-graph | `rea trace-dylib-resolution` | mutatesSession |

### Tool descriptions (verbatim)

**`compare_wasm_interfaces`** — Compare Wasm Interfaces

> Compare typed core WASM import/export names, kinds and exact signatures from two authenticated inspect_wasm_artifact Evidence records. Select imports, exports or both explicitly. Retained references resolve only in the current session; CLI accepts portable inline Evidence. Duplicate names, unsupported types and missing historical interface facets remain unknown. Preserve original module digests and every occurrence; no source acquisition, module execution or runtime-compatibility inference.

**`decode_interface_builder`** — Decode Interface Builder

> Decode compiled storyboard and nib archives inside the active Apple app bundle, including keyed property lists and NIBArchive object tables, into a bounded object, hierarchy, and connection graph. This is static archive parsing; unrecognized archive classes and unresolved code handlers remain explicit unknowns. A full app graph is often several megabytes; detail summary retains it and returns documents with node, edge and coverage counts, then page rows, optionally one document's, with inspect_analysis_view kind interface-builder.

**`decode_signal_recording`** — Decode Signal Recording

> Decode an existing local logic/signal recording on Linux with sigrok-cli 0.7.2 and util-linux prlimit. Supply decoder stack, channels and options explicitly; optionally select input format and annotation classes. Return 50 literal output lines by default, with line_offset/line_limit paging; line_limit:null requests all remaining lines. Output windows count display lines, not annotations or samples, and do not shorten decoding. Preserve selected text, sample ranges, stderr, source/tool identity and coverage inline. Configure absolute REA_SIGROK_COMMAND. File-only analysis; no hardware acquisition or device communication. Empty output does not prove absence of traffic.

**`extract_artifact`** — Extract Artifact

> Extract all regular files from the active archive or application package into a fresh temporary directory chosen by REA. The result includes its location. Rejects traversal and symlink escapes, never overwrites, and verifies cleanup. Integrity mismatches fail by default; record-and-continue extracts the observed bytes and returns each mismatch as an explicitly untrusted integrity contradiction.

**`inspect_artifact`** — Inspect Artifact

> Inspect an active archive or application package in one call. By default returns the complete content-addressed artifact graph once, as the typed nested inventory Evidence, with root and integrity observations, integrity contradictions, hypotheses, unexplored branches, limitations, and next probes inline. Optional detail summary retains the complete inspection and returns its derived summary view; read exact paths or inventory pages with inspect_analysis_view using parent_evidence_id. This changes delivery, not inventory coverage. Read-only DMG mounting is used automatically on supported macOS hosts. Integrity mismatches fail by default; record-and-continue keeps mismatches explicitly untrusted. It does not extract files; use extract_artifact to materialize its regular contents.

**`inspect_asset_catalog`** — Inspect Asset Catalog

> Inspect compiled Assets.car metadata in an active Apple app bundle. Returns stable paginated catalog and rendition records with raw assetutil metadata and catalog digests; rendition bytes are not extracted.

**`inspect_evm_interface`** — Inspect Evm Interface

> Inspect explicit local flat EVM bytecode without target execution or chain/RPC access. Select raw or hex encoding explicitly. Omitted or complete detail returns original carrier and decoded identities, full bytecode and all inferred interface candidates inline. For all inferred selectors/offsets/arguments/mutability and identities without bytecode hex or duplicated stdout, select detail: "summary" on this first call: it retains unchanged complete Evidence and returns a distinct linked inspect_analysis_view summary. Read original function rows or bytecode_hex/stdout/stderr text pages using view kind evm and normalized_result.parent_evidence_id; original complete Evidence remains accessible. Bytecode kind, hardfork, deployed authenticity and discovery completeness stay unknown; summary coverage covers only producer-returned candidates. Unchanged bundled EVMole 0.9.3/WASM in an owned bounded worker is initially real-verified on Linux x64; EOF-style EF00 containers are unsupported. No signature lookup, wallet action or transaction broadcast.

**`inspect_go_binary`** — Inspect Go Binary

> Inspect embedded Go compiler version, main module, dependency/replacement versions and build settings in an explicit local ELF, PE or thin Mach-O image. Returns original artifact SHA-256, exact build-info source ranges, raw framed module bytes and unparsed module-text lines inline as observed Evidence. Supports inline and historical pointer encodings without installing Go, opening a disassembler, executing the target, writing temporary files or accessing the network. Missing metadata is reported as unknown, not proof that an image is not Go. Does not recover functions, source mappings, types or runtime behavior. Resource guards bound files to 256 MiB, aggregate embedded strings to 1 MiB, structural table decoding to 16 MiB and complete inline metadata to 8 MiB; malformed, unsupported and oversized inputs receive typed failures rather than partial success.

**`inspect_keyed_archive`** — Inspect Keyed Archive

> Inspect one Foundation NSKeyedArchiver plist in the active app bundle as original object-table nodes, class descriptors, named roots, and UID edges. Preserves shared and cyclic references without instantiating classes. The path is relative to the bundle; root selection and object pagination preserve original identities.

**`inspect_packet_capture`** — Inspect Packet Capture

> Inspect caller-selected fields in an existing local packet capture with TShark 4.x. Return 50 matching frames by default, with match_offset/match_limit paging and coverage counts; match_limit:null requests all remaining matches. Preserve repeated values, frame numbers, display filter, decode-as rules and pass mode in inline Evidence with source/tool identity and diagnostics. Optional packet_limit counts input packets before filtering; output paging does not shorten dissection or two-pass reassembly. Requires Linux, util-linux prlimit, and absolute REA_TSHARK_COMMAND. File-only analysis; no live capture or device communication. Missing fields or no matches do not establish absence of device traffic.

**`inspect_packet_fields`** — Inspect Packet Fields

> Discover protocols or field names/types registered in the installed TShark 4.x. kind defaults to protocols; use fields and optional exact protocol abbreviation to select field definitions. query searches name/abbreviation/description by case-insensitive literal substring. Return 50 matches by default with offset/limit paging; null requests all remaining within resource limits. Preserve type/base/bitmask/description, duplicate registrations, source line numbers, coverage, tool identity and diagnostics. Linux, REA_TSHARK_COMMAND and prlimit required. No capture file, interface or binary target needed. Registrations describe tool capabilities, not observed traffic. Each call rereads the glossary; use selected fields with inspect_packet_capture.

**`inspect_rust_binary`** — Inspect Rust Binary

> Inspect the cargo-auditable crate dependency list embedded in an explicit local ELF, PE or thin Mach-O image. Returns the artifact SHA-256, the .dep-v0 section file offset and size, compressed and uncompressed sizes, format version, packages in their original order, the root package index, and dependency edges by index. Reads zlib-compressed JSON without installing Rust, opening a disassembler, executing the target, writing temporary files or accessing the network. A missing section is null metadata with a limitation and is not proof that the binary has no dependencies. A rustc commit hash is reported only as an inference when a /rustc/<40-hex>/ path is present in read-only data. Resource guards bound files to 256 MiB, dependency sections to 1 MiB, inflated JSON to the smaller of 8 MiB and 64 times the compressed size, and the complete report to 8 MiB. Malformed, unsupported and oversized inputs receive typed failures rather than partial success.

**`inspect_signal_decoders`** — Inspect Signal Decoders

> Discover installed sigrok protocol decoders or inspect one decoder's channel/option help on Linux. Omit decoder to list ID/name pairs; supply its exact ID for literal help lines with source line numbers. query is a case-insensitive literal substring. Page matches with offset/limit (default 50; null returns all remaining). Reports tool identity, version, diagnostics and examined/matching coverage. Uses configured REA_SIGROK_COMMAND and prlimit; no recording, binary target, hardware scan or acquisition. Each call probes again; decoder modules are trusted, not fully fingerprinted. Use returned IDs/options with decode_signal_recording.

**`inspect_sqlite_database`** — Inspect Sqlite Database

> Inspect an explicit local SQLite database snapshot and its existing sibling WAL without modifying source files or opening a native analysis provider. Requires Node.js 24.x >=24.15 or 26+ with native DatabaseSync.limits support, checked by the worker. Returns observed Evidence with database/WAL SHA-256 and a compact schema inventory. Selecting an exact ordinary table expands only its schema and samples rows (default 20, subject to byte and worker resource limits). Select exact columns in the requested order to avoid unrelated or large values; schema_scope=database explicitly expands the whole schema; returned rows retain 64-bit integers, text bytes and blobs with explicit truncation. No arbitrary SQL, view or virtual-table execution, extension loading, database repair, encryption support or live-snapshot atomicity claim. At most two inspections per provider are admitted; occupied capacity is retryable. An isolated temporary copy and owned worker enforce input, value/record, SQL-statement, JSON-reply, JavaScript-heap and deadline limits; overall native heap is not capped. Supply a quiescent snapshot for coherent database/WAL evidence.

**`inspect_wasm_artifact`** — Inspect Wasm Artifact

> Validate an explicit local WASM artifact with caller-supplied WABT 1.0.42. Omitted or complete detail returns exact byte SHA-256, sections, upstream import/export WAT forms and decoded WAT inline as Evidence. For counts, validation and WAT identity without WAT text, pass detail: "summary" on this first call; it retains the complete original Evidence and returns the same typed summary as inspect_analysis_view, avoiding oversized complete delivery. Read exact imports/exports or WAT pages with inspect_analysis_view using normalized_result.parent_evidence_id. Delivery selection does not change analysis, provider inputs or source identity. Optionally associate selected JavaScript glue literals with explicit local candidates while preserving ambiguous URL/basename matches. Configure absolute REA_WABT_BIN_DIRECTORY. No installation, implicit fetch, WASM execution or original-source claim.

**`trace_dylib_resolution`** — Trace Dylib Resolution

> Trace how dyld would resolve each Mach-O dylib load for the active Mach-O, or for every executable in the active .app bundle (the main app, XPC services, extensions, login items, helpers). Expands @executable_path, @loader_path, and @rpath through each process's LC_RPATH stack in dependents-first load order, and reports every candidate path with its outcome, the resolved image and digest, weak, re-export, and upward flags, and derived findings such as unresolved required loads or absent earlier @rpath candidates. Pure header parsing: nothing is executed, and absolute or system paths outside the analyzed root stay undetermined. Select roots or one architecture to narrow large bundles.

---

## 5. Family `managed` — surface `managed` (7 tools)

**What it does.** .NET PE/CLI metadata, CIL instructions, members, declared native dependencies (P/Invoke), project/application graph, build comparison, reconstruction import.

**Requirements.** None (static).

**Malware-analysis use.** Triage of .NET loaders/stealers: enumerate members and methods, read CIL, find P/Invoke and native boundaries, compare two builds of the same family. No assembly is loaded.

**Safety on hostile samples.** Static.

| Tool | Tier | Session | Providers | CLI | Needs |
|---|---|---|---|---|---|
| `compare_managed_members` | A | Y | rea-dotnet-workflows | `rea compare-managed-members` | mutatesSession |
| `import_managed_reconstruction` | A | Y | rea-dotnet-workflows | `rea import-managed-reconstruction` | mutatesSession |
| `inspect_managed_artifact` | A | N | rea-dotnet-static | `rea inspect-managed-artifact` | mutatesSession |
| `inspect_managed_members` | A | N | rea-dotnet-static | `rea inspect-managed-members` | mutatesSession |
| `inspect_managed_native_boundaries` | A | N | rea-dotnet-static | `rea inspect-managed-native-boundaries` | mutatesSession |
| `project_managed_application_graph` | A | Y | rea-dotnet-workflows | `rea project-managed-application-graph` | mutatesSession |
| `verify_managed_native_boundaries` | A | Y | rea-dotnet-workflows | `rea verify-managed-native-boundaries` | mutatesSession |

### Tool descriptions (verbatim)

**`compare_managed_members`** — Compare Managed Members

> Compare two authenticated inspect_managed_members Evidence records using unique-only tiers: exact declared type, name, and CIL/signature; exact declared type, name, and raw signature (decoded or not); exact declared type, name, and decoded structural method shape; then exact CIL/signature or decoded structural method shape alone, which never takes a member whose own declared type and name remain unpaired on the other side or whose declaring type is unresolved. Names alone are never a matching basis; a member whose signature was not decoded, or whose same-named counterpart's was not, stays unknown rather than added or removed. Metadata tokens remain build-local coordinates bound to each artifact SHA-256 and MVID, and the tuple digest does not itself remap them.

**`import_managed_reconstruction`** — Import Managed Reconstruction

> Import decompiler-produced managed reconstruction against authenticated inspect_managed_members Evidence. The workflow locks each method to artifact SHA-256, MVID, metadata token, signature hash, and the limited decoded-IL tuple hash, records the decompiler identity and options, and marks C# or pseudocode as analyst inference rather than canonical byte observation.

**`inspect_managed_artifact`** — Inspect Managed Artifact

> Inspect an explicit PE/CLI path, or the selected managed target, without loading or executing target code. Omitted or complete detail returns complete metadata inventories with original coverage. Select detail: "summary" on the first call for complete identity, PE/CLI, classification with its evidence, module/MVID, assembly, frameworks, returned-collection counts, coverage/issues and limitations. It retains complete Evidence and returns a distinct linked inspect_analysis_view summary. Page original references/resources/attributes with view kind managed and normalized_result.parent_evidence_id. Counts cover producer-returned rows; partial, unavailable or malformed metadata remains explicit and tokens remain build-local.

**`inspect_managed_members`** — Inspect Managed Members

> Inspect PE/CLI metadata members, signatures, raw CIL hashes, decoded-instruction-tuple hashes, separately reported exception regions, call edges, field-access anchors, and the #US string literals that ldstr loads, without loading or executing target code. Select type_names to decode only the members of those exact declaring types and the literals their bodies load, which keeps large assemblies such as a base class library within the representation budget. Metadata tokens are reported as build-local coordinates bound to the artifact SHA-256 and MVID; the tuple hash does not resolve them or fully commit control flow. Omitted or complete detail returns every collection, including the assembly-wide member_refs and exported_types, which type_names does not narrow. Select detail: "summary" for identity, metadata status, selection with unmatched names, coverage/issues, limitations and per-collection counts; it retains complete Evidence and returns a linked inspect_analysis_view summary. Page original rows with view kind managed-members, normalized_result.parent_evidence_id and collection types/exported_types/fields/methods/member_refs/call_edges/field_accesses/user_strings.

**`inspect_managed_native_boundaries`** — Inspect Managed Native Boundaries

> Inspect PE/CLI ModuleRef, ImplMap/PInvoke declarations, CLI native-header indicators, and non-IL method implementation flags without loading or executing target code. Results are managed declarations and degraded native-boundary observations, not verified native exports or addresses.

**`project_managed_application_graph`** — Project Managed Application Graph

> Project authenticated managed artifact, member, and native-boundary Evidence into the provider-neutral application graph without executing managed code, loading assemblies, or translating managed metadata tokens to native addresses. The graph preserves managed static observations as managed-specific nodes linked to source Evidence.

**`verify_managed_native_boundaries`** — Verify Managed Native Boundaries

> Verify managed P/Invoke/native-boundary declarations against authenticated native export or function Evidence without executing managed code or translating managed metadata tokens into native addresses. The workflow preserves declaration-only, verified, inferred, contradicted, and unresolved states; a name candidate with missing managed or native module identity remains unresolved with its candidate evidence retained.

---

## 6. Family `firmware` — surface `firmware-provider` (2 tools)

**What it does.** Firmware region inspection and extraction to a caller-selected new directory, with native-analysis handoff.

**Requirements.** Caller-supplied Binwalk/Unblob on Linux.

**Malware-analysis use.** IoT/router implant and backdoored-firmware review; extract to a scratch directory then analyse extracted binaries.

**Safety on hostile samples.** Spawns external extractors on the image; extraction writes files.

| Tool | Tier | Session | Providers | CLI | Needs |
|---|---|---|---|---|---|
| `extract_firmware` | B | N | unblob | `rea extract-firmware` | launchesProcess, mutatesSession, writesFilesystem |
| `inspect_firmware_regions` | B | N | binwalk | `rea inspect-firmware-regions` | launchesProcess, mutatesSession, writesFilesystem |

### Tool descriptions (verbatim)

**`extract_firmware`** — Extract Firmware

> Extract caller-selected firmware bytes with Unblob 26.6.x (verified with 26.6.4) into an absent output directory. Returns verified child paths/digests, task derivations, unknown chunks, extraction diagnostics and explicit extraction_gaps rows naming unextracted regions, missing extractor dependencies and a continuation_id referencing shared extraction_continuations recovery instructions. Preserves the default sandbox; publishes regular files only. Linux, caller-supplied tool, format-specific extractors and util-linux prlimit required. No mounts or extracted-code execution. Select a returned native file with open_binary for Ghidra analysis; decompressed offsets are not original-file addresses.

**`inspect_firmware_regions`** — Inspect Firmware Regions

> Inspect signature candidates in a local firmware file with Binwalk 3.1.x (verified with 3.1.0). Returns offsets, reported lengths, descriptions and raw confidence values. Length validation and runtime addresses remain unknown. No extraction or target execution. Linux, caller-supplied tool and util-linux prlimit required; 128 MiB input limit, one worker and 120-second deadline.

---

## 7. Family `android` — surface `android-provider` (5 tools)

**What it does.** APK manifest declarations, classes, decompiled methods, incoming references.

**Requirements.** Headless JADX and a full JDK (Linux/macOS/Windows x64).

**Malware-analysis use.** Mobile malware triage: permissions/components, class search, method decompile, reference tracing to sensitive APIs.

**Safety on hostile samples.** Static (decompiler runs on the APK).

| Tool | Tier | Session | Providers | CLI | Needs |
|---|---|---|---|---|---|
| `inspect_android_class` | B | N | jadx | `rea inspect-android-class` | launchesProcess, mutatesSession, writesFilesystem |
| `inspect_android_method` | B | N | jadx | `rea inspect-android-method` | launchesProcess, mutatesSession, writesFilesystem |
| `inspect_android_package` | B | N | jadx | `rea inspect-android-package` | launchesProcess, mutatesSession, writesFilesystem |
| `search_android_classes` | B | N | jadx | `rea search-android-classes` | launchesProcess, mutatesSession, writesFilesystem |
| `trace_android_references` | B | N | jadx | `rea trace-android-references` | launchesProcess, mutatesSession, writesFilesystem |

### Tool descriptions (verbatim)

**`inspect_android_class`** — Inspect Android Class

> Inspect one exact Android class's parsed methods, fields and inner classes, including synthetic members. Returns display signatures and exact DEX prototypes without generating source. A prototype is not a complete raw method ID; overload indices remain consistent within the artifact and engine session.

**`inspect_android_method`** — Inspect Android Method

> Decompile one Android method with smali fallback. Requires explicit overload_index when multiple methods share a name. Reports its DEX prototype, representation, fallback markers and source truncation; display signatures may be aliases.

**`inspect_android_package`** — Inspect Android Package

> Inspect a local APK's package, SDK and permission declarations, decoded manifest and class/resource counts. Omitted or complete detail preserves the complete result. Select detail: "summary" for all declarations, engine identity and counts without decoded manifest text or duplicate raw calls; retains the complete source and returns a distinct linked inspect_analysis_view summary. Read the exact retained manifest with view kind android, facet manifest, offset and limit (UTF-16 code units), using normalized_result.parent_evidence_id. Does not execute the APK or verify signatures. Requires a caller-supplied JADX MCP JAR and JDK; uses one worker in an isolated temporary workspace.

**`search_android_classes`** — Search Android Classes

> Search complete decompiler class-name rows in an explicit local APK by case-sensitive substring. Empty query inventories all rows. Repeated names remain repeated and appear in duplicate_names; the provider accepts only class names for lookup, so these rows do not identify which same-name class node a later lookup selects. Retains artifact and engine identity; no APK execution.

**`trace_android_references`** — Trace Android References

> Trace incoming static using nodes to an exact Android class or selected method overload. The total counts containing nodes, not individual invoke instructions. Use inspect_android_class to choose an overload_index when names collide. Source lines and the containing node dex_offset remain unknown. direct_invokes carries exact DEX code-unit instruction offsets when available; direct_invokes_exhaustive false marks byte-bounded partial instruction evidence, and null means coverage is unknown. Using-node coverage remains separate; no runtime calls are inferred.

---

## 8. Family `pcap` — surface `pcap-provider` (2 tools)

**What it does.** Summaries of recorded packet captures: endpoints, DNS, TLS SNI, protocol distribution, HTTP requests.

**Requirements.** Caller-supplied tshark and capinfos (Wireshark 4.x), Linux-verified.

**Malware-analysis use.** IOC extraction from sandbox PCAPs (domains, SNI, endpoints) without touching the network.

**Safety on hostile samples.** Reads recordings only.

| Tool | Tier | Session | Providers | CLI | Needs |
|---|---|---|---|---|---|
| `inspect_pcap_capture` | B | N | pcap | `rea inspect-pcap-capture` | launchesProcess, mutatesSession, writesFilesystem |
| `inspect_pcap_client` | B | N | pcap | `rea inspect-pcap-client` | launchesProcess, mutatesSession, writesFilesystem |

### Tool descriptions (verbatim)

**`inspect_pcap_capture`** — Inspect Pcap Capture

> Request detail summary for capture identity/counts, then page retained facts with inspect_analysis_view kind pcap. Default detail complete preserves inline delivery. Inspect one saved pcap or pcapng capture through an owned snapshot: metadata, exact packet count, SHA-256, IPv4/IPv6 address counts, DNS questions and address values from the same single-question response, TLS SNI, protocol distribution and HTTP URIs. All derived inventories are retained within declared resource budgets; unknown DNS attribution and excluded credentials remain explicit. Linux requires util-linux prlimit; Windows uses owned Job Objects. Requires caller-supplied capinfos and tshark; REA never captures traffic.

**`inspect_pcap_client`** — Inspect Pcap Client

> Inspect the caller-selected tshark and capinfos binaries: selected commands, selection sources, and versions. Both tools must be usable. Reads no capture file. REA never installs the Wireshark suite; select binaries with REA_TSHARK_COMMAND and REA_CAPINFOS_COMMAND (absolute) or from PATH.

---

## 9. Family `flutter` — surface `flutter-provider` (2 tools)

**What it does.** Flutter build identification and Dart AOT snapshot inspection.

**Requirements.** None (static APK parsing).

**Malware-analysis use.** Triage of Flutter-based mobile apps where Java decompilation shows little.

**Safety on hostile samples.** Static.

| Tool | Tier | Session | Providers | CLI | Needs |
|---|---|---|---|---|---|
| `identify_flutter_build` | B | N | flutter | `rea identify-flutter-build` | mutatesSession, writesFilesystem |
| `inspect_dart_aot` | B | N | flutter | `rea inspect-dart-aot` | mutatesSession, writesFilesystem |

### Tool descriptions (verbatim)

**`identify_flutter_build`** — Identify Flutter Build

> Identify a Flutter app's build facts by pure parsing: the Dart VM snapshot hash from every lib/<abi>/libapp.so AOT section (vm and isolate, cross-checked), per-ABI library digests, the engine library's GNU build-id, and any labeled Dart version or toolchain strings libflutter.so carries. The snapshot hash is the artifact that maps to a Dart SDK release through an external dataset; REA performs no lookup. No engine, no execution, no external tools.

**`inspect_dart_aot`** — Inspect Dart Aot

> Inspect one ABI's Dart AOT snapshot inside an APK: the four snapshot symbols located through the ELF dynamic symbol table with their offsets, sizes, and section headers (magic, kind, length), the snapshot hash, and a bounded string-pool projection from the isolate data section (package: source URIs, dart: SDK URIs, identifier-like tokens) exposing the app's dependency structure. String-pool entries are byte-pattern observations, not deserialized cluster semantics; typed class and function recovery needs an SDK-specific parser. Omitted or complete detail returns the full observation. Select detail: "summary" for target/ABI/library identity, all snapshot headers, coverage and original lower-bound counts without string lists. The complete source stays retained; read returned strings via inspect_analysis_view with parent_evidence_id and kind dart-aot, collection package_uris/dart_uris/class_like_tokens, offset and limit. Exhausting pages does not imply complete pool coverage. No engine, no execution.

---

## 10. Family `frida` — surface `instrumentation-provider` (9 tools)

**What it does.** Device and process listing, instrumentation sessions, script load/unload, resume, one-shot instrumentation.

**Requirements.** Caller-supplied Frida (device/remote).

**Malware-analysis use.** Dynamic API hooking inside a detonation VM/emulator (key/config extraction at runtime).

**Safety on hostile samples.** EXECUTES target. Audit gap (verified, chapter 21): `close_frida_session` resumes a paused spawn and a failed `start_frida_session` also resumes it, but neither is flagged `executesForeignCode`; treat the whole group as execution.

| Tool | Tier | Session | Providers | CLI | Needs |
|---|---|---|---|---|---|
| `close_frida_session` | C | N | frida | — | accessesNetwork, launchesProcess, mutatesSession, mutatesTarget |
| `frida_session_status` | A | N | frida | — | — |
| `instrument_with_frida` | D | N | frida | `rea instrument-with-frida` | accessesNetwork, executesForeignCode, launchesProcess, mutatesSession, mutatesTarget |
| `list_frida_devices` | B | N | frida | `rea list-frida-devices` | accessesNetwork, launchesProcess |
| `list_frida_processes` | B | N | frida | `rea list-frida-processes` | accessesNetwork, launchesProcess |
| `load_frida_script` | D | N | frida | — | accessesNetwork, executesForeignCode, launchesProcess, mutatesSession, mutatesTarget |
| `resume_frida_session` | D | N | frida | — | accessesNetwork, executesForeignCode, launchesProcess, mutatesSession, mutatesTarget |
| `start_frida_session` | C | N | frida | — | accessesNetwork, launchesProcess, mutatesSession, mutatesTarget |
| `unload_frida_script` | C | N | frida | — | accessesNetwork, launchesProcess, mutatesSession, mutatesTarget |

### Tool descriptions (verbatim)

**`close_frida_session`** — Close Frida Session

> Unload session scripts and detach REA's Frida session. If a spawned process is still paused, resume it before detaching so it is not left suspended. REA never kills the target; its final state is reported as unknown.

**`frida_session_status`** — Frida Session Status

> Return observed Frida session state and queued script messages. Message history is bounded by the provider capture budget and reports truncation.

**`instrument_with_frida`** — Instrument With Frida

> Run one caller-authored Frida script against an explicitly selected process and detach when the observation window ends. The CLI and MCP share this ephemeral workflow; use MCP session operations for persistent sessions. Remote authentication is used only for this call and excluded from Evidence.

**`list_frida_devices`** — List Frida Devices

> List Frida devices currently available to this host, optionally connecting to the caller-selected remote Frida endpoint. Remote authentication options are used for this call only and are never returned or recorded.

**`list_frida_processes`** — List Frida Processes

> List processes observed on a selected Frida device or caller-supplied remote endpoint. A remote connection is closed after discovery; authentication values are never returned or recorded.

**`load_frida_script`** — Load Frida Script

> Load caller-supplied JavaScript into a Frida session. Scripts can read or change target memory and behavior and can access the target process's capabilities. Messages and script errors are returned inline as Evidence; source content is not persisted.

**`resume_frida_session`** — Resume Frida Session

> Resume the process created by a paused Frida spawn session. Attached processes are already running and cannot be resumed through this operation.

**`start_frida_session`** — Start Frida Session

> Attach Frida to one selected process or spawn one selected target. Spawned targets remain paused until resume_frida_session, allowing scripts to load before execution. Closing a session detaches instrumentation; it does not kill the target.

**`unload_frida_script`** — Unload Frida Script

> Unload one caller-selected Frida script from a live session. This removes that script's instrumentation from the target.

---

## 11. Family `apktool` — surface `apktool-provider` (2 tools)

**What it does.** Decode Android binary resources (manifest, strings, locales).

**Requirements.** Caller-supplied Apktool launcher.

**Malware-analysis use.** Read repackaged-APK resources and manifest edits.

**Safety on hostile samples.** Static (external tool run on the APK).

| Tool | Tier | Session | Providers | CLI | Needs |
|---|---|---|---|---|---|
| `decode_android_resources` | B | N | apktool | `rea decode-android-resources` | launchesProcess, mutatesSession, writesFilesystem |
| `inspect_apktool_client` | B | N | apktool | `rea inspect-apktool-client` | launchesProcess, mutatesSession |

### Tool descriptions (verbatim)

**`decode_android_resources`** — Decode Android Resources

> Decode one local APK's resources with `apktool d --no-src` in a provider-owned workspace that is removed after projection: the readable AndroidManifest.xml, apktool.yml version and SDK facts, the app's string resources (default or one locale, bounded to 2000 entries), available string locales, and the decoded file count. The target APK is digest with SHA-256 before decoding; smali is skipped because Java-source recovery belongs to the JADX family.

**`inspect_apktool_client`** — Inspect Apktool Client

> Inspect the caller-selected apktool launcher: resolved command, selection source, and version. Decodes nothing. REA never installs Apktool or Java; select a launcher with REA_APKTOOL_COMMAND (absolute) or apktool on PATH.

---

## 12. Family `jeb` — surface `jeb-provider` (4 tools)

**What it does.** Open JEB projects, list units, decompile items.

**Requirements.** A caller-started JEB client serving MCP (`REA_JEB_MCP_URL`).

**Malware-analysis use.** Use an existing JEB licence for Android/native decompilation via REA's Evidence layer.

**Safety on hostile samples.** Static, via an operator-run JEB.

| Tool | Tier | Session | Providers | CLI | Needs |
|---|---|---|---|---|---|
| `decompile_jeb_item` | B | N | jeb | `rea decompile-jeb-item` | accessesNetwork, mutatesSession |
| `inspect_jeb_client` | B | N | jeb | `rea inspect-jeb-client` | accessesNetwork, mutatesSession |
| `list_jeb_units` | B | N | jeb | `rea list-jeb-units` | accessesNetwork, mutatesSession |
| `open_jeb_project` | B | N | jeb | `rea open-jeb-project` | accessesNetwork, mutatesSession |

### Tool descriptions (verbatim)

**`decompile_jeb_item`** — Decompile Jeb Item

> Decompile one type or method to engine pseudo-code using its decompiler (Dalvik, Java, or native). item_address comes from the engine's code item listing; unit_path defaults to the engine's first code unit and stays unknown when omitted. Read-only with respect to the target file.

**`inspect_jeb_client`** — Inspect Jeb Client

> Inspect the running JEB client serving MCP: engine version, GUI or headless mode, and startup time. Does not open a target. Requires a caller-started JEB client reachable at REA_JEB_MCP_URL (default http://127.0.0.1:8425/mcp); REA never installs or launches JEB.

**`list_jeb_units`** — List Jeb Units

> List project units by stable unit path and type, with optional wildcard filter, parent restriction, and pagination. The engine caps pages at 100 units; a full page reports partial coverage because more units may exist. Read-only.

**`open_jeb_project`** — Open Jeb Project

> Open or create a JEB project from an artifact file or existing .jdb2 database on the engine host. Returns the project's input-file digests and top-level units. The engine analyzes the target itself; REA does not read the file or execute it. Fails when a project is already open.

---

## 13. Family `adb` — surface `adb-provider` (24 tools)

**What it does.** Device/package/process/service/window/display inspection, logcat, settings, bugreports, screen capture, file and APK push/pull/install.

**Requirements.** Caller-supplied adb (emulator or hardware).

**Malware-analysis use.** Collect artefacts from an analysis emulator: logs, bugreports, installed APKs (`pull_adb_package`). Tools that push/install/start/stop mutate the device (6).

**Safety on hostile samples.** Reads are device-side; 6 tools mutate the device — dedicated analysis device only.

| Tool | Tier | Session | Providers | CLI | Needs |
|---|---|---|---|---|---|
| `capture_adb_screen` | B | N | adb | `rea capture-adb-screen` | accessesNetwork, launchesProcess, mutatesSession, writesFilesystem |
| `collect_adb_bugreport` | B | N | adb | `rea collect-adb-bugreport` | accessesNetwork, launchesProcess, mutatesSession, writesFilesystem |
| `inspect_adb_client` | B | N | adb | `rea inspect-adb-client` | launchesProcess, mutatesSession |
| `inspect_adb_device` | B | N | adb | `rea inspect-adb-device` | accessesNetwork, launchesProcess, mutatesSession |
| `inspect_adb_display` | B | N | adb | `rea inspect-adb-display` | accessesNetwork, launchesProcess, mutatesSession |
| `inspect_adb_package` | B | N | adb | `rea inspect-adb-package` | accessesNetwork, launchesProcess, mutatesSession |
| `inspect_adb_window` | B | N | adb | `rea inspect-adb-window` | accessesNetwork, launchesProcess, mutatesSession |
| `install_adb_package` | E | N | adb | `rea install-adb-package` | accessesNetwork, launchesProcess, mutatesDevice, mutatesSession, mutatesTarget |
| `list_adb_devices` | B | N | adb | `rea list-adb-devices` | accessesNetwork, launchesProcess, mutatesSession |
| `list_adb_directory` | B | N | adb | `rea list-adb-directory` | accessesNetwork, launchesProcess, mutatesSession |
| `list_adb_features` | B | N | adb | `rea list-adb-features` | accessesNetwork, launchesProcess, mutatesSession |
| `list_adb_packages` | B | N | adb | `rea list-adb-packages` | accessesNetwork, launchesProcess, mutatesSession |
| `list_adb_processes` | B | N | adb | `rea list-adb-processes` | accessesNetwork, launchesProcess, mutatesSession |
| `list_adb_services` | B | N | adb | `rea list-adb-services` | accessesNetwork, launchesProcess, mutatesSession |
| `pull_adb_file` | B | N | adb | `rea pull-adb-file` | accessesNetwork, launchesProcess, mutatesSession, writesFilesystem |
| `pull_adb_package` | B | N | adb | `rea pull-adb-package` | accessesNetwork, launchesProcess, mutatesSession, writesFilesystem |
| `push_adb_file` | E | N | adb | `rea push-adb-file` | accessesNetwork, launchesProcess, mutatesDevice, mutatesSession, mutatesTarget, writesFilesystem |
| `read_adb_logcat` | B | N | adb | `rea read-adb-logcat` | accessesNetwork, launchesProcess, mutatesSession |
| `read_adb_setting` | B | N | adb | `rea read-adb-setting` | accessesNetwork, launchesProcess, mutatesSession |
| `resolve_adb_packages` | B | N | adb | `rea resolve-adb-packages` | accessesNetwork, launchesProcess, mutatesSession |
| `start_adb_activity` | E | N | adb | `rea start-adb-activity` | accessesNetwork, launchesProcess, mutatesDevice, mutatesSession, mutatesTarget |
| `start_adb_app` | E | N | adb | `rea start-adb-app` | accessesNetwork, launchesProcess, mutatesDevice, mutatesSession, mutatesTarget |
| `stop_adb_app` | E | N | adb | `rea stop-adb-app` | accessesNetwork, launchesProcess, mutatesDevice, mutatesSession, mutatesTarget |
| `uninstall_adb_package` | E | N | adb | `rea uninstall-adb-package` | accessesNetwork, launchesProcess, mutatesDevice, mutatesSession, mutatesTarget |

### Tool descriptions (verbatim)

**`capture_adb_screen`** — Capture Adb Screen

> Capture one frame of the device screen as a PNG (`screencap -p` through exec-out, no device-side file) into a caller-selected output directory, digesting it and reporting its dimensions. No recording or interaction.

**`collect_adb_bugreport`** — Collect Adb Bugreport

> Collect one device-generated bugreport archive (`adb bugreport`) into a caller-selected output directory, digesting the zip. The archive contains the device's own dumpstate, dumpsys, and logcat report; collection can take minutes. Read-only with respect to configuration.

**`inspect_adb_client`** — Inspect Adb Client

> Inspect the caller-selected adb client: resolved binary, version, and install path. Never contacts devices and never starts the adb server. REA never installs platform tools; select a binary with REA_ADB_PATH (absolute) or adb on PATH.

**`inspect_adb_device`** — Inspect Adb Device

> Inspect one device's build identity through a fixed `getprop` whitelist: Android and SDK versions, security patch, fingerprint, product identity, CPU ABIs, and debuggable flag, plus the observed emulator indicator ro.kernel.qemu. Read-only with respect to the device.

**`inspect_adb_display`** — Inspect Adb Display

> Report the display's physical and any overridden size (`wm size`) and density (`wm density`) as the device declares them. Read-only; setting values is not exposed.

**`inspect_adb_package`** — Inspect Adb Package

> Inspect one installed package through `dumpsys package`: version name/code, install and update times, installer, user id, flags, and the requested-permission count. A fixed projection of version-dependent output; unknown sections are ignored rather than guessed. Read-only.

**`inspect_adb_window`** — Inspect Adb Window

> Report the window manager's current focus declarations (mCurrentFocus and mFocusedApp from `dumpsys window windows`, or from `dumpsys window displays` when the windows section declares neither, as on Android 16) — what is on screen at read time without any interaction. Read-only.

**`install_adb_package`** — Install Adb Package

> Install one local APK on the device (`adb install [-r]`), recording the APK's host digest and byte size. A device-mutating tool: `replace_requested` records whether `-r` was selected; `replaced` is null because install success does not establish prior package state. The device's own Success/Failure verdict is preserved with its reason.

**`list_adb_devices`** — List Adb Devices

> List attached devices exactly as `adb devices -l` reports them: serial, state, transport, model metadata, and an inferred emulator/physical kind with its evidence basis. Emulators and USB or network devices appear alike; REA neither starts nor manages them. May start the local adb server on first use.

**`list_adb_directory`** — List Adb Directory

> List the immediate children of one absolute device directory, including hidden entries: names, kinds, permissions, owner, group, sizes, dates, and symlink targets. Names and targets preserve embedded newlines. Recognizes the standard errors for absent paths and denied reads. Read-only.

**`list_adb_features`** — List Adb Features

> List the device's declared hardware and software features (`pm list features`) for device fingerprinting. Read-only.

**`list_adb_packages`** — List Adb Packages

> List installed packages on one device with each base APK's device path, optionally scoped to third-party or system packages. Paths are device filesystem paths, not host-local. Read-only.

**`list_adb_processes`** — List Adb Processes

> List running processes exactly as `ps -A` reports them: user, pid, ppid, rss, state, and name. Useful for pairing with instrumentation lanes. Read-only.

**`list_adb_services`** — List Adb Services

> List the device's binder services with their interfaces (`service list`). Read-only.

**`pull_adb_file`** — Pull Adb File

> Pull one absolute device path (a database, shared-preferences XML, or any readable file) into a caller-selected output directory, digesting it with SHA-256. The local copy must not already exist. Read-only with respect to the device.

**`pull_adb_package`** — Pull Adb Package

> Pull one installed package's complete APK set (base plus every split, as `pm path` reports) from the device into a caller-selected output directory, creating a package-named subdirectory that must not already exist. Every pulled file is digested with SHA-256; partial pulls keep successful artifacts and per-file failure reasons. The device keeps the originals.

**`push_adb_file`** — Push Adb File

> Push one local file to an absolute device path. A device-mutating tool: checks for an existing device file before transfer and refuses it unless overwrite is explicitly requested; this check is not an atomic create and another process can create the path before adb writes. When the device provides sha256sum, the transfer is verified by comparing it with the local digest.

**`read_adb_logcat`** — Read Adb Logcat

> Read a bounded dump of the device log (`logcat -d -t`) for one buffer, optionally restricted to a process id. No streaming, no clearing; the newest lines are kept when the count cap trims. Read-only.

**`read_adb_setting`** — Read Adb Setting

> Read one settings value (`settings get`) from the system, secure, or global namespace. Absent keys report the device's own null observation. Read-only; writing settings is not exposed.

**`resolve_adb_packages`** — Resolve Adb Packages

> Find installed packages by case-insensitive substring of the package name (e.g. `whatsapp` → `com.whatsapp`), returning each match's base APK device path. The first step of an easy get: resolve, then pull_adb_package the exact name. Read-only.

**`start_adb_activity`** — Start Adb Activity

> Start an intent with `am start -W`: one action, optional data URI, optional explicit component, and up to 16 typed extras (string, boolean, int, long, float). A device-mutating tool; the full wait report determines success, with failed-attempt facts and raw output retained.

**`start_adb_app`** — Start Adb App

> Start one installed app's resolved launcher activity with `am start -W -n`. A device-mutating tool for dynamic analysis. The full wait report determines success; failures retain launch-attempt facts and raw output. Pair with `read_adb_logcat` (pid filter) and `list_adb_processes` to observe the app, and `stop_adb_app` to end the run.

**`stop_adb_app`** — Stop Adb App

> Force-stop every process of one package (`am force-stop`), ending a dynamic-analysis run. A device-mutating tool; it succeeds whether or not the package had running processes.

**`uninstall_adb_package`** — Uninstall Adb Package

> Uninstall one package from the device (`adb uninstall`), removing its data for user 0. A device-mutating tool; absent packages report the device's own refusal reason.

---

## 14. Family `browser` — surface `browser-provider` (12 tools)

**What it does.** Page structure, scripts, network observation, screenshots, event listeners, WebMCP discovery, bundle analysis, retained HAR/SAZ/mitmproxy/qlog inspection, scenarios with declared actions.

**Requirements.** A Chrome-family browser (CDP).

**Malware-analysis use.** Phishing/malvertising/drive-by page analysis in a disposable browser profile; replay-free review of saved captures (`inspect_web_network_capture`). `capture_browser_scenario` drives a live page (execution tier). Note: the Chromium REA launches runs with its sandbox disabled by default (Playwright adds `--no-sandbox`) — use a disposable VM.

**Safety on hostile samples.** Mixed: `inspect_web_network_capture`, compare tools static; live observe/scenario tools drive a browser.

| Tool | Tier | Session | Providers | CLI | Needs |
|---|---|---|---|---|---|
| `analyze_web_bundle` | B | N | rea-cdp-browser | `rea analyze-web-bundle` | accessesNetwork, mutatesSession |
| `capture_browser_scenario` | D | N | rea-playwright-browser-scenario | `rea capture-browser-scenario` | accessesNetwork, changesUiState, executesForeignCode, launchesProcess, mayDiscardData, mutatesSession, mutatesTarget, writesFilesystem |
| `capture_web_screenshot` | B | N | rea-cdp-browser | `rea capture-web-screenshot` | accessesNetwork, mutatesSession |
| `compare_web_captures` | A | N | rea-cdp-browser | `rea compare-web-captures` | mutatesSession |
| `compare_web_screenshots` | A | N | rea-cdp-browser | `rea compare-web-screenshots` | mutatesSession |
| `discover_webmcp_tools` | B | N | rea-cdp-browser | `rea discover-webmcp-tools` | accessesNetwork, mutatesSession |
| `inspect_web_event_listeners` | B | N | rea-cdp-browser | `rea inspect-web-event-listeners` | accessesNetwork, mutatesSession |
| `inspect_web_network_capture` | B | N | fiddler-saz, har-schema/lossless-json, mitmproxy-native-tnetstring | `rea inspect-web-network-capture` | launchesProcess, mutatesSession, writesFilesystem |
| `inspect_web_page` | B | N | rea-cdp-browser | `rea inspect-web-page` | accessesNetwork, mutatesSession |
| `list_browser_targets` | B | N | rea-cdp-browser | `rea list-browser-targets` | accessesNetwork, mutatesSession |
| `observe_web_execution` | C | N | rea-cdp-browser | `rea observe-web-execution` | accessesNetwork, mayDiscardData, mutatesSession, mutatesTarget |
| `observe_web_session` | B | N | rea-cdp-browser | `rea observe-web-session` | accessesNetwork, mutatesSession |

### Tool descriptions (verbatim)

**`analyze_web_bundle`** — Analyze Web Bundle

> Capture JavaScript source from one selected CDP page and statically derive a chunk graph, route and endpoint candidates, vendor fingerprints, page-declared WebMCP metadata, and optionally fetch source maps from the selected target origin or explicitly requested origins. JavaScript is parsed but never executed.

**`capture_browser_scenario`** — Capture Browser Scenario

> Run a controlled browser scenario when passive observation cannot exercise the application. Launch the selected executable or connect to a loopback CDP target, provide a start URL and actions, and select storage or artifacts when needed. Environment, empty storage, and a URL-only final capture are defaults. capture.network selects request_body, response_body, and header_values independently; selected content is returned inline with transaction and event references, byte digests, and explicit unavailable states. Credentials and declared secrets are redacted. Agents can run their own local fixture servers to control application responses. Actions run until completion or cancellation unless timeout_ms is set. Results are returned inline.

**`capture_web_screenshot`** — Capture Web Screenshot

> Capture the current visible viewport of one configured page as an inline, content-addressed PNG artifact. The operation never scrolls, navigates, or evaluates page JavaScript.

**`compare_web_captures`** — Compare Web Captures

> Compare passive web captures by providing before and after, each with the complete inspect_web_page normalized_result in inspection and an optional complete discover_webmcp_tools normalized_result in webmcp; or compare recorded scenarios by passing complete capture_browser_scenario normalized_result objects in before_scenario and after_scenario with an optional normalization policy. Use exactly one input group. Network comparison includes observed HTTP requests and WebSocket frame streams; same-URL connections are compared as an unordered collection of ordered streams, retaining connection counts without claiming stable identity between individual connections. Scenario comparison aligns exact step IDs, records deterministic literal normalization, and returns every artifact-level difference plus alignment failures inline. Missing or truncated evidence never proves equality.

**`compare_web_screenshots`** — Compare Web Screenshots

> Compare two self-verifying PNG screenshot artifacts with local pixel metrics. Returns exact changed-pixel ratios and channel deltas without OCR or external services.

**`discover_webmcp_tools`** — Discover Webmcp Tools

> Passively inventory every page-registered WebMCP tool and its complete structural input-schema summary using the experimental CDP WebMCP domain. Metadata is page-declared-untrusted; REA never registers or invokes discovered tools.

**`inspect_web_event_listeners`** — Inspect Web Event Listeners

> Inspect listeners registered directly on the first main-document CSS match in one selected CDP page. Returns event flags, native callback locations, source ownership and exact script text/digests inline. Does not dispatch events, evaluate JavaScript or invoke handlers. Delegated ancestor/framework listeners and execution history remain unknown. Releases REA's object group and transport, preserving the external page.

**`inspect_web_network_capture`** — Inspect Web Network Capture

> Request detail summary for capture identity and counts; then page retained records with inspect_analysis_view kind capture (preview or complete), avoiding repeated decoding. Default detail complete preserves existing inline delivery. Inspect retained local HAR 1.2, native mitmproxy, Fiddler SAZ or aioquic 1.5.0 JSON qlog 0.3 events without contacting recorded URLs. Returns original ordinals, pointers/byte ranges/archive member names, preserved producer fields, precise numeric representations and exact exposed binary bytes inline. Excludes known transport credentials and explicitly marked values. Decodes every record before optional ordinal selection; malformed or oversized captures return no partial success. Duplicate JSON members are invalid; prototype-named members such as __proto__ are preserved as ordinary own JSON members without prototype mutation. Qlog reports trace-scoped STREAM interval unions and endpoint loss declarations; it does not recover bodies, prove network loss or correlate PCAP. Other qlog layouts are unsupported. Uses pinned upstream parsers, owned temporary files and bounded offline processes. SAZ preserves HTTP fields, XML metadata and encoded body/message bytes without replay or HAR conversion; encrypted archives are unsupported. Native mitmproxy requires caller-supplied mitmdump 12.2.3 on Linux. Browser transaction IDs, runtime attribution and original bytes of HAR Unicode text remain unknown.

**`inspect_web_page`** — Inspect Web Page

> Passively inspect one selected page target through CDP without evaluating JavaScript, navigating, clicking, closing, or mutating the page. If no origin filter is supplied, capture is scoped to the target's current origin. Returns DOM structure, accessibility, scripts, resources, attach-window network and console metadata, workers, and redacted storage inventory as Evidence.

**`list_browser_targets`** — List Browser Targets

> List page targets exposed by the selected loopback Chrome DevTools Protocol endpoint. Optionally filter by exact origin. URLs preserve query values and fragments; only URL userinfo credentials are removed.

**`observe_web_execution`** — Observe Web Execution

> Instrument one selected CDP page for a finite, externally driven precise coverage window. Resets execution counters and prevents optimized execution until stopped. Returns complete nested UTF-16 ranges/counts, independently hashed script text and request initiator associations by session script ID. Does not navigate, click, evaluate selected code or close the externally owned page. Navigation ends document-scoped collection; workers and UI causality remain outside this claim. Emits an actual armed progress notification before external actions.

**`observe_web_session`** — Observe Web Session

> Arm a CDP observation window of the requested duration while the user operates the page. By default it follows the selected target's current origin; an explicit origin list controls which origins may be retained. Records navigation, redirect, lifecycle, and failure events.

---

## 15. Family `electron` — surface `electron-provider` (6 tools)

**What it does.** Static JavaScript/Electron application graph (modules, imports, source maps, routes, IPC, native add-ons), Electron fuse inspection, target listing, scenario capture, static/runtime reconciliation.

**Requirements.** Node.js and npm (Linux: procps `ps`); Chrome-family for runtime.

**Malware-analysis use.** Trojanized Electron/npm desktop app review without running it (`analyze_javascript_application`, `inspect_electron_fuses`).

**Safety on hostile samples.** `analyze_*`, `inspect_electron_fuses` static; scenario capture executes the app.

| Tool | Tier | Session | Providers | CLI | Needs |
|---|---|---|---|---|---|
| `analyze_javascript_application` | A | N | rea-javascript-application | `rea analyze-javascript-application` | mutatesSession |
| `capture_electron_scenario` | D | N | rea-playwright-electron-active | `rea capture-electron-scenario` | accessesNetwork, changesUiState, executesForeignCode, launchesProcess, mayDiscardData, mutatesSession, mutatesTarget, writesFilesystem |
| `inspect_electron_fuses` | A | N | electron-fuses | `rea inspect-electron-fuses` | mutatesSession |
| `inspect_electron_page` | B | N | rea-cdp-electron | `rea inspect-electron-page` | accessesNetwork, mutatesSession |
| `list_electron_targets` | B | N | rea-cdp-electron | `rea list-electron-targets` | accessesNetwork, mutatesSession |
| `reconcile_javascript_runtime` | A | N | rea-javascript-runtime-reconciliation | `rea reconcile-javascript-runtime` | mutatesSession |

### Tool descriptions (verbatim)

**`analyze_javascript_application`** — Analyze Javascript Application

> Reconstruct one local ASAR or extracted JavaScript application as an inline application graph without executing it. Returns recovered graph nodes, edges, semantic relations, integrity contradictions, limitations, and coverage. Select source_paths to acquire and analyze only exact inventoried file paths; the complete artifact inventory and identity remain intact, and unselected sources remain explicit unknowns. Dependencies are not implicitly analyzed. Select detail summary to retain the complete analysis Evidence in this session and receive only its summary view, then inspect selected modules or pages with inspect_analysis_view. Summary detail reduces delivery, whereas source_paths bounds source analysis. Integrity mismatches fail by default; record-and-continue retains observed bytes as untrusted and marks graph coverage partial.

**`capture_electron_scenario`** — Capture Electron Scenario

> Use this for a provider-owned Electron run when passive CDP or Inspector observation cannot exercise application behavior. REA owns startup and teardown, accepts caller-defined click/wait actions plus window-targeted renderer reload/crash and synthetic open-url/second-instance delivery, and returns correlated window/WebContents/process/preload/session/navigation/shell/IPC evidence without retaining payload values. Actions wait for completion or request cancellation; a missing click target can keep the request pending. Results identify observed and unavailable event families, coverage status, action targets, and truncation. Cleanup failures retain collected observations with explicit cleanup uncertainty. External shell, navigation, permission, download, popup, updater, and OS-integration effects are blocked and recorded. Use passive Electron tools for observation-only work.

**`inspect_electron_fuses`** — Inspect Electron Fuses

> Inspect packaged Electron fuse bytes in one local macOS app bundle, Electron Framework binary, Windows PE executable, or Linux ELF executable. Returns the artifact digest, per-slice wire version, fuse index, version-1 name, state, and raw byte, plus derived implications for Inspector flags, ELECTRON_RUN_AS_NODE, embedded ASAR integrity, and app.asar-only loading. A missing sentinel is unknown fuse state. Reads artifact bytes only and does not modify the selected file or open a runtime target.

**`inspect_electron_page`** — Inspect Electron Page

> Passively inspect one Electron file page by supplying its loopback CDP endpoint and target ID. The provider rechecks that the target currently exists at that endpoint and is a local file page. Returns frames, DOM structure, resource paths, and scripts without evaluating renderer JavaScript or invoking Electron APIs. The selected endpoint exposes every local file page and its metadata to this tool.

**`list_electron_targets`** — List Electron Targets

> List every Electron file:// page target from a selected loopback CDP endpoint. Local file paths are canonicalized after symlink resolution. Selecting an endpoint exposes every eligible target and its local path metadata.

**`reconcile_javascript_runtime`** — Reconcile Javascript Runtime

> Reconcile verified static JavaScript application graphs with existing passive web/Electron CDP, passive V8 Inspector, or provider-owned active Electron Evidence. Active Electron captures contribute an explicitly partial target-only runtime record; they never invent renderer scripts, frames, workers, or execution claims. Exact captured-source digests take priority over caller-declared file/URL mappings; target, frame, script, and worker ambiguity remains explicit, and source-map authority stays separate.

---

## 16. Family `javascript-runtime` — surface `runtime-provider` (2 tools)

**What it does.** List and observe JavaScript runtime targets.

**Requirements.** V8 inspector-capable runtime target.

**Malware-analysis use.** Runtime observation of Node-based malware inside a sandbox.

**Safety on hostile samples.** Attaches to a running target.

| Tool | Tier | Session | Providers | CLI | Needs |
|---|---|---|---|---|---|
| `list_javascript_runtime_targets` | B | N | rea-v8-inspector | `rea list-javascript-runtime-targets` | accessesNetwork, mutatesSession |
| `observe_javascript_runtime` | B | N | rea-v8-inspector | `rea observe-javascript-runtime` | accessesNetwork, mutatesSession |

### Tool descriptions (verbatim)

**`list_javascript_runtime_targets`** — List Javascript Runtime Targets

> List every eligible Node/Electron V8 Inspector target from an explicit literal-loopback endpoint. Node discovery file locations that cannot be verified are preserved as unresolved reported URLs; they do not prove filesystem identity. Listing does not attach to targets.

**`observe_javascript_runtime`** — Observe Javascript Runtime

> Attach passively to one Node/Electron V8 Inspector target by supplying its loopback Inspector endpoint and target ID. The provider rechecks target presence and attachability; a Node discovery file location may remain unresolved. Loaded script locations are validated independently from Debugger.scriptParsed. Captures script and Runtime execution-context metadata. REA never evaluates, pauses, resumes, reads source, or instruments the target; require/import edges, EventEmitter activity, and Electron IPC remain explicit unknowns. Reconcile the result with static Application Graph Evidence using reconcile_javascript_runtime. The selected endpoint exposes every target it serves to this tool.

---

## 17. Family `application` — surface `application-workflow` (15 tools)

**What it does.** App-level workflows: version comparison, feature tracing, JS semantics tracing, source recovery, web script export, module-import tracing, source-to-bundle comparison, Android/Apple/Harmony application graphs, reconstruction obligation ledgers and coverage, analysis-view paging.

**Requirements.** Mostly built-in; some need retained session Evidence.

**Malware-analysis use.** Variant diffing (`compare_application_versions`), deobfuscation aid (`recover_javascript_sources`, `trace_javascript_semantics`), package anatomy (`project_*_application_graph`).

**Safety on hostile samples.** Static.

| Tool | Tier | Session | Providers | CLI | Needs |
|---|---|---|---|---|---|
| `build_reconstruction_obligation_ledger` | A | N | rea-javascript-application-workflows | `rea build-reconstruction-obligation-ledger` | mutatesSession |
| `compare_application_versions` | A | N | rea-javascript-application-workflows | `rea compare-application-versions` | mutatesSession |
| `compare_javascript_export_shapes` | A | N | rea-javascript-application-workflows | `rea compare-javascript-export-shapes` | mutatesSession |
| `compare_source_to_bundle` | A | N | rea-javascript-application-workflows | `rea compare-source-to-bundle` | mutatesSession |
| `evaluate_reconstruction_coverage` | A | N | rea-javascript-application-workflows | `rea evaluate-reconstruction-coverage` | — |
| `export_web_scripts` | B | N | rea-web-script-export | `rea export-web-scripts` | mutatesSession, writesFilesystem |
| `inspect_analysis_view` | A | N | rea-analysis-view | `rea inspect-analysis-view` | mutatesSession |
| `project_android_application_graph` | A | N | rea-android-application | `rea project-android-application-graph` | mutatesSession |
| `project_apple_application_graph` | A | N | rea-apple-application | `rea project-apple-application-graph` | mutatesSession |
| `project_harmony_application_graph` | A | N | rea-javascript-application-workflows | `rea project-harmony-application-graph` | mutatesSession |
| `recover_javascript_sources` | B | N | wakaru | `rea recover-javascript-sources` | launchesProcess, mutatesSession, writesFilesystem |
| `trace_application_feature` | A | N | rea-javascript-application-workflows | `rea trace-application-feature` | mutatesSession |
| `trace_javascript_semantics` | A | N | rea-javascript-application-workflows | `rea trace-javascript-semantics` | mutatesSession |
| `trace_web_module_imports` | B | N | rea-web-script-export | `rea trace-web-module-imports` | accessesNetwork, launchesProcess, mutatesSession, writesFilesystem |
| `trace_web_source_location` | B | N | rea-web-script-export | `rea trace-web-source-location` | launchesProcess, mutatesSession, writesFilesystem |

### Tool descriptions (verbatim)

**`build_reconstruction_obligation_ledger`** — Build Reconstruction Obligation Ledger

> Generate the complete deterministic ReconstructionObligationLedger from an authenticated Evidence bundle, reviewed obligations, and an explicit reconstruction manifest. Static candidates remain candidates; duplicate ownership, missing original or reconstruction cases, missing parser/type, weak verifier authority, unenumerated claims, contradictions, dependencies, and residual unknowns fail closed. The inline result carries the full-ledger closure digest and typed per-obligation diagnostics.

**`compare_application_versions`** — Compare Application Versions

> Compare two authenticated JavaScript Application Graph versions supplied as inline Evidence or exact same-session retained references. Uses unique-only exact digest, module source digest, source-map identity, structural fingerprint, and non-module semantic-key tiers. Reports added, removed, changed, ambiguous, and unknown entities plus the complete matching changed_from graph without fuzzy or module-ordinal pairing.

**`compare_javascript_export_shapes`** — Compare Javascript Export Shapes

> Compare static return shapes for one exact module/export selector on each authenticated JavaScript Application Graph supplied as inline Evidence or exact same-session retained references. Variants pair only by reciprocal unique literal discriminants. Each retained variant lists observed return-property names even when values stay unknown. Presence (present, absent, or unknown-coverage) is separate from value resolution: a name present on only one paired shape is added or removed when parent-property coverage is complete on both sides, including when the static value is unresolved. Dynamic values, incomplete parent coverage, and unpaired variants remain unknown. Reports JSON Pointer changes without executing JavaScript; runtime behavior requires a separate agent-run probe.

**`compare_source_to_bundle`** — Compare Source To Bundle

> Compare a cryptographically committed HistoricalSourceGraph with authenticated JavaScript Application Graph Evidence supplied inline or by exact same-session retained reference. Uses explicit exact-digest, source-map path, current-path, suffix, and basename signals with stable weights. Classifies unchanged, modified, removed, split, merged, duplicated, and unknown; incomplete coverage and ambiguous weak signals never become absence or forced matches.

**`evaluate_reconstruction_coverage`** — Evaluate Reconstruction Coverage

> Evaluate inline evidence-backed reconstruction coverage against one named boundary. Missing ownership or inventory is partial; stale, weak, truncated, skipped, unresolved, or conflicting tied verifier proof is unknown; contradictions, failed proof, missing owners, and authority routing fail closed.

**`export_web_scripts`** — Export Web Scripts

> Export JavaScript bytes already retained in one local inspect_web_page or capture_browser_scenario JSON capture (normalized result or complete Evidence). Writes scripts and a digest-verified manifest into an absent absolute output_directory. Returns all source URLs, script or transaction/event references, unavailable states, and an analysis_input for analyze_javascript_application when any bytes were exported. Include script sources in inspect_web_page or select capture.network.response_body in scenarios. No refetch or execution. Safe unambiguous URL layouts preserve relative module paths; versions, query variants, inline scripts, and path collisions are isolated with explicit resolution limitations.

**`inspect_analysis_view`** — Inspect Analysis View

> Inspect selected views of completed binary-layout, JavaScript application, native analyze_function, inspect_artifact, inventory_artifact, inspect_wasm_artifact, inspect_macho, decode_interface_builder, inspect_evm_interface, inspect_managed_artifact, inspect_managed_members, inspect_android_package, inspect_dart_aot or inspect_web_network_capture Evidence without repeating analysis. Historical capture summaries return identity and counts without bodies or archive inventories. Capture views page retained records: view {kind: "capture", detail: "preview" | "complete", offset: 0, limit: 20}; preview selects recorded headline fields and binary descriptors, complete returns exact records with all sidecars. Offsets follow the selected parent record order, preserving original producer ordinals. Paging never reopens the source or reruns the decoder. For inspect_pcap_capture parents, kind pcap pages endpoints, dns-queries, tls-sni, protocols, http-uris or unattributed-addresses. Select an exact query for dns-addresses, or a tshark/capinfos stream for UTF-16 diagnostics text. Page totals count retained facts; source coverage remains explicit. Qlog summaries keep profile/scope and counts; kind qlog pages traces, streams, loss-declarations, incomplete-records, contributions, ranges or final-sizes. Except traces, select trace_index; stream-specific facets also require exact stream_id and direction. Facts retain all-recorded-events-before-selection scope, and interval overlap or endpoint loss declarations do not prove retransmission or network loss. The api-surface view groups retained HAR requests by method, origin and format-rule path template; templated segments are inferences. It reads no headers or bodies and reports no query values. For a retained record use source: {kind: "retained-evidence", evidence_id: "<parent_evidence_id>"}. Use normalized_result.parent_evidence_id from a summary receipt. Source kind is required. Portable source uses {kind: "inline", evidence: <complete Evidence>}. For layout, JavaScript, inventory, WASM, Mach-O, Interface Builder, EVM, managed artifact, Android package and Dart AOT sources, request a summary with view: {kind: "summary"}; summary is a view kind and has no facet. The WASM summary gives validation, counts, WAT digest/length, tool profile and execution/network states without reading WAT text. Select a layout mitigations/linkage facet, one section/symbol/module, or a stable page. Module pages include assets, bundled and source modules; use node_id for ambiguous or unavailable paths. Inventory uses view: {kind: "inventory", collection: "occurrences", logical_paths: ["package.json"], offset: 0, limit: 64}. Inventory views page nodes, occurrences, edges or integrity contradictions; occurrence logical_paths matches exact recorded strings (omitted means all available, [] means none). source_complete distinguishes complete inventories from partial source records; page exhaustion does not prove absence in a partial source. WASM views use kind wasm and facet sections/imports/exports/candidates/glue/wat/headers/details/tool_profile; text facets use UTF-16 code units and source forms remain exact. Mach-O views use kind macho and facet entrypoints/architectures/build_metadata/load_commands/dependencies/imports/exports/segments/provenance; source_exhaustive false means unreturned rows may exist. Interface Builder views use kind interface-builder and collection documents/nodes/edges/coverage; nodes and edges accept an exact document relative_path. EVM summary returns all inferred interface candidates, carrier/decoded identities and explicit unknowns without hex or duplicate stdout. EVM views use kind evm and facet functions/bytecode_hex/stdout/stderr; function pages preserve the original candidate rows, and text offsets/limits count UTF-16 code units (hex has two characters per decoded byte). Exhausting candidate pages does not establish global interface completeness. Managed artifact summaries preserve complete identity/classification, metadata status, module/MVID, frameworks, coverage and limitations without unrelated inventories. Managed pages use kind managed and collection references/resources/attributes, retaining source coverage and build-local token scope; page exhaustion does not establish complete metadata. Managed member summaries keep identity, selection with unmatched names, coverage and per-collection counts; managed-members pages use collection types/exported_types/fields/methods/member_refs/call_edges/field_accesses/user_strings and carry the source selection and coverage. Android package summaries retain all declarations, engine identity and counts without decoded manifest text. Android manifest pages use kind android, facet manifest, offset and limit in UTF-16 code units; source_status preserves partial decoded coverage even when the retained text page is exhausted. Dart AOT summary preserves target/ABI/library identity, snapshot headers and pool lower bounds. String pages use kind dart-aot, collection package_uris/dart_uris/class_like_tokens; source coverage remains partial when the producer says partial. Native function Evidence requires kind native: view: {kind: "native", facet: "procedure"}. Facets select procedure, pseudocode, assembly, basic blocks, comments, callers/callees, references, unresolved calls, referenced strings/names, native API and high-pcode. Use nonnegative offset and a positive caller-selected limit (defaults 0 and 64); pseudocode uses UTF-16 code units, other native pages use rows. Returns artifact identity, parent Evidence ID, a distinct view digest, coverage, limitations and unknowns. Actual serialized size determines MCP transport admission; choose a smaller page or export the complete retained Evidence if needed.

**`project_android_application_graph`** — Project Android Application Graph

> Project authenticated APK inventory_artifact Evidence into an execution-free Android application inventory. Reports exact component paths and hashes, runtime-family hints, and path-based bridge hypotheses without decoding DEX, executing the APK, or claiming observed runtime calls.

**`project_apple_application_graph`** — Project Apple Application Graph

> Project authenticated IPA, macOS .app directory, ZIP, or DMG inventory Evidence into an execution-free Apple application inventory. Reports application roots, nested bundles with path-convention roles (app extensions, XPC services, login items, privileged helpers, system extensions, frameworks), launchd plists, exact component paths and hashes, runtime-family hints, and path-based bridge hypotheses without parsing plist/CMS semantics or claiming observed runtime calls.

**`project_harmony_application_graph`** — Project Harmony Application Graph

> Project authenticated HarmonyOS HAP, HSP, or App Pack inventory Evidence into an execution-free application inventory. Reports packaging-model hints (Stage module.json versus FA config.json), exact component paths and hashes (manifests, Ark bytecode, resources, native libraries, JavaScript, signing), App Pack child packages, runtime-family hints, and path-based N-API bridge hypotheses without decoding Ark bytecode, parsing manifest semantics, or claiming observed runtime calls.

**`recover_javascript_sources`** — Recover Javascript Sources

> Recover readable modules from local UTF-8 JavaScript scripts/bundles into an absent directory, using caller-supplied Wakaru ^1.13.0 (verified with 1.14.0) on Linux x64. Use additional_paths for related chunks; each input retains its own snapshot and provenance. Returns original/derived digests, extraction byte ranges, emitted source maps, warnings and analysis_input inline. Structural splitting may fall back to one module; original names and runtime equivalence remain unknown. No application code execution. Requires util-linux prlimit; one worker, 1 GiB address-space ceiling, 120-second deadline, 64 MiB total input, 128 MiB output, 10000 entries and 8 MiB per diagnostic/report stream.

**`trace_application_feature`** — Trace Application Feature

> Trace a typed literal seed through every reachable part of an authenticated JavaScript Application Graph supplied as inline Evidence or exact same-session retained references. Original static, native, passive-runtime, inferred, and unknown authorities remain distinct; native addon handoffs never open a provider or execute the application.

**`trace_javascript_semantics`** — Trace Javascript Semantics

> Trace static JavaScript data-flow, direct call/return, and closure relations from inline application Evidence or an exact same-session retained reference. Dynamic or unsupported semantics remain explicit unknowns; static reachability never claims runtime execution.

**`trace_web_module_imports`** — Trace Web Module Imports

> Trace one exported website script's outgoing native ES imports/re-exports, using exact URL and optional selected import-map context. Reads a local export_web_scripts manifest and verifies the selected source's SHA-256/size; returns source positions, native resolved URLs or exact errors, every matching captured candidate and explicit unknown execution. Query/fragment identities are preserved. Computed imports and bundler IDs remain unknown. Select importer_url for unknown inline/document-base context. Caller-supplied Chromium executes only a trusted REA resolver stub in an owned context with page requests locally fulfilled/blocked; no captured application execution or asset refetch. Requires absolute REA_BROWSER_EXECUTABLE for literal imports. 32 MiB manifest, 16 MiB source, 4 MiB map and 20-second native deadline; cleanup may extend the deadline.

**`trace_web_source_location`** — Trace Web Source Location

> Trace one generated position in an exported website script through an explicitly paired local source map. Verifies manifest, selected script and map SHA-256/byte identities; returns every equal-position mapping, reported source/root, resolved source URL, embedded sourcesContent and original position inline. One-based lines and zero-based UTF-16 columns; greatest generated position <= requested across lines. Duplicate sources and generated-only mappings remain distinct. Caller-selected pairing does not establish deployment authenticity or execution. Regular maps and inline indexed sections only; external section URLs are unsupported. No network access or application execution; uses the pinned upstream codec in an owned Node process with private temporary files, independent 192 MiB old-generation heap and 20-second deadline. 4 MiB map, 32 MiB reply; complete evidence or actionable resource failure. Cleanup may extend the deadline.

---

## 18. Family `session` — surface `session` (21 tools)

**What it does.** `open_binary`/`close_binary`, `binary_session`, Evidence bundle export/import/get, residual Unknown ledger, comparisons (artifacts, bundles, functions, process captures), call-path building, static/runtime correlation, reconstruction verification, process capture.

**Requirements.** Open session for most; no external engine for evidence tools.

**Malware-analysis use.** The analyst workflow backbone: Evidence bundles as portable reports, Unknowns for open hypotheses, comparisons for variants. `capture_process_scenario` executes the target (detonation tier).

**Safety on hostile samples.** Static except `capture_process_scenario`.

| Tool | Tier | Session | Providers | CLI | Needs |
|---|---|---|---|---|---|
| `binary_session` | B | Y | built-in | — | launchesProcess |
| `build_call_path` | A | Y | built-in | — | mutatesSession |
| `capture_process_scenario` | D | Y | built-in | — | accessesNetwork, executesForeignCode, launchesProcess, mutatesSession, writesFilesystem |
| `close_binary` | B | Y | built-in | — | mayDiscardData, mutatesSession, writesFilesystem |
| `compare_artifacts` | A | Y | built-in | — | mutatesSession |
| `compare_bundles` | A | Y | built-in | — | mutatesSession |
| `compare_functions` | A | Y | built-in | — | mutatesSession |
| `compare_process_captures` | A | Y | built-in | `rea compare-process-captures` | mutatesSession |
| `correlate_static_and_runtime` | A | Y | built-in | — | mutatesSession |
| `export_evidence_bundle` | B | Y | built-in | — | mayDiscardData, writesFilesystem |
| `find_changed_behavior` | A | Y | built-in | — | mutatesSession |
| `get_evidence_bundle` | A | Y | built-in | — | — |
| `get_navigation_context` | A | Y | built-in | — | mutatesSession |
| `import_evidence_bundle` | A | Y | built-in | — | mutatesSession |
| `inspect_address_context` | A | Y | built-in | — | mutatesSession |
| `list_unknowns` | A | Y | built-in | — | — |
| `open_binary` | B | Y | built-in | — | launchesProcess, mutatesSession |
| `record_unknown` | A | Y | built-in | — | mutatesSession |
| `update_unknown` | A | Y | built-in | — | mutatesSession |
| `verify_reconstruction` | A | Y | built-in | — | mutatesSession |
| `verify_unknown_resolution` | A | Y | built-in | — | — |

### Tool descriptions (verbatim)

**`binary_session`** — Binary Session

> Report the complete current target, provider, capability availability, client-feature, analysis, and server-identity status without starting analysis.

**`build_call_path`** — Build Call Path

> Build every shortest direct-callee path inline from complete analyze_function Evidence records using exact canonical addresses. Missing dossiers and provider mixing remain unknown; every node and edge cites source Evidence.

**`capture_process_scenario`** — Capture Process Scenario

> Run one caller-selected command under a PTY and return process capture Evidence with residual unknowns. The renderer admits at most 1,000,000 combined terminal cells, computed as columns × (rows + scrollback); every resize uses the selected scrollback and must fit the same budget. Supply a smaller terminal shape when that product is too large; dimensions are never clamped. A command name resolves through the inherited PATH; the working directory defaults to the caller's current directory; host environment variables are inherited with scenario overrides. Environment keys cannot contain '=' or NUL, and REA_PROCESS_RUN_ID is reserved for process ownership. Filesystem snapshots are opt-in through filesystem_observation_paths. A positive finalization_ms makes a timeout or idle deadline send SIGTERM to the captured root through its start identity, keep observing, and send SIGKILL once after the interval; exit.finalization records each attempt with its delivery result and the observed exit, and cancellation still ends the run at once. The target runs with the current user's permissions; this is not a security sandbox.

**`close_binary`** — Close Binary

> Drain earlier provider requests, optionally write a provider-neutral analysis snapshot atomically to the caller-supplied path, then close the active target and every provider resource started for it. Later provider requests wait until this lifecycle operation finishes. Existing files require explicit overwrite; a failed save leaves the session open so cached analysis is not lost. Metadata edits prevent immutable snapshot saves until the session is recreated; export_evidence_bundle preserves mutable observations before closing without a snapshot.

**`compare_artifacts`** — Compare Artifacts

> Compare complete artifact inventories by logical occurrence path, content identity, metadata, and graph relations. Pass the inventory Evidence nested in each inspect_artifact result as left and right. Every delta cites both inputs, and gaps yield truncated or unknown, never equivalence. Returns every change inline.

**`compare_bundles`** — Compare Bundles

> Compare two canonical Evidence bundles by exact record membership, explicit one-to-one observation pairs, and complete residual-unknown revision histories. Missing bundle members describe omission only, never behavioral equivalence; output is digest-anchored and returns every change inline.

**`compare_functions`** — Compare Functions

> Compare two explicit sets of analyze_function Evidence across identity, exact provider text, calls, references, strings, and address-normalized CFG topology. Missing or provider-incompatible facets remain truncated or unknown; every conclusion cites both Evidence sets.

**`compare_process_captures`** — Compare Process Captures

> Compare two compatible process capture observations across terminal, interaction, lifecycle, process, filesystem, command-shim, HTTP, and WebSocket evidence. Optional trace_spec validates exact events against an explicit partial order or finite trace language; concurrency is never inferred from timestamps or broad sorting. Missing, journal-free, or truncated observations are never treated as equivalent.

**`correlate_static_and_runtime`** — Correlate Static And Runtime

> Evaluate every explicit caller-declared hypothesis between exact static comparison findings and runtime comparison dimensions. Similar names or paths are never auto-matched, consistent cochange never proves causality, and unknown or truncated inputs remain unresolved. Returns all correlations and their complete Evidence closure inline.

**`export_evidence_bundle`** — Export Evidence Bundle

> Atomically write the session's deterministic Evidence bundle to the requested local path. Existing files require overwrite: true; records and manifests use canonical byte-stable ordering.

**`find_changed_behavior`** — Find Changed Behavior

> Aggregate validated process and artifact comparison Evidence. Runtime observations remain distinct from static behavior candidates; missing or incomplete comparisons produce unresolved findings, never causal claims. Returns every finding inline.

**`get_evidence_bundle`** — Get Evidence Bundle

> Return every retained Evidence record and residual unknown as a complete canonical bundle by default. detail=summary discovers retained records without copying or transferring their payloads; optionally filter by exact Evidence ID, operation, target SHA-256, analysis-profile digest or canonical native procedure address. Metadata distinguishes complete record retention from native value-flow truncation or unavailable/unknown coverage. Use a discovered evidence_id with inspect_analysis_view without restarting a provider. Filters apply only to summary delivery.

**`get_navigation_context`** — Get Navigation Context

> Return the selected document, current address, and containing/current procedure in one provider-neutral result. The result reflects sequential provider observations, not an atomic cursor snapshot; a cursor outside any procedure returns procedure: null.

**`import_evidence_bundle`** — Import Evidence Bundle

> Read the JSON bundle at the supplied local path, validate every Evidence ID and canonical manifest, then atomically merge it. Imported content is data only and is never executed.

**`inspect_address_context`** — Inspect Address Context

> Inspect one explicit reproducible address for its analyzed name, containing procedure, regular and inline comments, and matching bookmarks. Each unsupported facet returns a typed unavailable outcome; use xrefs, assembly, or pseudocode for those deeper views.

**`list_unknowns`** — List Unknowns

> List current residual-unknown heads in deterministic ID order, with optional exact status, severity, and domain filters. Results are complete inline by default; supply offset and limit to page the filtered order. total is the matching-head count and next_offset is null when the page exhausts the result. This is read-only; unresolved, contradicted, and non-truth dispositions remain distinct.

**`open_binary`** — Open Binary

> Open a local executable, application bundle, archive, JavaScript, source map, plist, or analysis database after validation. format=dos-com explicitly interprets 1..65280 headerless bytes as a DOS COM analysis image. format=raw-binary interprets headerless bytes with a required architecture and entry_point; file offset 0 maps at that address. Omission preserves header-based detection. provider_id selects one deep provider or deterministic auto selection; the binding remains stable until close or an explicit switch, with no failure fallback. Reopening the same target and profile retains its active database and metadata edits. An optional analysis snapshot is imported atomically and must match the binary identity, concrete provider, and canonical analysis profile exactly; importing into a session with metadata mutations requires closing and reopening it first.

**`record_unknown`** — Record Unknown

> Create one deterministic residual unknown and immutable mutation evidence. Validates all evidence and relationship references, and rejects duplicate stable identity.

**`update_unknown`** — Update Unknown

> Append one immutable full-state revision and mutation evidence. Requires exact expected_revision; stale concurrent writers fail instead of overwriting newer analysis.

**`verify_reconstruction`** — Verify Reconstruction

> Verify a finite typed behavioral and structural specification against a canonical Evidence bundle. Pass means every declared claim has complete comparable authority—not global source equivalence; changed claims fail and missing, limited, or unresolved evidence stays unknown.

**`verify_unknown_resolution`** — Verify Unknown Resolution

> Revalidate the current residual-unknown head against live bundled evidence, exact authority/confidence/environment requirements, and revision integrity. Withdrawn and out-of-scope dispositions are not truth claims.

---

## Providers (engines and parsers) — 47

| Provider id | Name | Tools it advertises |
|---|---|---|
| `adb` | Android Debug Bridge | 24 |
| `apktool` | Apktool | 2 |
| `binwalk` | Binwalk | 1 |
| `cutter.python-plugin` | Cutter Python plugin | 2 |
| `electron-fuses` | REA Electron fuse reader | 1 |
| `evmole-interface` | REA EVM interface adapter | 1 |
| `fiddler-saz` | REA Fiddler SAZ capture adapter | 1 |
| `flutter` | Flutter build identification | 2 |
| `frida` | Frida | 9 |
| `ghidra` | Ghidra | 29 |
| `gnu.gdb` | GNU GDB | 4 |
| `gnu.objdump` | GNU objdump | 1 |
| `go-build-info` | REA Go build-information reader | 1 |
| `har-schema/lossless-json` | REA HAR capture adapter | 1 |
| `hopper` | Hopper Disassembler | 36 |
| `ida` | IDA MCP adapter | 14 |
| `jadx` | JADX headless | 5 |
| `jeb` | JEB | 4 |
| `mitmproxy-native-tnetstring` | REA offline native mitmproxy adapter | 1 |
| `native-macos` | macOS native inspection utilities | 8 |
| `pcap` | Packet capture analysis | 2 |
| `pwntools-elf` | REA pwntools ELF adapter | 2 |
| `rea-analysis-view` | REA analysis view projection | 1 |
| `rea-android-application` | REA Android application workflows | 1 |
| `rea-apple-application` | REA Apple application workflows | 1 |
| `rea-artifact-graph` | REA safe artifact graph provider | 6 |
| `rea-cdp-browser` | REA Chrome DevTools Protocol observation provider | 10 |
| `rea-cdp-electron` | REA Electron file-page CDP observation provider | 2 |
| `rea-dotnet-static` | REA managed static analysis provider | 3 |
| `rea-dotnet-workflows` | REA managed-code workflows | 4 |
| `rea-javascript-application` | REA JavaScript application analyzer | 1 |
| `rea-javascript-application-workflows` | REA JavaScript application workflows | 8 |
| `rea-javascript-runtime-reconciliation` | REA JavaScript runtime reconciliation | 1 |
| `rea-pe-resources` | REA PE resource parser | 1 |
| `rea-playwright-browser-scenario` | REA Playwright browser scenario capture provider | 1 |
| `rea-playwright-electron-active` | REA Playwright active Electron observation provider | 1 |
| `rea-v8-inspector` | REA passive Node/Electron V8 Inspector provider | 2 |
| `rea-web-script-export` | REA captured script export | 3 |
| `rizin` | Rizin | 1 |
| `rizin.debugger` | Rizin debugger | 4 |
| `rust-auditable` | REA Rust dependency reader | 1 |
| `sigrok-recording` | REA sigrok recording adapter | 2 |
| `sqlite` | REA SQLite database inspector | 1 |
| `tshark-capture` | REA TShark capture adapter | 2 |
| `unblob` | Unblob | 1 |
| `wabt-artifact` | REA WABT artifact adapter | 1 |
| `wakaru` | Wakaru | 1 |

External requirements, env vars and platforms per provider: [06-provider-layer-and-session-routing.md](06-provider-layer-and-session-routing.md).

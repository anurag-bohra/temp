# Tool family: Native investigation workflows (enhanced)

Generated mechanically from `.cache/mcp-tool-catalog.json` (produced by `scripts/generate-mcp-tool-catalog.mjs`, which registers every tool through the MCP SDK and exports the advertised JSON Schema 2020-12 input/output schemas) and `docs/public/product-catalog.json` (family `enhanced`, surface `enhanced`, 14 tools). Input schemas below are **verbatim**. Output schemas are verbatim in `tool-specs/<tool>.json` (field `outputSchema`) because several exceed 100 KB; the complete per-tool spec (description, effects, annotations, inputSchema, outputSchema) is in that file.

| Tool | Kind | Session? | Providers advertising it | CLI command |
|---|---|---|---|---|
| [`analyze_function`](#analyzefunction) | enhanced | no | ghidra, hopper, ida | — |
| [`analyze_swift_types`](#analyzeswifttypes) | enhanced | no | (built-in / not provider-listed) | — |
| [`batch_decompile`](#batchdecompile) | enhanced | no | (built-in / not provider-listed) | — |
| [`binary_overview`](#binaryoverview) | enhanced | no | (built-in / not provider-listed) | — |
| [`find_xrefs_to_name`](#findxrefstoname) | enhanced | no | (built-in / not provider-listed) | — |
| [`get_call_graph`](#getcallgraph) | enhanced | no | (built-in / not provider-listed) | — |
| [`get_objc_classes`](#getobjcclasses) | enhanced | no | (built-in / not provider-listed) | — |
| [`get_objc_protocols`](#getobjcprotocols) | enhanced | no | (built-in / not provider-listed) | — |
| [`inspect_native_api`](#inspectnativeapi) | enhanced | no | (built-in / not provider-listed) | `rea inspect-native-api` |
| [`inspect_native_dispatch_metadata`](#inspectnativedispatchmetadata) | enhanced | no | (built-in / not provider-listed) | `rea inspect-native-dispatch-metadata` |
| [`trace_call_path`](#tracecallpath) | enhanced | no | (built-in / not provider-listed) | — |
| [`trace_feature`](#tracefeature) | enhanced | no | (built-in / not provider-listed) | — |
| [`trace_native_ui_action`](#tracenativeuiaction) | enhanced | no | (built-in / not provider-listed) | `rea trace-native-ui-action` |
| [`trace_native_values`](#tracenativevalues) | enhanced | no | (built-in / not provider-listed) | `rea trace-native-values` |

## analyze_function

<a id="analyzefunction"></a>

**Title:** Analyze Function  
**Kind:** `enhanced` · **Requires session:** false · **analysisOperation:** analyze_function  
**Providers:** ghidra, hopper, ida  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Build a dossier for one native function identified by symbol or provider-returned address. Returns identity with complete inclusive analyzed body ranges or explicit unknown, provider-specific pseudocode and assembly, comments, calls, references, referenced strings/names, local CFG blocks, and available native API boundary observations. Ghidra terminal-call assumptions that may cut the analyzed body are reported in limitations with available callee identities.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for analyze_function</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "A procedure name or address",
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "procedure": "main"
    }
  ],
  "properties": {
    "procedure": {
      "$ref": "#/$defs/__schema0",
      "description": "A procedure name or address"
    }
  },
  "required": [
    "procedure"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/analyze_function.json`](../tool-specs/analyze_function.json) (`outputSchema`).

---

## analyze_swift_types

<a id="analyzeswifttypes"></a>

**Title:** Analyze Swift Types  
**Kind:** `enhanced` · **Requires session:** false · **analysisOperation:** analyze_swift_types  
**Providers:** n/a  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Categorize analyzed Swift procedure names using their manglings or same-address Swift symbol aliases. Decodes legacy and literal modern nominal contexts into classes, structs, enums, protocols, and extensions. Preserves provider names and supporting mangled_names; unresolved categories appear in other and in unclassified, which remains inline even under category filters. Returns deduplicated procedure-name counts, not unique source types, plus identification limitations. Optionally select one category and/or apply a case-sensitive literal filter to provider names or supporting manglings; for example, use {category: "structs", pattern: "Pair"}.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for analyze_swift_types</summary>

```json
{
  "$defs": {
    "__schema0": {
      "$ref": "#/$defs/__schema1",
      "description": "Limit categorized results to one Swift category; unresolved category observations remain in unclassified."
    },
    "__schema1": {
      "enum": [
        "classes",
        "structs",
        "enums",
        "protocols",
        "extensions",
        "other"
      ],
      "type": "string"
    },
    "__schema2": {
      "$ref": "#/$defs/__schema3",
      "description": "Case-sensitive literal filter applied to provider procedure names and their supporting Swift manglings."
    },
    "__schema3": {
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "category": "classes",
      "pattern": "Account"
    }
  ],
  "properties": {
    "category": {
      "$ref": "#/$defs/__schema0",
      "description": "Limit categorized results to one Swift category; unresolved category observations remain in unclassified."
    },
    "pattern": {
      "$ref": "#/$defs/__schema2",
      "description": "Case-sensitive literal filter applied to provider procedure names and their supporting Swift manglings."
    }
  },
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/analyze_swift_types.json`](../tool-specs/analyze_swift_types.json) (`outputSchema`).

---

## batch_decompile

<a id="batchdecompile"></a>

**Title:** Batch Decompile  
**Kind:** `enhanced` · **Requires session:** false · **analysisOperation:** batch_decompile  
**Providers:** n/a  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Decompile each explicit procedure symbol or address concurrently. Preserves each input selector in address and reports the observed canonical entry and entry label in procedure; identity or label failures remain explicit without discarding usable pseudocode. Returns ordered per-item success or error results and aggregate counts.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for batch_decompile</summary>

```json
{
  "$defs": {
    "__schema0": {
      "default": [],
      "items": {
        "description": "A provider-normalized procedure address",
        "type": "string"
      },
      "type": "array"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "addresses": []
    }
  ],
  "properties": {
    "addresses": {
      "$ref": "#/$defs/__schema0",
      "description": "Ordered provider-normalized procedure addresses to analyze."
    }
  },
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/batch_decompile.json`](../tool-specs/batch_decompile.json) (`outputSchema`).

---

## binary_overview

<a id="binaryoverview"></a>

**Title:** Binary Overview  
**Kind:** `enhanced` · **Requires session:** false · **analysisOperation:** binary_overview  
**Providers:** n/a  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Return the bound document and exhaustive procedure/string counts, plus every segment and segment_count when the provider supports segment enumeration. If segment fields are omitted, segment coverage is unavailable rather than empty. When every observed segment agrees on an analysis image base, return it as image_base so callers can relate provider addresses to their loader coordinates. Use search_procedures, list_procedures, or analyze_function directly when you already know which procedure to inspect.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for binary_overview</summary>

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {}
  ],
  "properties": {},
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/binary_overview.json`](../tool-specs/binary_overview.json) (`outputSchema`).

---

## find_xrefs_to_name

<a id="findxrefstoname"></a>

**Title:** Find Xrefs To Name  
**Kind:** `enhanced` · **Requires session:** false · **analysisOperation:** find_xrefs_to_name  
**Providers:** n/a  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Resolve an exact name against the bound provider's name inventory and return a resolved or unresolved result. Unresolved names use the stable name_not_found reason; this xref workflow returns address-only projections.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for find_xrefs_to_name</summary>

```json
{
  "$defs": {
    "__schema0": {
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "name": "malloc"
    }
  ],
  "properties": {
    "name": {
      "$ref": "#/$defs/__schema0",
      "description": "Exact name used by this operation."
    }
  },
  "required": [
    "name"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/find_xrefs_to_name.json`](../tool-specs/find_xrefs_to_name.json) (`outputSchema`).

---

## get_call_graph

<a id="getcallgraph"></a>

**Title:** Get Call Graph  
**Kind:** `enhanced` · **Requires session:** false · **analysisOperation:** get_call_graph  
**Providers:** n/a  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Resolve one symbol or address to its canonical procedure entry, then traverse the bound provider's caller or callee relationships until the reachable graph is exhausted. Every node uses a canonical address and has an ok/error status; failures use safe typed projections. Unresolved indirect calls may be missing and results are not a whole-program CFG.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for get_call_graph</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "A procedure symbol or address to resolve to its canonical entry",
      "type": "string"
    },
    "__schema1": {
      "default": "forward",
      "enum": [
        "forward",
        "backward"
      ],
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "address": "0x1000",
      "direction": "forward"
    }
  ],
  "properties": {
    "address": {
      "$ref": "#/$defs/__schema0",
      "description": "A procedure symbol or address to resolve to its canonical entry"
    },
    "direction": {
      "$ref": "#/$defs/__schema1",
      "description": "Direction in which to traverse or compare relationships."
    }
  },
  "required": [
    "address"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/get_call_graph.json`](../tool-specs/get_call_graph.json) (`outputSchema`).

---

## get_objc_classes

<a id="getobjcclasses"></a>

**Title:** Get Objc Classes  
**Kind:** `enhanced` · **Requires session:** false · **analysisOperation:** get_objc_classes  
**Providers:** n/a  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Discover and deduplicate Objective-C class labels, optionally filtering by literal substring.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for get_objc_classes</summary>

```json
{
  "$defs": {
    "__schema0": {
      "default": "",
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "pattern": ""
    }
  ],
  "properties": {
    "pattern": {
      "$ref": "#/$defs/__schema0",
      "description": "Literal text or regular expression used to filter matching results."
    }
  },
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/get_objc_classes.json`](../tool-specs/get_objc_classes.json) (`outputSchema`).

---

## get_objc_protocols

<a id="getobjcprotocols"></a>

**Title:** Get Objc Protocols  
**Kind:** `enhanced` · **Requires session:** false · **analysisOperation:** get_objc_protocols  
**Providers:** n/a  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Discover and deduplicate Objective-C and Swift protocol labels.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for get_objc_protocols</summary>

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {}
  ],
  "properties": {},
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/get_objc_protocols.json`](../tool-specs/get_objc_protocols.json) (`outputSchema`).

---

## inspect_native_api

<a id="inspectnativeapi"></a>

**Title:** Inspect Native Api  
**Kind:** `enhanced` · **Requires session:** false · **analysisOperation:** inspect_native_api  
**Providers:** n/a  
**Effects set (true flags):** NOT idempotent, mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":false,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Analyze a native API boundary in one function identified by symbol or provider-returned address. Returns confidence, evidence, jump-table dispatch/data/case mappings, separately evidenced default targets, unsupported branches, and residual unknowns. Null case values mean unresolved cases, never a known default.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for inspect_native_api</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "A procedure name or address",
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "procedure": "main"
    }
  ],
  "properties": {
    "procedure": {
      "$ref": "#/$defs/__schema0",
      "description": "A procedure name or address"
    }
  },
  "required": [
    "procedure"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/inspect_native_api.json`](../tool-specs/inspect_native_api.json) (`outputSchema`).

---

## inspect_native_dispatch_metadata

<a id="inspectnativedispatchmetadata"></a>

**Title:** Inspect Native Dispatch Metadata  
**Kind:** `enhanced` · **Requires session:** false · **analysisOperation:** inspect_native_dispatch_metadata  
**Providers:** n/a  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Inspect the bound provider's name inventory for Objective-C class/method symbols and Swift mangled symbols, returning at most max_records decoded names. Includes target SHA-256 when available, provider identity/version, analysis-profile digest, facet coverage, and per-record Evidence. This is symbol-level evidence, not runtime metadata: ivar layouts, protocol conformances, witness/class tables, and relative pointers are explicitly marked unsupported unless a provider supplies those decoders. The provider controls how its name inventory is acquired.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for inspect_native_dispatch_metadata</summary>

```json
{
  "$defs": {
    "__schema0": {
      "default": 5000,
      "maximum": 20000,
      "minimum": 1,
      "type": "integer"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "max_records": 5000
    }
  ],
  "properties": {
    "max_records": {
      "$ref": "#/$defs/__schema0",
      "description": "Maximum permitted records for this operation."
    }
  },
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/inspect_native_dispatch_metadata.json`](../tool-specs/inspect_native_dispatch_metadata.json) (`outputSchema`).

---

## trace_call_path

<a id="tracecallpath"></a>

**Title:** Trace Call Path  
**Kind:** `enhanced` · **Requires session:** false · **analysisOperation:** trace_call_path  
**Providers:** n/a  
**Effects set (true flags):** NOT idempotent, mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":false,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Resolve start and optional goal symbols or addresses to canonical procedure entries, then trace direct callers or callees until the graph is exhausted or the goal is reached. Results use canonical addresses; Evidence preserves supplied selectors. Returns visited nodes, direct-call edges, a shortest traversal path, provider failures, and residual unknowns. A requested goal is unknown when unresolved expansions prevent proving it absent; unresolved indirect calls remain unknown.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for trace_call_path</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "A starting procedure symbol or address",
      "type": "string"
    },
    "__schema1": {
      "description": "An optional destination procedure symbol or address",
      "type": "string"
    },
    "__schema2": {
      "default": "forward",
      "enum": [
        "forward",
        "backward"
      ],
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "direction": "forward",
      "goal": "0x1100",
      "start": "0x1000"
    }
  ],
  "properties": {
    "direction": {
      "$ref": "#/$defs/__schema2",
      "description": "Direction in which to traverse or compare relationships."
    },
    "goal": {
      "$ref": "#/$defs/__schema1",
      "description": "An optional destination procedure symbol or address"
    },
    "start": {
      "$ref": "#/$defs/__schema0",
      "description": "A starting procedure symbol or address"
    }
  },
  "required": [
    "start"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/trace_call_path.json`](../tool-specs/trace_call_path.json) (`outputSchema`).

---

## trace_feature

<a id="tracefeature"></a>

**Title:** Trace Feature  
**Kind:** `enhanced` · **Requires session:** false · **analysisOperation:** trace_feature  
**Providers:** n/a  
**Effects set (true flags):** NOT idempotent, mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":false,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Trace the complete literal query, preserving spaces, through every matching string and procedure, their xrefs, and truthful containing-procedure resolution. Returns observations, operation count, and residual unknowns without inferring reference kinds.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for trace_feature</summary>

```json
{
  "$defs": {
    "__schema0": {
      "minLength": 1,
      "type": "string"
    },
    "__schema1": {
      "default": false,
      "type": "boolean"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "case_sensitive": false,
      "query": "license"
    }
  ],
  "properties": {
    "case_sensitive": {
      "$ref": "#/$defs/__schema1",
      "description": "Whether text matching distinguishes uppercase and lowercase."
    },
    "query": {
      "$ref": "#/$defs/__schema0",
      "description": "Non-empty feature or text query to investigate."
    }
  },
  "required": [
    "query"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/trace_feature.json`](../tool-specs/trace_feature.json) (`outputSchema`).

---

## trace_native_ui_action

<a id="tracenativeuiaction"></a>

**Title:** Trace Native Ui Action  
**Kind:** `enhanced` · **Requires session:** false · **analysisOperation:** trace_native_ui_action  
**Providers:** n/a  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Trace one unique compiled UI action, object ID, native symbol or exact function address through authored connections, encoded or symbolized Objective-C handlers, and bounded static call references. Typed direct and resolved indirect calls, ambiguous candidates, inferred untyped provider callees, and targetless sites remain distinct. Runtime reachability is unknown; use trace_native_values for recovered value dependencies.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for trace_native_ui_action</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "A unique compiled UI action selector, interface object ID, native symbol or exact function address",
      "minLength": 1,
      "type": "string"
    },
    "__schema1": {
      "default": 8,
      "maximum": 32,
      "minimum": 0,
      "type": "integer"
    },
    "__schema2": {
      "default": 250,
      "maximum": 2000,
      "minimum": 1,
      "type": "integer"
    },
    "__schema3": {
      "default": 500,
      "maximum": 5000,
      "minimum": 1,
      "type": "integer"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "action": "buildTapped:",
      "max_depth": 8,
      "max_edges": 500,
      "max_nodes": 250
    }
  ],
  "properties": {
    "action": {
      "$ref": "#/$defs/__schema0",
      "description": "A unique compiled UI action selector, interface object ID, native symbol or exact function address"
    },
    "max_depth": {
      "$ref": "#/$defs/__schema1",
      "description": "Maximum permitted depth for this operation."
    },
    "max_edges": {
      "$ref": "#/$defs/__schema3",
      "description": "Maximum permitted edges for this operation."
    },
    "max_nodes": {
      "$ref": "#/$defs/__schema2",
      "description": "Maximum permitted nodes for this operation."
    }
  },
  "required": [
    "action"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/trace_native_ui_action.json`](../tool-specs/trace_native_ui_action.json) (`outputSchema`).

---

## trace_native_values

<a id="tracenativevalues"></a>

**Title:** Trace Native Values  
**Kind:** `enhanced` · **Requires session:** false · **analysisOperation:** trace_native_values  
**Providers:** n/a  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Trace a bounded static dependency graph from one explicit native procedure. Includes high-p-code def-use, constants, operators, memory and branch operations, resolved call edges, and derived argument/parameter and return/output bindings. Missing bindings, alias semantics, persistent state and RNG roles remain unknown. Budgets bound depth, decompilations, graph size and payloads; nodes are paginated.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for trace_native_values</summary>

```json
{
  "$defs": {
    "__schema0": {
      "minLength": 1,
      "type": "string"
    },
    "__schema1": {
      "default": 3,
      "maximum": 16,
      "minimum": 0,
      "type": "integer"
    },
    "__schema2": {
      "default": 16,
      "maximum": 64,
      "minimum": 1,
      "type": "integer"
    },
    "__schema3": {
      "default": 256,
      "maximum": 4096,
      "minimum": 1,
      "type": "integer"
    },
    "__schema4": {
      "default": 5000,
      "maximum": 20000,
      "minimum": 1,
      "type": "integer"
    },
    "__schema5": {
      "default": 10000,
      "maximum": 40000,
      "minimum": 1,
      "type": "integer"
    },
    "__schema6": {
      "default": 0,
      "maximum": 9007199254740991,
      "minimum": 0,
      "type": "integer"
    },
    "__schema7": {
      "default": 1000,
      "maximum": 5000,
      "minimum": 1,
      "type": "integer"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "limit": 1000,
      "max_call_sites": 256,
      "max_depth": 3,
      "max_edges": 10000,
      "max_functions": 16,
      "max_nodes": 5000,
      "offset": 0,
      "procedure": "0x1000"
    }
  ],
  "properties": {
    "limit": {
      "$ref": "#/$defs/__schema7"
    },
    "max_call_sites": {
      "$ref": "#/$defs/__schema3",
      "description": "Maximum permitted call sites for this operation."
    },
    "max_depth": {
      "$ref": "#/$defs/__schema1",
      "description": "Maximum permitted depth for this operation."
    },
    "max_edges": {
      "$ref": "#/$defs/__schema5",
      "description": "Maximum permitted edges for this operation."
    },
    "max_functions": {
      "$ref": "#/$defs/__schema2",
      "description": "Maximum permitted functions for this operation."
    },
    "max_nodes": {
      "$ref": "#/$defs/__schema4",
      "description": "Maximum permitted nodes for this operation."
    },
    "offset": {
      "$ref": "#/$defs/__schema6"
    },
    "procedure": {
      "$ref": "#/$defs/__schema0"
    }
  },
  "required": [
    "procedure"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/trace_native_values.json`](../tool-specs/trace_native_values.json) (`outputSchema`).

---


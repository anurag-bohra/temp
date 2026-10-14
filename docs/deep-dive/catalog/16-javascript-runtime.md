# Tool family: JavaScript runtime observation

Generated mechanically from `.cache/mcp-tool-catalog.json` (produced by `scripts/generate-mcp-tool-catalog.mjs`, which registers every tool through the MCP SDK and exports the advertised JSON Schema 2020-12 input/output schemas) and `docs/public/product-catalog.json` (family `javascript-runtime`, surface `runtime-provider`, 2 tools). Input schemas below are **verbatim**. Output schemas are verbatim in `tool-specs/<tool>.json` (field `outputSchema`) because several exceed 100 KB; the complete per-tool spec (description, effects, annotations, inputSchema, outputSchema) is in that file.

| Tool | Kind | Session? | Providers advertising it | CLI command |
|---|---|---|---|---|
| [`list_javascript_runtime_targets`](#listjavascriptruntimetargets) | runtime-provider | no | rea-v8-inspector | `rea list-javascript-runtime-targets` |
| [`observe_javascript_runtime`](#observejavascriptruntime) | runtime-provider | no | rea-v8-inspector | `rea observe-javascript-runtime` |

## list_javascript_runtime_targets

<a id="listjavascriptruntimetargets"></a>

**Title:** List Javascript Runtime Targets  
**Kind:** `runtime-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** rea-v8-inspector  
**Effects set (true flags):** accessesNetwork, mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> List every eligible Node/Electron V8 Inspector target from an explicit literal-loopback endpoint. Node discovery file locations that cannot be verified are preserved as unresolved reported URLs; they do not prove filesystem identity. Listing does not attach to targets.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for list_javascript_runtime_targets</summary>

```json
{
  "$defs": {
    "__schema0": {
      "minLength": 1,
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "inspector_endpoint": "http://127.0.0.1:9229"
    }
  ],
  "properties": {
    "inspector_endpoint": {
      "$ref": "#/$defs/__schema0"
    }
  },
  "required": [
    "inspector_endpoint"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/list_javascript_runtime_targets.json`](../tool-specs/list_javascript_runtime_targets.json) (`outputSchema`).

---

## observe_javascript_runtime

<a id="observejavascriptruntime"></a>

**Title:** Observe Javascript Runtime  
**Kind:** `runtime-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** rea-v8-inspector  
**Effects set (true flags):** accessesNetwork, mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Attach passively to one Node/Electron V8 Inspector target by supplying its loopback Inspector endpoint and target ID. The provider rechecks target presence and attachability; a Node discovery file location may remain unresolved. Loaded script locations are validated independently from Debugger.scriptParsed. Captures script and Runtime execution-context metadata. REA never evaluates, pauses, resumes, reads source, or instruments the target; require/import edges, EventEmitter activity, and Electron IPC remain explicit unknowns. Reconcile the result with static Application Graph Evidence using reconcile_javascript_runtime. The selected endpoint exposes every target it serves to this tool.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for observe_javascript_runtime</summary>

```json
{
  "$defs": {
    "__schema0": {
      "minLength": 1,
      "type": "string"
    },
    "__schema1": {
      "minLength": 1,
      "type": "string"
    },
    "__schema2": {
      "enum": [
        "node",
        "electron-main",
        "electron-preload",
        "electron-renderer"
      ],
      "type": "string"
    },
    "__schema3": {
      "default": 100,
      "maximum": 9007199254740991,
      "minimum": 0,
      "type": "integer"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "inspector_endpoint": "http://127.0.0.1:9229",
      "target_id": "TARGET_ID_FROM_LIST_JAVASCRIPT_RUNTIME_TARGETS"
    }
  ],
  "properties": {
    "inspector_endpoint": {
      "$ref": "#/$defs/__schema0"
    },
    "observation_ms": {
      "$ref": "#/$defs/__schema3"
    },
    "runtime_kind": {
      "$ref": "#/$defs/__schema2"
    },
    "target_id": {
      "$ref": "#/$defs/__schema1",
      "description": "Exact CDP target identifier selected from the endpoint's target listing."
    }
  },
  "required": [
    "inspector_endpoint",
    "target_id"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/observe_javascript_runtime.json`](../tool-specs/observe_javascript_runtime.json) (`outputSchema`).

---


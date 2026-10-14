# Tool family: JEB

Generated mechanically from `.cache/mcp-tool-catalog.json` (produced by `scripts/generate-mcp-tool-catalog.mjs`, which registers every tool through the MCP SDK and exports the advertised JSON Schema 2020-12 input/output schemas) and `docs/public/product-catalog.json` (family `jeb`, surface `jeb-provider`, 4 tools). Input schemas below are **verbatim**. Output schemas are verbatim in `tool-specs/<tool>.json` (field `outputSchema`) because several exceed 100 KB; the complete per-tool spec (description, effects, annotations, inputSchema, outputSchema) is in that file.

| Tool | Kind | Session? | Providers advertising it | CLI command |
|---|---|---|---|---|
| [`decompile_jeb_item`](#decompilejebitem) | jeb-provider | no | jeb | `rea decompile-jeb-item` |
| [`inspect_jeb_client`](#inspectjebclient) | jeb-provider | no | jeb | `rea inspect-jeb-client` |
| [`list_jeb_units`](#listjebunits) | jeb-provider | no | jeb | `rea list-jeb-units` |
| [`open_jeb_project`](#openjebproject) | jeb-provider | no | jeb | `rea open-jeb-project` |

## decompile_jeb_item

<a id="decompilejebitem"></a>

**Title:** Decompile Jeb Item  
**Kind:** `jeb-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** jeb  
**Effects set (true flags):** accessesNetwork, mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Decompile one type or method to engine pseudo-code using its decompiler (Dalvik, Java, or native). item_address comes from the engine's code item listing; unit_path defaults to the engine's first code unit and stays unknown when omitted. Read-only with respect to the target file.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for decompile_jeb_item</summary>

```json
{
  "$defs": {
    "__schema0": {
      "$ref": "#/$defs/__schema1",
      "description": "Target code unit; the engine's first code unit in the project when omitted"
    },
    "__schema1": {
      "minLength": 1,
      "type": "string"
    },
    "__schema2": {
      "description": "Type or method address within the unit, as listed by the engine",
      "minLength": 1,
      "type": "string"
    },
    "__schema3": {
      "description": "Kind of item to decompile",
      "enum": [
        "type",
        "method"
      ],
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "item_address": "Lcom/example/Main;->onCreate()V",
      "item_kind": "method"
    }
  ],
  "properties": {
    "item_address": {
      "$ref": "#/$defs/__schema2",
      "description": "Type or method address within the unit, as listed by the engine"
    },
    "item_kind": {
      "$ref": "#/$defs/__schema3",
      "description": "Kind of item to decompile"
    },
    "unit_path": {
      "$ref": "#/$defs/__schema0",
      "description": "Target code unit; the engine's first code unit in the project when omitted"
    }
  },
  "required": [
    "item_address",
    "item_kind"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/decompile_jeb_item.json`](../tool-specs/decompile_jeb_item.json) (`outputSchema`).

---

## inspect_jeb_client

<a id="inspectjebclient"></a>

**Title:** Inspect Jeb Client  
**Kind:** `jeb-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** jeb  
**Effects set (true flags):** accessesNetwork, mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Inspect the running JEB client serving MCP: engine version, GUI or headless mode, and startup time. Does not open a target. Requires a caller-started JEB client reachable at REA_JEB_MCP_URL (default http://127.0.0.1:8425/mcp); REA never installs or launches JEB.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for inspect_jeb_client</summary>

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

**Output schema:** see [`tool-specs/inspect_jeb_client.json`](../tool-specs/inspect_jeb_client.json) (`outputSchema`).

---

## list_jeb_units

<a id="listjebunits"></a>

**Title:** List Jeb Units  
**Kind:** `jeb-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** jeb  
**Effects set (true flags):** accessesNetwork, mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> List project units by stable unit path and type, with optional wildcard filter, parent restriction, and pagination. The engine caps pages at 100 units; a full page reports partial coverage because more units may exist. Read-only.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for list_jeb_units</summary>

```json
{
  "$defs": {
    "__schema0": {
      "$ref": "#/$defs/__schema1",
      "description": "Wildcard filter matched against unit paths; '*' allowed"
    },
    "__schema1": {
      "type": "string"
    },
    "__schema2": {
      "$ref": "#/$defs/__schema3",
      "description": "Restrict results to descendants of this unit path"
    },
    "__schema3": {
      "minLength": 1,
      "type": "string"
    },
    "__schema4": {
      "$ref": "#/$defs/__schema5",
      "default": 0,
      "description": "Zero-based index of the first result to return"
    },
    "__schema5": {
      "maximum": 9007199254740991,
      "minimum": 0,
      "type": "integer"
    },
    "__schema6": {
      "$ref": "#/$defs/__schema7",
      "default": 100,
      "description": "Maximum results to return; the engine protocol caps pages at 100"
    },
    "__schema7": {
      "maximum": 100,
      "minimum": 1,
      "type": "integer"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {},
    {
      "filter": "*.dex"
    }
  ],
  "properties": {
    "count": {
      "$ref": "#/$defs/__schema6",
      "description": "Maximum results to return; the engine protocol caps pages at 100"
    },
    "filter": {
      "$ref": "#/$defs/__schema0",
      "description": "Wildcard filter matched against unit paths; '*' allowed"
    },
    "index": {
      "$ref": "#/$defs/__schema4",
      "description": "Zero-based index of the first result to return"
    },
    "parent_unit_path": {
      "$ref": "#/$defs/__schema2",
      "description": "Restrict results to descendants of this unit path"
    }
  },
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/list_jeb_units.json`](../tool-specs/list_jeb_units.json) (`outputSchema`).

---

## open_jeb_project

<a id="openjebproject"></a>

**Title:** Open Jeb Project  
**Kind:** `jeb-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** jeb  
**Effects set (true flags):** accessesNetwork, NOT idempotent, mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":false,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Open or create a JEB project from an artifact file or existing .jdb2 database on the engine host. Returns the project's input-file digests and top-level units. The engine analyzes the target itself; REA does not read the file or execute it. Fails when a project is already open.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for open_jeb_project</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Artifact file or existing .jdb2 project database, resolved by the running JEB client",
      "minLength": 1,
      "pattern": "^[^\\x00]*$",
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "path": "/tmp/Example.apk"
    }
  ],
  "properties": {
    "path": {
      "$ref": "#/$defs/__schema0",
      "description": "Artifact file or existing .jdb2 project database, resolved by the running JEB client"
    }
  },
  "required": [
    "path"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/open_jeb_project.json`](../tool-specs/open_jeb_project.json) (`outputSchema`).

---

